# Architecture

## Processes

Wicket ships two binaries:

- **`wicket`** (`cmd/wicket`) — the core service. Runs the public portal, the
  admin portal, the CLI's Unix socket listener, the WireGuard reconciler, and
  the agent WebSocket hub, all in one process (`internal/core`).
- **`wicket-agent`** (`cmd/wicket-agent`) — a standalone binary for remote
  sites. It manages its own local WireGuard interface and takes instructions
  from the core over a WebSocket connection. Only needed for multi-site /
  HA setups; a single-site deployment never runs it.

```
                 ┌────────────────────────────────────────────┐
                 │                  core (wicket)              │
  Browser ─────► │  Public Portal (:8080) ─┐                   │
                 │  Admin Portal  (:9090) ─┼─► Service ─► DB    │
  wicket CLI ───►│  Unix socket           ─┘      │   (postgres)│
                 │                                 ▼            │
                 │                            Reconciler        │
                 │                            ├─► local wgctrl  │
                 │                            └─► Agent Hub (WS) │
                 └────────────────────────────────────┼──────────┘
                                                       │ wss://
                                              ┌────────▼────────┐
                                              │  wicket-agent   │
                                              │  (remote site)  │
                                              │  local wgctrl   │
                                              └─────────────────┘
```

## Core components (`internal/core`)

- **`Service`** (`service.go`, `service_extra.go`) — all business logic: device
  creation, session lifecycle, approvals, audit logging. Nothing else touches
  the database or WireGuard directly except through `Service`.
- **`Reconciler`** (`reconciler.go`) — runs on a timer (and on-demand via
  `wicket reconcile` / the CLI socket). Compares DB state against the live
  WireGuard interface and:
  - marks expired sessions, removes their peers
  - re-adds peers that are missing (e.g. after a restart)
  - restores sessions for `always_connected` devices that have lapsed
    (`restoreAlwaysConnectedSessions` — recovery after reboots, revocations,
    or expiry is automatic within one reconcile interval)
  - samples per-peer metrics (including source IP) into `metric_snapshots`
  - prunes metrics older than `metrics.retention_days`
- **`socketServer`** (`socket_commands.go`) — the Unix socket the `wicket` CLI
  talks to (`server.socket_path`, default `/var/run/wicket/core.sock`).
  Commands are plain JSON request/response (see `SocketRequest`/`SocketResponse`
  in `server.go`); the CLI is a thin client over this protocol.
- **`events.go`** — an in-process pub/sub `Service.Events()` channel that
  drives the WebSocket-pushed live updates in `internal/ws`.

## Data model (`internal/db/models.go`)

- **Group** — a session policy (`session_duration`, `max_extensions`) plus a
  default set of **Routes**. Devices and users inherit their group's policy.
  A group can be `is_public` (selectable by any authenticated user) or
  restricted via `UserGroup` membership.
- **Route** — a named CIDR pushed to clients as an `AllowedIPs` entry
  (`is_excluded` flags an "exclude this from the default route" entry rather
  than a route to add). A **DeviceRoute** override on a device *replaces*,
  rather than extends, its group's routes.
- **Device** — a WireGuard peer belonging to a user. The keypair is generated
  server-side; the private key is returned once in the downloadable config
  and never persisted (`config_downloaded` is a one-time-download guard).
  `always_connected` (admin-only toggle) gives a device a permanent session
  regardless of its group's `session_duration` — for servers/infra devices
  that shouldn't need re-auth — and the reconciler actively restores that
  session if it ever lapses.
- **Session** — the thing that actually puts a device's peer onto WireGuard.
  A device only has a live peer while it has a non-expired, non-revoked
  session; the reconciler enforces this. `auto_renew` on the device causes a
  new session to be created automatically on portal login; `always_connected`
  goes further and keeps it active even with no logins at all.
- **Agent** — a registered remote `wicket-agent`. Has its own `vpn_pool` CIDR,
  WireGuard keypair, and bearer token (`token` is bcrypt-hashed). Unlike a
  device's keypair, the agent's `wg_private_key` is persisted server-side
  (generated at registration, in `Service.GenerateAgentKeypair`) so the
  agent's public key — and therefore every device config that points at it
  as an endpoint — stays stable even if the agent process is reinstalled.
  `wicket agent rotate-key` regenerates (or imports) it; the agent picks up
  the new key automatically on its next `sync`. A group can be pinned to
  specific agents (`group_agents`) so its devices' peers are pushed to those
  agents instead of the local interface.
- **AuditLog** — append-only event log (`session.created`, `peer.removed`,
  `user.admin.grant`, etc.), shown in the admin UI.

## Request flow: device gets online

1. User logs in to the **public portal** via OIDC (`internal/oidc`,
   `internal/portal/session.go`). A `User` row is created/updated.
2. User registers a device for a group → `Service.CreateDevice` generates a
   WireGuard keypair, allocates an IP from the group's pool, and (if the
   group requires it) leaves the device pending admin approval.
3. An admin approves it in the **admin portal** (`internal/admin`), which
   calls `Service.ApproveDevice`.
4. The user (or `auto_renew`) activates a session →
   `Service.ActivateSession` writes a `Session` row and calls
   `notifyAgentPeerUpdate`, which either:
   - calls `LocalPeerManager.AddPeer` directly (device's group has no
     pinned agent), or
   - pushes a `peer.add` message to the right agent(s) over the WebSocket
     hub (`internal/agent/hub.go`).
5. The **Reconciler** continuously reconciles DB ↔ live WireGuard state in
   case of restarts, expiries, or missed pushes — the push path is an
   optimization, not the source of truth.

## Remote agents (`internal/agent`, `cmd/wicket-agent`)

Agents connect to the core over WebSocket (`ws/wss://<core>/ws/agent`),
authenticate with a bearer token, and exchange a small JSON protocol
(`internal/agent/protocol.go`):

| Direction | Message | Purpose |
|---|---|---|
| core → agent | `sync` | full peer list + the agent's WireGuard private key, sent right after connect |
| core → agent | `peer.add` / `peer.remove` | incremental peer changes |
| core → agent | `request.stats` | ask the agent to report stats immediately, instead of waiting for its periodic timer |
| agent → core | `ready` | agent is up (hostname, agent version) |
| agent → core | `ack` / `error` | result of a peer operation |
| agent → core | `status` | periodic peer stats (bytes, last handshake, source IP) |

The agent's WireGuard keypair is generated **server-side** when the agent is
registered (Agents → Register in the admin portal), not by the agent itself.
The core sends the private key down in the `sync` payload, and the agent
configures its local interface with whatever it's given — so `wicket agent
rotate-key` can change an agent's key centrally and it takes effect on the
agent's next reconnect, with no access to the agent host required. (The
install script still generates a local keypair via `wicket-agent
-generate-key` as a bootstrap/legacy fallback, but in normal operation
that key is immediately superseded by the server-issued one.)

`wicket-agent` is configured entirely by CLI flags (`-server`, `-token`,
`-interface`, `-listen-port`, `-private-key`), not by `config.yaml` — it
never reads `internal/config`. Per-peer expiry is enforced locally with an
in-process timer per peer (`expiryTracker` in `cmd/wicket-agent/main.go`),
seeded from each peer's `ExpiresAt`, so expiry keeps working even while
disconnected from the core. What happens to peers *without* an expiry when
the WebSocket connection itself drops is controlled by
`-keep-peers-on-disconnect` (default `true`): the agent normally leaves
existing peers alone and just retries the connection every 10s; pass
`-keep-peers-on-disconnect=false` to have it clear all local peers
immediately on disconnect instead.

Agents are installed via a self-contained script served by the core at
`/agent/install.sh` (embedded from `internal/portal/static/agent/install.sh`),
which downloads the `wicket-agent` binary from `/agent/download`, generates a
WireGuard keypair, and installs a systemd unit.

## Web layer

- **Public portal** (`internal/portal`) and **admin portal** (`internal/admin`)
  are server-rendered with [templ](https://templ.guide) (`.templ` files
  compiled to Go by `templ generate`) plus [htmx](https://htmx.org) for partial
  updates — there is no SPA/JS build step.
- **`internal/ws`** pushes live updates (pending devices, session expiry,
  connected agents) to open browser tabs over WebSocket, fed by
  `Service.Events()`.
- The admin portal must **never** be exposed publicly (`admin.bind_addr`
  is validated at startup to reject `0.0.0.0`); it's reached over the VPN
  itself or from `localhost` on the host.

## Database

PostgreSQL only (via `pgx`). Migrations are plain `.sql` files embedded into
the binary (`internal/db/migrations`, `go:embed`) and applied automatically
on startup, tracked in a `schema_migrations` table. Migrations must be
idempotent on their own (`ADD COLUMN IF NOT EXISTS`, etc.) — there is no
Go-side schema introspection, the runner just executes statements and treats
"already exists" errors as success.
