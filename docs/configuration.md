# Configuration

The full set of keys, with inline comments, lives in
[`config.example.yaml`](../config.example.yaml) — copy it to `config.yaml`
and edit. This doc explains the parts that aren't self-evident from the
comments: precedence, validation, and how sections relate to each other.

Loading happens in `internal/config/config.go`: `Load()` reads the YAML
(rejecting unknown keys — `KnownFields(true)`, to catch typos), applies
environment variable overrides, then calls `Validate()`. A misconfigured
server fails to start with a specific error rather than running degraded.

## Secrets: environment variables always win

Every secret field can be set in `config.yaml`, but **shouldn't be** if the
file is version-controlled or shared. Setting the corresponding environment
variable always overrides whatever is in the file:

| Env var | Overrides |
|---|---|
| `WICKET_WG_PRIVATE_KEY` | `wireguard.private_key` |
| `WICKET_OIDC_CLIENT_ID` | `oidc.client_id` |
| `WICKET_OIDC_CLIENT_SECRET` | `oidc.client_secret` |
| `WICKET_PUBLIC_SESSION_SECRET` | `public.session_secret` |
| `WICKET_ADMIN_HMAC_SECRET` | `admin.hmac_secret` |
| `WICKET_ADMIN_SESSION_SECRET` | `admin.session_secret` |
| `WICKET_SMTP_PASSWORD` | `smtp.password` |
| `WICKET_AGENT_TOKEN` | `agent.token` (only relevant when running `wicket-agent`) |

`public.session_secret`, `admin.hmac_secret`, and `admin.session_secret` must
be at least 32 bytes — `Validate()` rejects shorter values. Generate them with
`openssl rand -hex 32`.

## Admin portal is intentionally locked down

`admin.bind_addr` is validated at startup to reject anything starting with
`0.0.0.0` — the admin portal must only ever be reachable from the host or
over the VPN itself, never the public internet. If you need remote admin
access, put it behind the VPN (a group with `is_public: true` covers this)
or an SSH tunnel, not a public reverse-proxy route.

`admin.external_url` and `admin.hmac_secret` exist because the admin portal
has its *own* OIDC callback (separate from the public portal's), and signs
its own session cookies independently — compromising one portal's session
secret doesn't compromise the other.

## WireGuard section

- `wireguard.interface` defaults to `wg1` (not `wg0`) specifically to avoid
  colliding with an interface a host might already have for other purposes.
- `wireguard.endpoint` is what's written into generated client `.conf` files
  as `Endpoint = `. It must include the port and have no scheme
  (`vpn.example.com:51820`, not `https://...`).
- A **group** can override the endpoint clients are told to use
  (`groups.endpoint_override` in the admin UI) — useful when a group's
  devices should connect to a specific remote agent's public endpoint
  instead of the core's.
- On startup, the core calls `wireguard.EnsureInterface` to create/fix the
  interface and address before doing anything else — config changes to
  `wireguard.address` self-heal on next restart, no manual `ip addr` needed.

## Agent section

> **Note:** `wicket-agent` does not currently read `config.yaml` — it's
> configured entirely by CLI flags. The `agent:` section here (`core_url`,
> `token`, `core_timeout`, the nested `wireguard` override) is parsed but
> unused by either binary. See [agents.md](agents.md) for how agents are
> actually configured, and `config.example.yaml` if you're auditing this
> further.

## Security section

`security.rate_limit_*` and `security.max_login_attempts` /
`login_block_duration` apply to the **public** portal's login/auth endpoints
only — they're brute-force protection in front of OIDC, not a general API
rate limiter. `allow_portal_session_extension` controls whether a still-valid
portal session can extend a VPN session without forcing a full OIDC
re-auth; turn it off if you want every extension to re-verify identity.

## Metrics section

`metrics.sample_interval` controls how often the reconciler polls `wgctrl`
for per-peer stats; `metrics.retention_days` controls how long
`metric_snapshots` rows are kept before the reconciler prunes them. There's
no separate metrics database — it's the same Postgres instance.
