# Wicket

A self-hosted WireGuard VPN management portal with OIDC SSO, session management, and a clean web UI.

## Features

- **OIDC SSO** — login via Authentik or any OIDC provider
- **Session expiry** — WireGuard peers are removed when sessions expire; re-auth to reconnect
- **No proprietary client** — standard WireGuard `.conf` files, import into any WireGuard client
- **Public portal** — users register devices, manage sessions, download configs, regenerate keys
- **Admin portal** — approve/reject devices, manage groups, subnets, users, agents; live metrics
- **Always-connected devices** — admin-flagged devices with permanent sessions (for servers, infra)
- **Live UI** — WebSocket-driven, real-time updates without page refresh
- **CLI** — admin commands over a Unix socket (`wicket session extend`, `wicket agent rotate-key`, etc.)
- **Remote agents** — WireGuard agents on remote servers for HA or network-segmented setups; keypairs stored server-side
- **Metrics** — per-device traffic, handshake age, and real source IP tracking

## Quick Start

### 1. Prerequisites

templ generates Go code from `.templ` files. It's a `go.mod` build tool
dependency, so `make build` fetches and runs it automatically — nothing to
install separately.

### 2. Clone and configure

```bash
git clone https://github.com/elsing/wicket
cd wicket
cp config.example.yaml config.yaml
cp .env.example .env
# Edit config.yaml with your settings
# Fill .env with secrets (see below)
```

### 3. Generate secrets

```bash
# WireGuard server private key
wg genkey | tee /tmp/wg-private.key        # → WICKET_WG_PRIVATE_KEY

# Session and HMAC secrets
openssl rand -hex 32                        # → WICKET_PUBLIC_SESSION_SECRET
openssl rand -hex 32                        # → WICKET_ADMIN_HMAC_SECRET
openssl rand -hex 32                        # → WICKET_ADMIN_SESSION_SECRET
```

### 4. Run

```bash
# Docker: pulls the published image, no Go/templ toolchain needed
docker compose up -d

# Or build and run from source
make build
./wicket serve --config config.yaml
```

### 5. First admin

On first start, the public portal is at `http://your-server:8080`. Log in via OIDC, then promote your account to admin from the host running the server:

```bash
wicket user list
wicket make-admin --email you@example.com
```

The admin portal is at `http://localhost:9090` (host-only by default).

For emergency access without OIDC:

```bash
wicket create-local-admin --username admin --password <password>
```

## CLI Reference

```bash
wicket health
wicket make-admin --email <email>
wicket remove-admin --email <email>

wicket device list [--pending]
wicket device approve --id <device-id>
wicket device reject --id <device-id>

wicket session list
wicket session extend --id <session-id> --duration 24h
wicket session revoke --id <session-id>

wicket user list

wicket agent list
wicket agent rotate-key --id <agent-id>
wicket agent rotate-key --id <agent-id> --private-key <key>  # import existing key

wicket create-local-admin --username <name> --password <password>
wicket reconcile
```

Full reference: [docs/cli.md](docs/cli.md).

## Architecture

```
Public Portal (:8080)  ─┐
Admin Portal  (:9090)  ─┤─► Core Service ─► PostgreSQL + wgctrl
CLI (Unix socket)      ─┘
                             ↕ WebSocket
                          Remote Agents (wicket-agent)
```

Details: [docs/architecture.md](docs/architecture.md). Database migrations
run automatically on startup.

## Configuration

See `config.example.yaml` for all options with inline documentation, and
[docs/configuration.md](docs/configuration.md) for the parts that aren't
obvious from the comments (env var precedence, validation rules, what each
section actually affects).

All secrets should be set via environment variables — never in `config.yaml`.

## Remote agents

For multi-site or HA setups, see [docs/agents.md](docs/agents.md).

## License

MIT

