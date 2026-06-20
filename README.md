# Wicket

A self-hosted WireGuard VPN management portal with OIDC SSO, session management, and a clean web UI.

## Features

- **OIDC SSO** via Authentik (or any OIDC provider)
- **Session expiry** — peers are removed when sessions expire, re-auth to reconnect
- **No proprietary client** — uses plain WireGuard `.conf` files
- **Public portal** — users manage their own devices and sessions
- **Admin portal** — approve devices, manage groups, subnets, users, agents
- **Live UI** — WebSocket-driven dashboard with real-time updates
- **CLI** — admin commands via Unix socket (`wicket session extend`, etc.)
- **Agent support** — remote WireGuard agents for HA/load-balanced setups
- **Metrics** — per-device bytes/handshake tracking

## Quick Start

### 1. Prerequisites

templ generates Go code from `.templ` files. It's a `go.mod` build tool
dependency, so `make build` fetches and runs it automatically — nothing to
install separately.

### 2. Clone and configure

```bash
cp config.example.yaml config.yaml
cp .env.example .env
# Edit config.yaml with your settings
# Fill in .env with your secrets
```

### 3. Generate secrets

```bash
# WireGuard server key
wg genkey | tee /tmp/wg-private.key
cat /tmp/wg-private.key  # → WICKET_WG_PRIVATE_KEY

# Session secrets
openssl rand -hex 32  # → WICKET_PUBLIC_SESSION_SECRET
openssl rand -hex 32  # → WICKET_ADMIN_HMAC_SECRET
openssl rand -hex 32  # → WICKET_ADMIN_SESSION_SECRET
```

### 4. Build and run

```bash
# Docker: pulls the published image, no Go/templ toolchain needed
docker compose up

# Or build from source
make build
```

### 5. First run

On first start, navigate to `http://your-server:8080` — you'll be redirected to Authentik.
Promote the first user to admin from the host running the server:

```bash
wicket user list
wicket make-admin --email you@example.com
```

Or use the admin portal at `http://localhost:9090` (accessible from the host only).

## CLI Usage

```bash
# Server must be running
wicket health
wicket device list --pending
wicket device approve --id <device-id>
wicket session list
wicket session extend --id <session-id> --duration 24h
wicket session revoke --id <session-id>
wicket user list
wicket reconcile
```

Full reference: [docs/cli.md](docs/cli.md).

## Architecture

```
Public Portal (:8080)  ─┐
Admin Portal  (:9090)  ─┤─► Core Service ─► PostgreSQL + wgctrl
CLI (Unix socket)      ─┘
                             ↕ WebSocket
                          Remote Agents
```

Details: [docs/architecture.md](docs/architecture.md).

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
