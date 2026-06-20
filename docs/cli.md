# CLI Reference

`wicket` is both the server (`wicket serve`) and an admin client. The client
commands talk to a *running* server over a Unix socket
(`server.socket_path`, default `/var/run/wicket/core.sock`) — they don't
touch the database directly, so they only work on the same host as the
server (or wherever that socket is mounted).

```
wicket --socket /path/to/core.sock <command>   # --socket overrides server.socket_path
```

## Sessions

```bash
wicket session list                                    # all active sessions, as JSON
wicket session revoke --id <session-id>
wicket session extend --id <session-id> --duration 24h  # admin override — ignores the group's max_extensions
```

## Devices

```bash
wicket device list                  # all devices
wicket device list --pending        # only devices awaiting approval
wicket device approve --id <device-id>
wicket device reject --id <device-id>   # rejects AND deletes the device
```

## Users

```bash
wicket user list                                    # table: ID, email, display name, admin, active
wicket make-admin --email you@example.com           # promote a user to admin (bootstrap the first admin)
wicket create-local-admin --username admin --password '...'
```

`create-local-admin` creates a username/password account for the **admin
portal only** — a fallback in case your OIDC provider is unreachable. It
bypasses OIDC entirely; don't create one you don't need.

## Operational

```bash
wicket reconcile     # trigger an immediate reconcile pass instead of waiting for the timer
wicket health        # JSON health report (DB, WireGuard, reconciler last-run, agent connections)
```

## Server

```bash
wicket serve --config /etc/wicket/config.yaml
```

See [configuration.md](configuration.md) for what goes in that file.
