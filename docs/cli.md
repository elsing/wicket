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
wicket session create --device <device-id> [--duration 24h]  # start a session without portal login
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
wicket remove-admin --email you@example.com          # revoke admin privileges
wicket create-local-admin --username admin --password '...'
```

`create-local-admin` creates a username/password account for the **admin
portal only** — a fallback in case your OIDC provider is unreachable. It
bypasses OIDC entirely; don't create one you don't need.

## Agents

```bash
wicket agent list                                       # all registered agents, as JSON
wicket agent rotate-key --id <agent-id>                 # generate a fresh keypair server-side
wicket agent rotate-key --id <agent-id> --private-key <key>  # import an existing key instead
```

The agent picks up a rotated key automatically on its next reconnect — no
access to the agent host needed. See [agents.md](agents.md) for the full
remote-agent setup.

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
