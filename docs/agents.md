# Remote Agents

A single-site Wicket deployment manages WireGuard on the same host the core
runs on and never needs this. Run a `wicket-agent` per remote site when you
want a group's devices to land on a different VPN endpoint — for geographic
distribution, HA, or to keep a site's traffic off the core host entirely.

See [architecture.md](architecture.md#remote-agents-internalagent-cmdwicket-agent)
for the wire protocol. This doc covers setting one up.

## 1. Register the agent

In the admin portal: **Agents → Register**. This creates an `Agent` row,
generates its WireGuard keypair server-side, and returns a one-time bearer
token — copy the token now, it's bcrypt-hashed at rest and isn't shown
again. If you lose it, revoke and re-register.

Generating the keypair server-side (rather than letting the agent generate
its own) means the agent's public key — and every device config that
embeds it as an `Endpoint` — stays stable even if you wipe and reinstall
the agent host later. See [Rotating an agent's key](#rotating-an-agents-key)
to change it deliberately.

## 2. Install on the remote host

On the remote machine (needs root, a Linux box with the `wireguard` kernel
module, and `NET_ADMIN`):

```bash
curl -fsSL https://your-wicket-server/agent/install.sh -o install-agent.sh
sudo bash install-agent.sh
```

Don't pipe directly to `bash` — the script reads prompts from the terminal
(token, WebSocket URL, interface name, listen port), which a pipe breaks.
Pass them as environment variables instead for non-interactive installs:

```bash
AGENT_TOKEN=xxx WICKET_SERVER=wss://your-wicket-server/agent/connect \
  WG_IFACE=wg1 WG_PORT=51820 sudo bash install-agent.sh
```

The script downloads the `wicket-agent` binary from the core
(`/agent/download`), generates a local WireGuard keypair as a bootstrap
placeholder, and installs a `systemd` unit that runs it with
`Restart=always`. That local key is superseded immediately on first
connect: the core sends the agent's *real* (server-generated) private key
in the first `sync` message, and the agent reconfigures its interface with
that instead.

```bash
systemctl status wicket-agent
journalctl -u wicket-agent -f
sudo wicket-agent remove   # uninstall
```

Re-running the install script on a host that already has it just updates
the binary and restarts the service, keeping the existing key and config.

## 3. Point a group at it

In the admin portal, assign the agent to a group (**Groups → \<group\> →
Agents**). Once assigned, new sessions for that group's devices are pushed
to the agent instead of the local WireGuard interface. If the group also
sets `endpoint_override`, generated client configs point at that endpoint
instead of the core's; otherwise they use the agent's own `endpoint` field
(set when registering the agent).

## Rotating an agent's key

```bash
wicket agent rotate-key --id <agent-id>                       # generate a fresh keypair
wicket agent rotate-key --id <agent-id> --private-key <key>   # import an existing one instead
```

This updates the `Agent` row immediately; the running agent picks up the
new key on its next `sync` (i.e. its next reconnect — no need to touch the
agent host). **After rotating, regenerate configs for every device in
groups that use this agent** — each config has the agent's *old* public
key baked in as the `[Peer] PublicKey` and won't reach the agent until
updated.

The `--private-key` import form exists for migrating an agent that was set
up before server-side key storage existed: register it normally, then
import its already-deployed private key so existing devices don't need new
configs.

## Failure behavior

- If the agent's WebSocket connection drops, it retries every 10s; on
  reconnect the core sends a fresh `sync` with the full current peer list.
- Sessions still expire correctly while disconnected — each peer's expiry is
  a local timer on the agent (seeded from `ExpiresAt` at the time it was
  added), not something that depends on a live connection to the core.
- What happens to *other* peers (no expiry, or one further out) while
  disconnected is controlled by the agent's
  `-keep-peers-on-disconnect` flag: `true` (the default, and what
  `install.sh` sets up) leaves them connected; `false` clears all local
  peers immediately on disconnect, fail-closed instead of fail-open.
- `config.yaml`'s `agent:` section (`core_url`, `token`, `core_timeout`) is
  **not used** by `wicket-agent` — see the note in
  [configuration.md](configuration.md#agent-section). Configure agents via
  the install script / systemd unit flags, not the config file.
