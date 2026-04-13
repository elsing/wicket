#!/usr/bin/env bash
# wicket-agent installer / updater
#
# Download and run directly (do NOT pipe — piping disables prompts):
#   curl -fsSL https://your-wicket-server/agent/install.sh -o install-agent.sh
#   sudo bash install-agent.sh
#
# Non-interactive (env vars override all prompts):
#   AGENT_TOKEN=xxx WICKET_SERVER=wss://... sudo bash install-agent.sh

set -euo pipefail

WICKET_PUBLIC_URL="__WICKET_PUBLIC_URL__"
INSTALL_DIR="/usr/local/bin"
SERVICE_NAME="wicket-agent"
KEY_FILE="/etc/wicket-agent.key"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

info()    { echo "[wicket-agent] $*"; }
warning() { echo "[WARN] $*"; }
error()   { echo "[ERROR] $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || error "Please run as root: sudo bash $0"

# ── Detect existing installation ──────────────────────────────────────────────
ALREADY_INSTALLED=false
if [ -f "${INSTALL_DIR}/wicket-agent" ]; then
    ALREADY_INSTALLED=true
    warning "wicket-agent is already installed."
    exec < /dev/tty
    read -rp "Update binary and keep existing config? [Y/n]: " CONFIRM
    CONFIRM="${CONFIRM:-Y}"
    if [[ "${CONFIRM}" =~ ^[Nn] ]]; then
        info "Aborted. To remove: wicket-agent remove"
        exit 0
    fi
fi

# ── Download binary ────────────────────────────────────────────────────────────
info "Downloading wicket-agent from ${WICKET_PUBLIC_URL}..."
curl -fsSL --output "${INSTALL_DIR}/wicket-agent" "${WICKET_PUBLIC_URL}/agent/download"
chmod +x "${INSTALL_DIR}/wicket-agent"
info "Installed to ${INSTALL_DIR}/wicket-agent"

# If updating with an existing service, just restart and exit
if [ "${ALREADY_INSTALLED}" = "true" ] && [ -f "${SERVICE_FILE}" ]; then
    info "Restarting service with updated binary..."
    systemctl restart "${SERVICE_NAME}"
    info "Done. Logs: journalctl -u ${SERVICE_NAME} -f"
    exit 0
fi

# ── Generate WireGuard keypair ─────────────────────────────────────────────────
info "Generating WireGuard keypair..."
KEYGEN=$(${INSTALL_DIR}/wicket-agent -generate-key 2>&1)
PRIVATE_KEY=$(echo "${KEYGEN}" | grep "^PRIVATE_KEY=" | cut -d= -f2-)
PUBLIC_KEY=$(echo "${KEYGEN}" | grep "^Public key:" | awk '{print $NF}')
[ -z "${PRIVATE_KEY}" ] && error "Failed to generate keypair"
info "Public key: ${PUBLIC_KEY}"

# ── Configuration prompts ──────────────────────────────────────────────────────
echo ""
echo "=== wicket-agent configuration ==="
echo ""

if [ -z "${AGENT_TOKEN:-}" ]; then
    exec < /dev/tty
    read -rp "Agent token (from Wicket admin > Agents > Register): " AGENT_TOKEN
fi
[ -z "${AGENT_TOKEN}" ] && error "Token is required"

if [ -z "${WICKET_SERVER:-}" ]; then
    # Default: wss:// version of public portal, same path /agent/connect
    DEFAULT_SERVER="$(echo "${WICKET_PUBLIC_URL}" | sed 's|^http:|ws:|;s|^https:|wss:|')/agent/connect"
    exec < /dev/tty
    read -rp "Wicket server WebSocket URL [${DEFAULT_SERVER}]: " WICKET_SERVER
    WICKET_SERVER="${WICKET_SERVER:-${DEFAULT_SERVER}}"
fi

if [ -z "${WG_IFACE:-}" ]; then
    exec < /dev/tty
    read -rp "WireGuard interface [wg1]: " WG_IFACE
    WG_IFACE="${WG_IFACE:-wg1}"
fi

if [ -z "${WG_PORT:-}" ]; then
    exec < /dev/tty
    read -rp "WireGuard listen port [51820]: " WG_PORT
    WG_PORT="${WG_PORT:-51820}"
fi

# ── Save private key ───────────────────────────────────────────────────────────
echo "${PRIVATE_KEY}" > "${KEY_FILE}"
chmod 600 "${KEY_FILE}"
info "Private key saved to ${KEY_FILE}"

# ── Create systemd service ─────────────────────────────────────────────────────
info "Creating systemd service..."
cat > "${SERVICE_FILE}" << SVCEOF
[Unit]
Description=Wicket VPN Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/wicket-agent -server ${WICKET_SERVER} -token ${AGENT_TOKEN} -interface ${WG_IFACE} -listen-port ${WG_PORT} -private-key ${PRIVATE_KEY}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl start "${SERVICE_NAME}"

echo ""
info "wicket-agent installed and running!"
info "  Status: systemctl status ${SERVICE_NAME}"
info "  Logs:   journalctl -u ${SERVICE_NAME} -f"
info "  Remove: sudo wicket-agent remove"
echo ""
warning "Public key: ${PUBLIC_KEY}"
warning "This is sent to Wicket automatically when the agent first connects."