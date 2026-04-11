#!/bin/sh
# Minimal entrypoint — interface setup (IP, iptables) is handled by the Go server.
# This script only ensures the kernel module is loaded and IP forwarding is enabled.

CONFIG_FILE="/etc/wicket/config.yaml"
for arg in "$@"; do
    case "$arg" in --config=*) CONFIG_FILE="${arg#--config=}" ;; esac
done

WG_IFACE=$(awk '/^\s*interface:/{gsub(/[" ]/, "", $2); print $2; exit}' "$CONFIG_FILE" 2>/dev/null)
WG_IFACE="${WG_IFACE:-wg1}"

echo "Loading WireGuard kernel module..."
modprobe wireguard 2>/dev/null || true

# Enable IP forwarding — required for the server to route packets between
# the WireGuard interface and the LAN. The Go server handles iptables.
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true

# Create WireGuard interface if missing — Go server will configure it fully
if ! ip link show "$WG_IFACE" > /dev/null 2>&1; then
    ip link add "$WG_IFACE" type wireguard \
        || { echo "FATAL: cannot create $WG_IFACE — check NET_ADMIN capability"; exit 1; }
fi

exec /usr/local/bin/wicket "$@"
