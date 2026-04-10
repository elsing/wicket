#!/bin/sh
# Minimal entrypoint — WireGuard interface setup is handled by the server itself.
# This script only ensures the kernel module is loaded and the interface exists
# as a basic WireGuard type before the Go process starts.

CONFIG_FILE="/etc/wicket/config.yaml"
for arg in "$@"; do
    case "$arg" in --config=*) CONFIG_FILE="${arg#--config=}" ;; esac
done

WG_IFACE=$(awk '/^\s*interface:/{gsub(/[" ]/, "", $2); print $2; exit}' "$CONFIG_FILE" 2>/dev/null)
WG_IFACE="${WG_IFACE:-wg1}"

echo "Loading WireGuard kernel module..."
modprobe wireguard 2>/dev/null || true

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

# Create interface if it doesn't exist — the Go server will configure it fully
if ! ip link show "$WG_IFACE" > /dev/null 2>&1; then
    echo "Creating $WG_IFACE..."
    ip link add "$WG_IFACE" type wireguard \
        || { echo "FATAL: cannot create $WG_IFACE — check NET_ADMIN capability"; exit 1; }
fi

echo "Handing off to wicket server..."
exec /usr/local/bin/wicket "$@"
