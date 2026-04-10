#!/bin/sh

CONFIG_FILE="/etc/wicket/config.yaml"
for arg in "$@"; do
    case "$arg" in --config=*) CONFIG_FILE="${arg#--config=}" ;; esac
done

WG_IFACE=$(awk '/^\s*interface:/{gsub(/[" ]/, "", $2); print $2; exit}' "$CONFIG_FILE" 2>/dev/null)
WG_ADDR=$(awk '/^\s*address:/{gsub(/[" ]/, "", $2); print $2; exit}' "$CONFIG_FILE" 2>/dev/null)
WG_IFACE="${WG_IFACE:-wg1}"
WG_ADDR="${WG_ADDR:-10.10.0.1/24}"

# Derive the VPN subnet from the address (e.g. 10.10.0.1/24 -> 10.10.0.0/24)
VPN_SUBNET=$(ip route 2>/dev/null | grep "$WG_IFACE" | awk '{print $1}' | head -1)

echo "=== Wicket entrypoint ==="
echo "Interface : $WG_IFACE"
echo "Address   : $WG_ADDR"

modprobe wireguard 2>/dev/null || true

# Always recreate interface for clean state
if ip link show "$WG_IFACE" > /dev/null 2>&1; then
    echo "Removing stale $WG_IFACE..."
    ip link delete "$WG_IFACE" 2>/dev/null || true
fi

ip link add "$WG_IFACE" type wireguard \
    || { echo "FATAL: cannot create $WG_IFACE"; exit 1; }

ip addr add "$WG_ADDR" dev "$WG_IFACE" \
    && echo "Address set OK" || echo "WARN: could not set address"

ip link set "$WG_IFACE" up

# ── Routing setup ─────────────────────────────────────────────────────────────
# Enable IP forwarding (belt-and-suspenders alongside sysctl in compose)
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

# Add iptables masquerade so VPN clients can reach the LAN.
# POSTROUTING masquerade: when a packet from the VPN subnet leaves via any
# non-WG interface (e.g. eth0), rewrite the source to the server's LAN IP.
# This means your firewall only needs a static route to the server — it doesn't
# need to know about individual VPN client IPs.
VPN_NET=$(echo "$WG_ADDR" | sed 's|\.[0-9]*/|.0/|')
echo "Setting up NAT masquerade for VPN subnet $VPN_NET..."
iptables -t nat -C POSTROUTING -s "$VPN_NET" ! -o "$WG_IFACE" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "$VPN_NET" ! -o "$WG_IFACE" -j MASQUERADE

# Allow forwarding between WG and LAN interfaces
iptables -C FORWARD -i "$WG_IFACE" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -i "$WG_IFACE" -j ACCEPT
iptables -C FORWARD -o "$WG_IFACE" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -o "$WG_IFACE" -j ACCEPT

echo "Routing configured"
echo "Interface state: $(ip addr show "$WG_IFACE" | grep 'inet ')"
echo "========================"

exec /usr/local/bin/wicket "$@"