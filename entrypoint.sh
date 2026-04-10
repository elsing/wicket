#!/bin/sh

CONFIG_FILE="/etc/wicket/config.yaml"
for arg in "$@"; do
    case "$arg" in --config=*) CONFIG_FILE="${arg#--config=}" ;; esac
done

# Parse values from config
WG_IFACE=$(awk '/^\s*interface:/{gsub(/[" ]/, "", $2); print $2; exit}' "$CONFIG_FILE" 2>/dev/null)
WG_ADDR=$(awk '/^\s*address:/{gsub(/[" ]/, "", $2); print $2; exit}' "$CONFIG_FILE" 2>/dev/null)

WG_IFACE="${WG_IFACE:-wg1}"
WG_ADDR="${WG_ADDR:-10.10.0.1/24}"

echo "=== Wicket entrypoint ==="
echo "Config    : $CONFIG_FILE"
echo "Interface : $WG_IFACE"
echo "Address   : $WG_ADDR"

modprobe wireguard 2>/dev/null || echo "Note: modprobe wireguard failed (module may already be loaded)"

# Remove stale interface if it exists with wrong config, recreate clean
if ip link show "$WG_IFACE" > /dev/null 2>&1; then
    echo "Interface $WG_IFACE already exists"
else
    echo "Creating interface $WG_IFACE..."
    ip link add "$WG_IFACE" type wireguard || { echo "FATAL: cannot create $WG_IFACE"; exit 1; }
fi

# Assign address
CURRENT_ADDR=$(ip addr show "$WG_IFACE" 2>/dev/null | awk '/inet /{print $2}')
if [ "$CURRENT_ADDR" = "$WG_ADDR" ]; then
    echo "Address $WG_ADDR already set"
else
    if [ -n "$CURRENT_ADDR" ]; then
        ip addr del "$CURRENT_ADDR" dev "$WG_IFACE" 2>/dev/null || true
    fi
    echo "Setting address $WG_ADDR on $WG_IFACE..."
    ip addr add "$WG_ADDR" dev "$WG_IFACE" && echo "Address set OK" || echo "WARN: could not set address"
fi

ip link set "$WG_IFACE" up

echo "Interface state: $(ip addr show "$WG_IFACE" 2>/dev/null | head -3)"
echo "========================"

exec /usr/local/bin/wicket "$@"