package wireguard

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"go.uber.org/zap"
)

// EnsureInterface creates (or recreates) the WireGuard interface with the
// correct address. If the interface exists but has the wrong address, it is
// corrected in-place without tearing down existing peers.
//
// This runs at server startup so config changes (e.g. switching VPN subnet)
// are applied automatically without needing entrypoint script changes.
func EnsureInterface(iface, address string, log *zap.Logger) error {
	// Parse the desired address
	ip, ipNet, err := net.ParseCIDR(address)
	if err != nil {
		return fmt.Errorf("invalid wireguard address %q: %w", address, err)
	}
	// Use host IP (e.g. 10.10.0.1), not network address (e.g. 10.10.0.0)
	desiredAddr := fmt.Sprintf("%s/%d", ip.String(), prefixLen(ipNet.Mask))

	// Check if interface already exists
	exists := run("ip", "link", "show", iface) == nil

	if !exists {
		log.Info("creating WireGuard interface", zap.String("iface", iface))
		if err := run("ip", "link", "add", iface, "type", "wireguard"); err != nil {
			return fmt.Errorf("creating interface %s: %w", iface, err)
		}
	}

	// Check current address
	currentAddr := getIfaceAddr(iface)
	if currentAddr != desiredAddr {
		if currentAddr != "" {
			log.Info("removing old interface address",
				zap.String("iface", iface),
				zap.String("old", currentAddr),
				zap.String("new", desiredAddr),
			)
			_ = run("ip", "addr", "del", currentAddr, "dev", iface)
		}
		log.Info("setting interface address",
			zap.String("iface", iface),
			zap.String("addr", desiredAddr),
		)
		if err := run("ip", "addr", "add", desiredAddr, "dev", iface); err != nil {
			return fmt.Errorf("setting address on %s: %w", iface, err)
		}
	} else {
		log.Info("interface address already correct",
			zap.String("iface", iface),
			zap.String("addr", desiredAddr),
		)
	}

	// Bring up
	if err := run("ip", "link", "set", iface, "up"); err != nil {
		return fmt.Errorf("bringing up %s: %w", iface, err)
	}

	// Set up NAT masquerade for VPN subnet
	vpnNet := ipNet.String()
	ensureIPTables(iface, vpnNet, log)

	log.Info("WireGuard interface ready",
		zap.String("iface", iface),
		zap.String("addr", desiredAddr),
	)
	return nil
}

// getIfaceAddr returns the current IPv4 address of the interface (with prefix),
// or empty string if none is set.
func getIfaceAddr(iface string) string {
	out, err := execOutput("ip", "addr", "show", iface)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return ""
}

// ensureIPTables sets up masquerade and forwarding rules if not already present.
func ensureIPTables(iface, vpnNet string, log *zap.Logger) {
	rules := [][]string{
		{"iptables", "-t", "nat", "-C", "POSTROUTING", "-s", vpnNet, "!", "-o", iface, "-j", "MASQUERADE"},
		{"iptables", "-C", "FORWARD", "-i", iface, "-j", "ACCEPT"},
		{"iptables", "-C", "FORWARD", "-o", iface, "-j", "ACCEPT"},
	}
	add := [][]string{
		{"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", vpnNet, "!", "-o", iface, "-j", "MASQUERADE"},
		{"iptables", "-A", "FORWARD", "-i", iface, "-j", "ACCEPT"},
		{"iptables", "-A", "FORWARD", "-o", iface, "-j", "ACCEPT"},
	}
	for i, check := range rules {
		if run(check...) != nil {
			// Rule doesn't exist — add it
			if err := run(add[i]...); err != nil {
				log.Warn("adding iptables rule", zap.Strings("rule", add[i]), zap.Error(err))
			}
		}
	}
}

func run(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	return cmd.Run()
}

func execOutput(args ...string) (string, error) {
	out, err := exec.Command(args[0], args[1:]...).Output()
	return string(out), err
}

func prefixLen(mask net.IPMask) int {
	ones, _ := mask.Size()
	return ones
}
