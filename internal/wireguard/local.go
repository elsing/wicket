package wireguard

import (
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// LocalPeerManager manages WireGuard peers on the local interface via wgctrl.
type LocalPeerManager struct {
	client *wgctrl.Client
	iface  string
}

// NewLocalPeerManager creates a LocalPeerManager for the named interface.
func NewLocalPeerManager(iface string) (*LocalPeerManager, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("creating wgctrl client: %w", err)
	}

	if _, err := client.Device(iface); err != nil {
		client.Close()
		return nil, fmt.Errorf(
			"accessing WireGuard interface %q: %w\n"+
				"  → is the interface up? does this process have NET_ADMIN capability?",
			iface, err,
		)
	}

	return &LocalPeerManager{client: client, iface: iface}, nil
}

// AddPeer adds or replaces a peer on the local WireGuard interface.
func (m *LocalPeerManager) AddPeer(cfg PeerConfig) error {
	key, err := wgtypes.ParseKey(cfg.PublicKey)
	if err != nil {
		return fmt.Errorf("parsing peer public key: %w", err)
	}

	if cfg.AssignedIP == nil {
		return fmt.Errorf("peer %s has nil AssignedIP", cfg.PublicKey)
	}

	// Force 4-byte representation. net.ParseIP returns 16-byte form for IPv4;
	// wgctrl requires 4-byte for IPv4 addresses or it panics.
	ip4 := cfg.AssignedIP.To4()
	if ip4 == nil {
		return fmt.Errorf("peer %s AssignedIP %s is not a valid IPv4 address", cfg.PublicKey, cfg.AssignedIP)
	}

	allowedIPs := make([]net.IPNet, 0, len(cfg.AllowedIPs)+1)

	// Always include the assigned /32.
	allowedIPs = append(allowedIPs, net.IPNet{
		IP:   ip4,
		Mask: net.CIDRMask(32, 32),
	})

	// Normalise and append subnet routes.
	for _, ipNet := range cfg.AllowedIPs {
		normalised := normaliseIPNet(ipNet)
		allowedIPs = append(allowedIPs, normalised)
	}

	peerCfg := wgtypes.PeerConfig{
		PublicKey:         key,
		ReplaceAllowedIPs: true,
		AllowedIPs:        allowedIPs,
	}

	if err := m.client.ConfigureDevice(m.iface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	}); err != nil {
		return fmt.Errorf("adding peer %s to %s: %w", cfg.PublicKey, m.iface, err)
	}

	return nil
}

// RemovePeer removes a peer by public key. Idempotent.
func (m *LocalPeerManager) RemovePeer(publicKey string) error {
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("parsing peer public key: %w", err)
	}

	if err := m.client.ConfigureDevice(m.iface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{PublicKey: key, Remove: true},
		},
	}); err != nil {
		return fmt.Errorf("removing peer %s from %s: %w", publicKey, m.iface, err)
	}

	return nil
}

// ListPeers returns the public keys of all peers on the interface.
func (m *LocalPeerManager) ListPeers() ([]string, error) {
	dev, err := m.client.Device(m.iface)
	if err != nil {
		return nil, fmt.Errorf("reading WireGuard device %s: %w", m.iface, err)
	}

	keys := make([]string, 0, len(dev.Peers))
	for _, p := range dev.Peers {
		keys = append(keys, p.PublicKey.String())
	}

	return keys, nil
}

// GetStats returns current WireGuard statistics for all peers.
func (m *LocalPeerManager) GetStats() ([]PeerStats, error) {
	dev, err := m.client.Device(m.iface)
	if err != nil {
		return nil, fmt.Errorf("reading WireGuard device %s: %w", m.iface, err)
	}

	stats := make([]PeerStats, 0, len(dev.Peers))
	for _, p := range dev.Peers {
		s := PeerStats{
			PublicKey:     p.PublicKey.String(),
			BytesSent:     p.TransmitBytes,
			BytesReceived: p.ReceiveBytes,
		}
		if !p.LastHandshakeTime.IsZero() {
			s.LastHandshake = p.LastHandshakeTime
		}
		stats = append(stats, s)
	}

	return stats, nil
}

// Close releases the wgctrl client.
func (m *LocalPeerManager) Close() error {
	return m.client.Close()
}

// ConfigureServer sets the server's private key and listen port.
func (m *LocalPeerManager) ConfigureServer(privateKeyBase64 string, listenPort int) error {
	key, err := wgtypes.ParseKey(privateKeyBase64)
	if err != nil {
		return fmt.Errorf("parsing server private key: %w", err)
	}

	if err := m.client.ConfigureDevice(m.iface, wgtypes.Config{
		PrivateKey: &key,
		ListenPort: &listenPort,
	}); err != nil {
		return fmt.Errorf("configuring WireGuard server on %s: %w", m.iface, err)
	}

	return nil
}

// ServerPublicKey derives the public key from a base64 private key.
func ServerPublicKey(privateKeyBase64 string) (string, error) {
	key, err := wgtypes.ParseKey(privateKeyBase64)
	if err != nil {
		return "", fmt.Errorf("parsing private key: %w", err)
	}
	return key.PublicKey().String(), nil
}

// normaliseIPNet ensures the IP in a net.IPNet is in 4-byte form for wgctrl.
func normaliseIPNet(n net.IPNet) net.IPNet {
	if ip4 := n.IP.To4(); ip4 != nil {
		return net.IPNet{IP: ip4, Mask: n.Mask}
	}
	return n
}

// compile-time interface check
var _ PeerManager = (*LocalPeerManager)(nil)
