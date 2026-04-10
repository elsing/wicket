// Package wireguard provides the PeerManager interface and implementations
// for managing WireGuard peers. The core never calls wgctrl directly —
// everything goes through this interface so the local and remote agent
// implementations are interchangeable.
package wireguard

import (
	"net"
	"time"
)

// PeerConfig holds everything needed to add or update a WireGuard peer.
type PeerConfig struct {
	// PublicKey is the peer's WireGuard public key, base64 encoded.
	PublicKey string

	// AssignedIP is the peer's address within the WireGuard subnet, e.g. "10.10.0.2".
	AssignedIP net.IP

	// AllowedIPs is the list of CIDRs this peer is permitted to reach.
	// The assigned /32 is always included automatically.
	AllowedIPs []net.IPNet

	// ExpiresAt is the session expiry time. Sent to agents so they can
	// autonomously remove the peer when it expires without contacting the core.
	ExpiresAt time.Time
}

// PeerStats holds live WireGuard statistics for a peer, read from wgctrl.
type PeerStats struct {
	PublicKey     string
	BytesSent     int64
	BytesReceived int64
	LastHandshake time.Time // zero if never connected
}

// PeerManager is the interface for all WireGuard peer operations.
// The local implementation talks to wgctrl directly.
// The remote implementation delegates to an agent over WebSocket.
// Nothing outside this package should reference wgctrl types.
type PeerManager interface {
	// AddPeer adds or replaces a peer on the WireGuard interface.
	AddPeer(cfg PeerConfig) error

	// RemovePeer removes a peer by its public key.
	// It is not an error if the peer does not exist (idempotent).
	RemovePeer(publicKey string) error

	// ListPeers returns the public keys of all currently configured peers.
	ListPeers() ([]string, error)

	// GetStats returns current WireGuard statistics for all peers.
	GetStats() ([]PeerStats, error)

	// Close releases any resources held by the manager.
	Close() error
}
