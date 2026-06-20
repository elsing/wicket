// Package wireguard manages WireGuard peers via wgctrl. Nothing outside
// this package should reference wgctrl types directly.
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

