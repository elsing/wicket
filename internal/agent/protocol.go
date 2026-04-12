// Package agent defines the protocol between the Wicket core and remote agents.
// Agents connect to the core via WebSocket, authenticate with a bearer token,
// and receive peer management instructions.
package agent

import "time"

// MsgType identifies the type of a protocol message.
type MsgType string

const (
	// Server → Agent
	MsgSync       MsgType = "sync"        // full peer list on connect
	MsgPeerAdd    MsgType = "peer.add"    // add or update a WireGuard peer
	MsgPeerRemove MsgType = "peer.remove" // remove a WireGuard peer

	// Agent → Server
	MsgReady  MsgType = "ready"  // agent is up and connected
	MsgAck    MsgType = "ack"    // operation completed successfully
	MsgError  MsgType = "error"  // operation failed
	MsgStatus MsgType = "status" // periodic status report
)

// Envelope is the outer wrapper for all protocol messages.
type Envelope struct {
	Type    MsgType `json:"type"`
	MsgID   string  `json:"msg_id,omitempty"` // for ack correlation
	Payload any     `json:"payload,omitempty"`
}

// PeerConfig describes a WireGuard peer to be added/updated.
type PeerConfig struct {
	PublicKey   string   `json:"public_key"`
	AssignedIP  string   `json:"assigned_ip"` // /32 host route
	AllowedIPs  []string `json:"allowed_ips"` // what the peer can route
	DeviceID    string   `json:"device_id"`
	DeviceName  string   `json:"device_name,omitempty"`
}

// SyncPayload is sent on connect with the full peer list.
type SyncPayload struct {
	Peers            []PeerConfig `json:"peers"`
	Interface        string       `json:"interface"`         // WireGuard interface name
	ListenPort       int          `json:"listen_port"`
	PrivateKey       string       `json:"private_key"`       // agent's WireGuard private key
	InterfaceAddress string       `json:"interface_address"` // CIDR for the WG interface e.g. 10.1.0.1/24
}

// PeerRemovePayload identifies a peer to remove.
type PeerRemovePayload struct {
	PublicKey string `json:"public_key"`
	DeviceID  string `json:"device_id"`
}

// ReadyPayload is sent by the agent after connecting.
type ReadyPayload struct {
	AgentVersion string    `json:"agent_version"`
	Hostname     string    `json:"hostname"`
	WGPublicKey  string    `json:"wg_public_key"` // agent's WireGuard public key
	ConnectedAt  time.Time `json:"connected_at"`
}

// AckPayload confirms a peer operation.
type AckPayload struct {
	MsgID   string `json:"msg_id"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// StatusPayload is sent periodically by agents.
type StatusPayload struct {
	PeerCount  int       `json:"peer_count"`
	ReportedAt time.Time `json:"reported_at"`
}
