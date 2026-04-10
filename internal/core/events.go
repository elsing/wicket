package core

// EventType identifies what kind of change occurred.
type EventType string

const (
	EventDeviceCreated  EventType = "device.created"
	EventDeviceApproved EventType = "device.approved"
	EventDeviceRejected EventType = "device.rejected"

	EventSessionCreated  EventType = "session.created"
	EventSessionExtended EventType = "session.extended"
	EventSessionRevoked  EventType = "session.revoked"
	EventSessionExpired  EventType = "session.expired"

	EventPeerAdded   EventType = "peer.added"
	EventPeerRemoved EventType = "peer.removed"

	EventAgentConnected    EventType = "agent.connected"
	EventAgentDisconnected EventType = "agent.disconnected"
)

// Event is published on the event channel when system state changes.
// The WebSocket hub broadcasts relevant events to connected portal clients.
type Event struct {
	Type     EventType `json:"type"`
	UserID   string    `json:"user_id,omitempty"`
	DeviceID string    `json:"device_id,omitempty"`
	AgentID  string    `json:"agent_id,omitempty"`
	// Payload carries additional context (e.g. expires_at for session events).
	Payload any `json:"payload,omitempty"`
}
