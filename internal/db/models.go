// Package db handles database access: opening the connection, running migrations,
// and all query methods. Nothing outside this package touches SQL directly.
package db

import (
	"database/sql"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Groups
// ─────────────────────────────────────────────────────────────────────────────

// Group defines a session policy and a default set of subnets.
// Users and devices inherit the group's settings.
type Group struct {
	ID              string        `db:"id"`
	Name            string        `db:"name"`
	Description     string        `db:"description"`
	SessionDuration time.Duration `db:"session_duration"` // stored as seconds in DB
	MaxExtensions   sql.NullInt64 `db:"max_extensions"`   // NULL = unlimited
	IsPublic        bool          `db:"is_public"`        // any user can select this group
	CreatedAt       time.Time     `db:"created_at"`
	UpdatedAt       time.Time     `db:"updated_at"`

	// Populated by joins, not stored in this table.
	Subnets []Subnet `db:"-"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Subnets
// ─────────────────────────────────────────────────────────────────────────────

// Subnet is a named CIDR block available for routing.
// Designed to integrate cleanly with OSPF mesh routing.
type Subnet struct {
	ID          string    `db:"id"`
	Name        string    `db:"name"`
	CIDR        string    `db:"cidr"`
	Description string    `db:"description"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
}

// GroupSubnet is the many-to-many join between groups and subnets.
type GroupSubnet struct {
	ID        string    `db:"id"`
	GroupID   string    `db:"group_id"`
	SubnetID  string    `db:"subnet_id"`
	CreatedAt time.Time `db:"created_at"`
}

// DeviceSubnet is a per-device subnet override, set by an admin.
// When any DeviceSubnets exist for a device, they replace (not append to)
// the group's subnets for that device's WireGuard AllowedIPs.
type DeviceSubnet struct {
	ID        string    `db:"id"`
	DeviceID  string    `db:"device_id"`
	SubnetID  string    `db:"subnet_id"`
	CreatedAt time.Time `db:"created_at"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Users
// ─────────────────────────────────────────────────────────────────────────────

// User represents a person who has logged in via OIDC.
// Created automatically on first login.
type User struct {
	ID          string       `db:"id"`
	OIDCSub     string       `db:"oidc_sub"` // stable OIDC subject — primary identifier
	Email       string       `db:"email"`
	DisplayName string       `db:"display_name"`
	IsAdmin     bool         `db:"is_admin"`
	IsActive    bool         `db:"is_active"`
	CreatedAt   time.Time    `db:"created_at"`
	UpdatedAt   time.Time    `db:"updated_at"`
	LastLoginAt sql.NullTime `db:"last_login_at"`

	// Populated by joins.
	Groups  []Group  `db:"-"`
	Devices []Device `db:"-"`
}

// UserGroup is explicit group membership for restricted groups.
// Users can always see public groups without being in this table.
type UserGroup struct {
	ID        string    `db:"id"`
	UserID    string    `db:"user_id"`
	GroupID   string    `db:"group_id"`
	CreatedAt time.Time `db:"created_at"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Devices
// ─────────────────────────────────────────────────────────────────────────────

// Device is a WireGuard peer belonging to a user.
// The keypair is generated server-side; the private key is discarded after
// the one-time config download and never stored.
type Device struct {
	ID               string       `db:"id"`
	UserID           string       `db:"user_id"`
	GroupID          string       `db:"group_id"`
	Name             string       `db:"name"`
	PublicKey        string       `db:"public_key"`
	AssignedIP       string       `db:"assigned_ip"`
	IsApproved       bool         `db:"is_approved"`
	IsActive         bool         `db:"is_active"`         // admin-level toggle
	AutoRenew        bool         `db:"auto_renew"`        // activate session on portal login
	ConfigDownloaded bool         `db:"config_downloaded"` // one-time download guard
	CreatedAt        time.Time    `db:"created_at"`
	UpdatedAt        time.Time    `db:"updated_at"`
	LastSeenAt       sql.NullTime `db:"last_seen_at"`

	// Populated by joins.
	Group         *Group   `db:"-"`
	User          *User    `db:"-"`
	Subnets       []Subnet `db:"-"` // device overrides if set, else group subnets
	ActiveSession *Session `db:"-"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Sessions
// ─────────────────────────────────────────────────────────────────────────────

// Session represents an active or historical VPN session for a device.
// A WireGuard peer is present on the interface only when a valid session exists.
type Session struct {
	ID             string         `db:"id"`
	DeviceID       string         `db:"device_id"`
	DeviceName     string         `db:"-"` // populated by join queries
	UserEmail      string         `db:"-"` // populated by join queries
	AuthedAt       time.Time      `db:"authed_at"`
	ExpiresAt      time.Time      `db:"expires_at"`
	ExtendedAt     sql.NullTime   `db:"extended_at"`
	ExtensionCount int            `db:"extension_count"`
	RevokedAt      sql.NullTime   `db:"revoked_at"`
	RevokedBy      sql.NullString `db:"revoked_by"` // user_id of the admin who revoked
	IPAddress      string         `db:"ip_address"` // client portal IP at auth time
	Status         SessionStatus  `db:"status"`
}

// SessionStatus is the lifecycle state of a session.
type SessionStatus string

const (
	SessionStatusActive  SessionStatus = "active"
	SessionStatusExpired SessionStatus = "expired"
	SessionStatusRevoked SessionStatus = "revoked"
)

// IsActive returns true if the session has not expired and has not been revoked.
func (s *Session) IsActive() bool {
	return s.Status == SessionStatusActive && time.Now().Before(s.ExpiresAt)
}

// TimeRemaining returns the duration until the session expires.
// Returns 0 if already expired.
func (s *Session) TimeRemaining() time.Duration {
	d := time.Until(s.ExpiresAt)
	if d < 0 {
		return 0
	}
	return d
}

// ─────────────────────────────────────────────────────────────────────────────
// Agents
// ─────────────────────────────────────────────────────────────────────────────

// Agent represents a remote WireGuard agent registered with the core.
// Each agent manages its own WireGuard interface and receives peer updates
// via WebSocket from the core.
type Agent struct {
	ID          string       `db:"id"`
	Name        string       `db:"name"`
	Description string       `db:"description"`
	TokenHash   string       `db:"token"` // bcrypt hashed agent token
	IsActive    bool         `db:"is_active"`
	LastSeenAt  sql.NullTime `db:"last_seen_at"`
	CreatedAt   time.Time    `db:"created_at"`
	UpdatedAt   time.Time    `db:"updated_at"`

	// Set at runtime, not stored.
	Connected bool `db:"-"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Metrics
// ─────────────────────────────────────────────────────────────────────────────

// MetricSnapshot is a point-in-time sample of WireGuard stats for a device.
// Collected by the reconciler loop on each pass.
type MetricSnapshot struct {
	ID            string       `db:"id"`
	DeviceID      string       `db:"device_id"`
	BytesSent     int64        `db:"bytes_sent"`
	BytesReceived int64        `db:"bytes_received"`
	LastHandshake sql.NullTime `db:"last_handshake"`
	RecordedAt    time.Time    `db:"recorded_at"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit Log
// ─────────────────────────────────────────────────────────────────────────────

// AuditLog is an append-only record of system events.
// Rows are never updated or deleted.
type AuditLog struct {
	ID         string         `db:"id"`
	UserID     sql.NullString `db:"user_id"`
	DeviceID   sql.NullString `db:"device_id"`
	AgentID    sql.NullString `db:"agent_id"`
	Event      string         `db:"event"`
	Metadata   string         `db:"metadata"` // JSON blob
	IPAddress  string         `db:"ip_address"`
	CreatedAt  time.Time      `db:"created_at"`
	UserEmail  string         `db:"-"` // populated by join queries
	DeviceName string         `db:"-"` // populated by join queries
}

// Audit event constants. Format: "entity.action"
const (
	AuditEventUserLogin   = "user.login"
	AuditEventUserCreated = "user.created"

	AuditEventDeviceCreated  = "device.created"
	AuditEventDeviceApproved = "device.approved"
	AuditEventDeviceRejected = "device.rejected"
	AuditEventDeviceDeleted  = "device.deleted"
	AuditEventDeviceDisabled = "device.disabled"

	AuditEventSessionCreated  = "session.created"
	AuditEventSessionExtended = "session.extended"
	AuditEventSessionRevoked  = "session.revoked"
	AuditEventSessionExpired  = "session.expired"

	AuditEventPeerAdded   = "peer.added"
	AuditEventPeerRemoved = "peer.removed"

	AuditEventAgentConnected    = "agent.connected"
	AuditEventAgentDisconnected = "agent.disconnected"
	AuditEventAgentPurged       = "agent.purged" // dead man's switch triggered
)

// LocalAdmin is a local username/password account for emergency admin access.
// Used as a fallback when OIDC is unavailable.
type LocalAdmin struct {
	ID           string    `db:"id"`
	Username     string    `db:"username"`
	PasswordHash string    `db:"password_hash"`
	CreatedAt    time.Time `db:"created_at"`
}
