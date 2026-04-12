package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

func newID() string {
	return uuid.New().String()
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("db.mustJSON: %v", err))
	}
	return string(b)
}

// ─────────────────────────────────────────────────────────────────────────────
// Users
// ─────────────────────────────────────────────────────────────────────────────

func (d *DB) GetUserByOIDCSub(ctx context.Context, sub string) (*User, error) {
	row := d.sql.QueryRowContext(ctx,
		`SELECT id, oidc_sub, email, display_name, is_admin, is_active,
		        created_at, updated_at, last_login_at
		 FROM users WHERE oidc_sub = ?`, sub)
	return scanUser(row)
}

func (d *DB) GetUserByID(ctx context.Context, id string) (*User, error) {
	row := d.sql.QueryRowContext(ctx,
		`SELECT id, oidc_sub, email, display_name, is_admin, is_active,
		        created_at, updated_at, last_login_at
		 FROM users WHERE id = ?`, id)
	return scanUser(row)
}

func (d *DB) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	row := d.sql.QueryRowContext(ctx,
		`SELECT id, oidc_sub, email, display_name, is_admin, is_active,
		        created_at, updated_at, last_login_at
		 FROM users WHERE email = ?`, email)
	return scanUser(row)
}

// UpsertUser creates or updates a user from OIDC claims on every login.
// Explicitly sets is_active = 1 so new users are always active.
func (d *DB) UpsertUser(ctx context.Context, sub, email, displayName string) (*User, error) {
	now := time.Now().UTC()
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO users (id, oidc_sub, email, display_name, is_active, is_admin, created_at, updated_at, last_login_at)
		VALUES (?, ?, ?, ?, 1, 0, ?, ?, ?)
		ON CONFLICT(oidc_sub) DO UPDATE SET
			email         = excluded.email,
			display_name  = excluded.display_name,
			is_active     = 1,
			updated_at    = excluded.updated_at,
			last_login_at = excluded.last_login_at
	`, newID(), sub, email, displayName, now, now, now)
	if err != nil {
		return nil, fmt.Errorf("upserting user: %w", err)
	}
	return d.GetUserByOIDCSub(ctx, sub)
}

func (d *DB) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := d.sql.QueryContext(ctx,
		`SELECT id, oidc_sub, email, display_name, is_admin, is_active,
		        created_at, updated_at, last_login_at
		 FROM users ORDER BY email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanUsers(rows)
}

// SetUserAdmin sets the is_admin flag. Uses 1/0 explicitly for SQLite compatibility.
func (d *DB) SetUserAdmin(ctx context.Context, userID string, admin bool) error {
	val := 0
	if admin {
		val = 1
	}
	result, err := d.sql.ExecContext(ctx,
		`UPDATE users SET is_admin = ? WHERE id = ?`, val, userID)
	if err != nil {
		return fmt.Errorf("setting admin flag: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

func scanUser(row *sql.Row) (*User, error) {
	var u User
	err := row.Scan(
		&u.ID, &u.OIDCSub, &u.Email, &u.DisplayName,
		&u.IsAdmin, &u.IsActive,
		&u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
	)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func scanUsers(rows *sql.Rows) ([]*User, error) {
	var users []*User
	for rows.Next() {
		var u User
		if err := rows.Scan(
			&u.ID, &u.OIDCSub, &u.Email, &u.DisplayName,
			&u.IsAdmin, &u.IsActive,
			&u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
		); err != nil {
			return nil, err
		}
		users = append(users, &u)
	}
	return users, rows.Err()
}

// ─────────────────────────────────────────────────────────────────────────────
// Groups
// ─────────────────────────────────────────────────────────────────────────────

func (d *DB) GetGroupByID(ctx context.Context, id string) (*Group, error) {
	row := d.sql.QueryRowContext(ctx,
		`SELECT id, name, description, session_duration, max_extensions, is_public,
		        endpoint_override, created_at, updated_at
		 FROM groups WHERE id = ?`, id)
	return scanGroup(row)
}

func (d *DB) ListGroups(ctx context.Context) ([]*Group, error) {
	rows, err := d.sql.QueryContext(ctx,
		`SELECT id, name, description, session_duration, max_extensions, is_public,
		        endpoint_override, created_at, updated_at
		 FROM groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanGroups(rows)
}

func (d *DB) ListGroupsForUser(ctx context.Context, userID string) ([]*Group, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT DISTINCT g.id, g.name, g.description, g.session_duration,
		                g.max_extensions, g.is_public, g.endpoint_override,
		                g.created_at, g.updated_at
		FROM groups g
		LEFT JOIN user_groups ug ON ug.group_id = g.id AND ug.user_id = ?
		WHERE g.is_public = 1 OR ug.user_id IS NOT NULL
		ORDER BY g.name
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanGroups(rows)
}

func (d *DB) CreateGroup(ctx context.Context, name, description string, sessionDuration time.Duration, maxExtensions *int64, isPublic bool) (*Group, error) {
	id := newID()
	now := time.Now().UTC()
	isPublicInt := 0
	if isPublic {
		isPublicInt = 1
	}
	_, err := d.sql.ExecContext(ctx,
		`INSERT INTO groups (id, name, description, session_duration, max_extensions, is_public, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, name, description, int64(sessionDuration.Seconds()), maxExtensions, isPublicInt, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("creating group: %w", err)
	}
	return d.GetGroupByID(ctx, id)
}

func scanGroup(row *sql.Row) (*Group, error) {
	var g Group
	var sessionSecs int64
	err := row.Scan(
		&g.ID, &g.Name, &g.Description, &sessionSecs,
		&g.MaxExtensions, &g.IsPublic,
		&g.EndpointOverride,
		&g.CreatedAt, &g.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	g.SessionDuration = time.Duration(sessionSecs) * time.Second
	return &g, nil
}

func scanGroups(rows *sql.Rows) ([]*Group, error) {
	var groups []*Group
	for rows.Next() {
		var g Group
		var sessionSecs int64
		if err := rows.Scan(
			&g.ID, &g.Name, &g.Description, &sessionSecs,
			&g.MaxExtensions, &g.IsPublic,
			&g.EndpointOverride,
			&g.CreatedAt, &g.UpdatedAt,
		); err != nil {
			return nil, err
		}
		g.SessionDuration = time.Duration(sessionSecs) * time.Second
		groups = append(groups, &g)
	}
	return groups, rows.Err()
}

// ─────────────────────────────────────────────────────────────────────────────
// Routes
// ─────────────────────────────────────────────────────────────────────────────

func (d *DB) GetRouteByID(ctx context.Context, id string) (*Route, error) {
	row := d.sql.QueryRowContext(ctx,
		`SELECT id, name, cidr, description, created_at, updated_at FROM subnets WHERE id = ?`, id)
	return scanRoute(row)
}

func (d *DB) ListRoutes(ctx context.Context) ([]*Route, error) {
	rows, err := d.sql.QueryContext(ctx,
		`SELECT id, name, cidr, description, created_at, updated_at FROM subnets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRoutes(rows)
}

func (d *DB) ListRoutesForDevice(ctx context.Context, deviceID string) ([]*Route, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT s.id, s.name, s.cidr, s.description, s.created_at, s.updated_at
		FROM device_subnets ds
		JOIN subnets s ON s.id = ds.route_id
		WHERE ds.device_id = ?
		ORDER BY s.name
	`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	subnets, err := scanRoutes(rows)
	if err != nil {
		return nil, err
	}
	if len(subnets) > 0 {
		return subnets, nil
	}
	// Fall back to group subnets
	rows2, err := d.sql.QueryContext(ctx, `
		SELECT s.id, s.name, s.cidr, s.description, s.created_at, s.updated_at
		FROM group_subnets gs
		JOIN subnets s ON s.id = gs.route_id
		JOIN devices d ON d.group_id = gs.group_id
		WHERE d.id = ?
		ORDER BY s.name
	`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows2.Close()
	return scanRoutes(rows2)
}

func (d *DB) CreateRoute(ctx context.Context, name, cidr, description string) (*Route, error) {
	id := newID()
	now := time.Now().UTC()
	_, err := d.sql.ExecContext(ctx,
		`INSERT INTO subnets (id, name, cidr, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, name, cidr, description, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("creating subnet: %w", err)
	}
	return d.GetRouteByID(ctx, id)
}

func scanRoute(row *sql.Row) (*Route, error) {
	var s Route
	return &s, row.Scan(&s.ID, &s.Name, &s.CIDR, &s.Description, &s.CreatedAt, &s.UpdatedAt)
}

func scanRoutes(rows *sql.Rows) ([]*Route, error) {
	var routes []*Route
	for rows.Next() {
		var s Route
		if err := rows.Scan(&s.ID, &s.Name, &s.CIDR, &s.Description, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		routes = append(routes, &s)
	}
	return routes, rows.Err()
}

// ─────────────────────────────────────────────────────────────────────────────
// Devices
// ─────────────────────────────────────────────────────────────────────────────

func (d *DB) GetDeviceByID(ctx context.Context, id string) (*Device, error) {
	row := d.sql.QueryRowContext(ctx, deviceSelectSQL+` WHERE id = ?`, id)
	return scanDevice(row)
}

func (d *DB) GetDeviceByPublicKey(ctx context.Context, key string) (*Device, error) {
	row := d.sql.QueryRowContext(ctx, deviceSelectSQL+` WHERE public_key = ?`, key)
	return scanDevice(row)
}

func (d *DB) ListDevicesByUser(ctx context.Context, userID string) ([]*Device, error) {
	rows, err := d.sql.QueryContext(ctx, deviceSelectSQL+` WHERE user_id = ? ORDER BY name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanDevices(rows)
}

func (d *DB) ListAllDevices(ctx context.Context) ([]*Device, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT d.id, d.user_id, d.group_id, d.name, d.public_key, d.assigned_ip,
		       d.is_approved, d.is_active, d.auto_renew, d.config_downloaded,
		       d.created_at, d.updated_at, d.last_seen_at,
		       u.email, u.display_name, g.name as group_name
		FROM devices d
		LEFT JOIN users u ON u.id = d.user_id
		LEFT JOIN groups g ON g.id = d.group_id
		ORDER BY d.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var devices []*Device
	for rows.Next() {
		var dev Device
		var userEmail, userDisplay, groupName sql.NullString
		if err := rows.Scan(
			&dev.ID, &dev.UserID, &dev.GroupID, &dev.Name,
			&dev.PublicKey, &dev.AssignedIP,
			&dev.IsApproved, &dev.IsActive, &dev.AutoRenew, &dev.ConfigDownloaded,
			&dev.CreatedAt, &dev.UpdatedAt, &dev.LastSeenAt,
			&userEmail, &userDisplay, &groupName,
		); err != nil {
			return nil, err
		}
		dev.User = &User{ID: dev.UserID, Email: userEmail.String, DisplayName: userDisplay.String}
		dev.Group = &Group{ID: dev.GroupID, Name: groupName.String}
		devices = append(devices, &dev)
	}
	return devices, rows.Err()
}

func (d *DB) ListAllDevicesRaw(ctx context.Context) ([]*Device, error) {
	rows, err := d.sql.QueryContext(ctx, deviceSelectSQL+` ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanDevices(rows)
}

func (d *DB) ListDevicesForGroup(ctx context.Context, groupID string) ([]*Device, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT d.id, d.user_id, d.group_id, d.name, d.public_key, d.assigned_ip,
		       d.is_approved, d.is_active, d.auto_renew, d.config_downloaded,
		       d.created_at, d.updated_at, d.last_seen_at,
		       u.email, u.display_name, g.name as group_name
		FROM devices d
		LEFT JOIN users u ON u.id = d.user_id
		LEFT JOIN groups g ON g.id = d.group_id
		WHERE d.group_id = ?
		ORDER BY d.created_at DESC`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var devices []*Device
	for rows.Next() {
		var dev Device
		var userEmail, userDisplay, groupName sql.NullString
		if err := rows.Scan(
			&dev.ID, &dev.UserID, &dev.GroupID, &dev.Name,
			&dev.PublicKey, &dev.AssignedIP,
			&dev.IsApproved, &dev.IsActive, &dev.AutoRenew, &dev.ConfigDownloaded,
			&dev.CreatedAt, &dev.UpdatedAt, &dev.LastSeenAt,
			&userEmail, &userDisplay, &groupName,
		); err != nil {
			return nil, err
		}
		dev.User = &User{ID: dev.UserID, Email: userEmail.String, DisplayName: userDisplay.String}
		dev.Group = &Group{ID: dev.GroupID, Name: groupName.String}
		devices = append(devices, &dev)
	}
	return devices, rows.Err()
}

func (d *DB) ListPendingDevices(ctx context.Context) ([]*Device, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT d.id, d.user_id, d.group_id, d.name, d.public_key, d.assigned_ip,
		       d.is_approved, d.is_active, d.auto_renew, d.config_downloaded,
		       d.created_at, d.updated_at, d.last_seen_at,
		       u.email, u.display_name, g.name as group_name
		FROM devices d
		LEFT JOIN users u ON u.id = d.user_id
		LEFT JOIN groups g ON g.id = d.group_id
		WHERE d.is_approved = 0 ORDER BY d.created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var devices []*Device
	for rows.Next() {
		var dev Device
		var userEmail, userDisplay, groupName sql.NullString
		if err := rows.Scan(
			&dev.ID, &dev.UserID, &dev.GroupID, &dev.Name,
			&dev.PublicKey, &dev.AssignedIP,
			&dev.IsApproved, &dev.IsActive, &dev.AutoRenew, &dev.ConfigDownloaded,
			&dev.CreatedAt, &dev.UpdatedAt, &dev.LastSeenAt,
			&userEmail, &userDisplay, &groupName,
		); err != nil {
			return nil, err
		}
		dev.User = &User{ID: dev.UserID, Email: userEmail.String, DisplayName: userDisplay.String}
		dev.Group = &Group{ID: dev.GroupID, Name: groupName.String}
		devices = append(devices, &dev)
	}
	return devices, rows.Err()
}

func (d *DB) ListApprovedActiveDevices(ctx context.Context) ([]*Device, error) {
	rows, err := d.sql.QueryContext(ctx, deviceSelectSQL+` WHERE is_approved = 1 AND is_active = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanDevices(rows)
}

func (d *DB) CreateDevice(ctx context.Context, dev *Device) (*Device, error) {
	dev.ID = newID()
	now := time.Now().UTC()
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO devices
			(id, user_id, group_id, name, public_key, assigned_ip,
			 is_approved, is_active, auto_renew, config_downloaded,
			 created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 0, 1, 0, 0, ?, ?)
	`, dev.ID, dev.UserID, dev.GroupID, dev.Name, dev.PublicKey, dev.AssignedIP, now, now)
	if err != nil {
		return nil, fmt.Errorf("creating device: %w", err)
	}
	return d.GetDeviceByID(ctx, dev.ID)
}

func (d *DB) ApproveDevice(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE devices SET is_approved = 1 WHERE id = ?`, id)
	return err
}

func (d *DB) RejectDevice(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM devices WHERE id = ? AND is_approved = 0`, id)
	return err
}

func (d *DB) SetDeviceActive(ctx context.Context, id string, active bool) error {
	val := 0
	if active {
		val = 1
	}
	_, err := d.sql.ExecContext(ctx, `UPDATE devices SET is_active = ? WHERE id = ?`, val, id)
	return err
}

func (d *DB) SetDeviceAutoRenew(ctx context.Context, id string, autoRenew bool) error {
	val := 0
	if autoRenew {
		val = 1
	}
	_, err := d.sql.ExecContext(ctx, `UPDATE devices SET auto_renew = ? WHERE id = ?`, val, id)
	return err
}

func (d *DB) MarkConfigDownloaded(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE devices SET config_downloaded = 1 WHERE id = ?`, id)
	return err
}

const deviceSelectSQL = `SELECT id, user_id, group_id, name, public_key, assigned_ip,
	is_approved, is_active, auto_renew, config_downloaded,
	created_at, updated_at, last_seen_at FROM devices`

func scanDevice(row *sql.Row) (*Device, error) {
	var dev Device
	err := row.Scan(
		&dev.ID, &dev.UserID, &dev.GroupID, &dev.Name,
		&dev.PublicKey, &dev.AssignedIP,
		&dev.IsApproved, &dev.IsActive, &dev.AutoRenew, &dev.ConfigDownloaded,
		&dev.CreatedAt, &dev.UpdatedAt, &dev.LastSeenAt,
	)
	if err != nil {
		return nil, err
	}
	return &dev, nil
}

func scanDevices(rows *sql.Rows) ([]*Device, error) {
	var devices []*Device
	for rows.Next() {
		var dev Device
		if err := rows.Scan(
			&dev.ID, &dev.UserID, &dev.GroupID, &dev.Name,
			&dev.PublicKey, &dev.AssignedIP,
			&dev.IsApproved, &dev.IsActive, &dev.AutoRenew, &dev.ConfigDownloaded,
			&dev.CreatedAt, &dev.UpdatedAt, &dev.LastSeenAt,
		); err != nil {
			return nil, err
		}
		devices = append(devices, &dev)
	}
	return devices, rows.Err()
}

// ─────────────────────────────────────────────────────────────────────────────
// Sessions
// ─────────────────────────────────────────────────────────────────────────────

func (d *DB) GetActiveSessionForDevice(ctx context.Context, deviceID string) (*Session, error) {
	row := d.sql.QueryRowContext(ctx, `
		SELECT id, device_id, authed_at, expires_at, extended_at,
		       extension_count, revoked_at, revoked_by, ip_address, status
		FROM sessions
		WHERE device_id = ? AND status = 'active' AND expires_at > ?
		ORDER BY authed_at DESC LIMIT 1
	`, deviceID, time.Now().UTC())
	return scanSession(row)
}

func (d *DB) GetSessionByID(ctx context.Context, id string) (*Session, error) {
	row := d.sql.QueryRowContext(ctx, `
		SELECT id, device_id, authed_at, expires_at, extended_at,
		       extension_count, revoked_at, revoked_by, ip_address, status
		FROM sessions WHERE id = ?
	`, id)
	return scanSession(row)
}

func (d *DB) CreateSession(ctx context.Context, deviceID string, expiresAt time.Time, ipAddress string) (*Session, error) {
	id := newID()
	now := time.Now().UTC()
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO sessions (id, device_id, authed_at, expires_at, ip_address, status)
		VALUES (?, ?, ?, ?, ?, 'active')
	`, id, deviceID, now, expiresAt, ipAddress)
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}
	return d.GetSessionByID(ctx, id)
}

func (d *DB) ExtendSession(ctx context.Context, id string, by time.Duration) (*Session, error) {
	// Fetch current expiry, add duration in Go, write back as a proper time value.
	// SQLite datetime() arithmetic fails with RFC3339 strings stored by Go's driver.
	sess, err := d.GetSessionByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("extending session: getting session: %w", err)
	}
	newExpiry := sess.ExpiresAt.Add(by)
	now := time.Now().UTC()
	_, err = d.sql.ExecContext(ctx, `
		UPDATE sessions
		SET expires_at      = ?,
		    extended_at     = ?,
		    extension_count = extension_count + 1
		WHERE id = ? AND status = 'active'
	`, newExpiry, now, id)
	if err != nil {
		return nil, fmt.Errorf("extending session: %w", err)
	}
	return d.GetSessionByID(ctx, id)
}

func (d *DB) RevokeSession(ctx context.Context, id, revokedBy string) error {
	now := time.Now().UTC()
	_, err := d.sql.ExecContext(ctx, `
		UPDATE sessions SET status = 'revoked', revoked_at = ?, revoked_by = ?
		WHERE id = ?
	`, now, revokedBy, id)
	return err
}

func (d *DB) MarkExpiredSessions(ctx context.Context) (int64, error) {
	result, err := d.sql.ExecContext(ctx, `
		UPDATE sessions SET status = 'expired'
		WHERE status = 'active' AND expires_at <= ?
	`, time.Now().UTC())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (d *DB) ListActiveSessions(ctx context.Context) ([]*Session, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT s.id, s.device_id, s.authed_at, s.expires_at, s.extended_at,
		       s.extension_count, s.revoked_at, s.revoked_by, s.ip_address, s.status,
		       d.name as device_name, u.email as user_email
		FROM sessions s
		LEFT JOIN devices d ON d.id = s.device_id
		LEFT JOIN users u ON u.id = d.user_id
		WHERE s.status = 'active' AND s.expires_at > ?
		ORDER BY s.expires_at ASC
	`, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sessions []*Session
	for rows.Next() {
		var s Session
		var deviceName, userEmail sql.NullString
		if err := rows.Scan(
			&s.ID, &s.DeviceID, &s.AuthedAt, &s.ExpiresAt,
			&s.ExtendedAt, &s.ExtensionCount,
			&s.RevokedAt, &s.RevokedBy,
			&s.IPAddress, &s.Status,
			&deviceName, &userEmail,
		); err != nil {
			return nil, err
		}
		s.DeviceName = deviceName.String
		s.UserEmail = userEmail.String
		sessions = append(sessions, &s)
	}
	return sessions, rows.Err()
}

func scanSession(row *sql.Row) (*Session, error) {
	var s Session
	err := row.Scan(
		&s.ID, &s.DeviceID, &s.AuthedAt, &s.ExpiresAt,
		&s.ExtendedAt, &s.ExtensionCount,
		&s.RevokedAt, &s.RevokedBy,
		&s.IPAddress, &s.Status,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	return &s, err
}


// ─────────────────────────────────────────────────────────────────────────────
// Agents
// ─────────────────────────────────────────────────────────────────────────────

// GetAgentByID is defined in queries_extra.go

func (d *DB) ListAgents(ctx context.Context) ([]*Agent, error) {
	rows, err := d.sql.QueryContext(ctx,
		`SELECT id, name, description, token, vpn_pool, endpoint, wg_public_key,
		        is_active, last_seen_at, created_at
		 FROM agents ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var agents []*Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(
			&a.ID, &a.Name, &a.Description, &a.TokenHash,
			&a.VPNPool, &a.Endpoint, &a.WGPublicKey,
			&a.IsActive, &a.LastSeenAt, &a.CreatedAt,
		); err != nil {
			return nil, err
		}
		agents = append(agents, &a)
	}
	return agents, rows.Err()
}

func (d *DB) CreateAgent(ctx context.Context, name, description, tokenHash, vpnPool, endpoint string) (*Agent, error) {
	id := newID()
	now := time.Now().UTC()
	_, err := d.sql.ExecContext(ctx,
		`INSERT INTO agents (id, name, description, token, vpn_pool, endpoint, is_active, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, 1, ?)`,
		id, name, description, tokenHash, vpnPool, endpoint, now,
	)
	if err != nil {
		return nil, fmt.Errorf("creating agent: %w", err)
	}
	return d.GetAgentByID(ctx, id)
}

func (d *DB) TouchAgentSeen(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx,
		`UPDATE agents SET last_seen_at = ? WHERE id = ?`, time.Now().UTC(), id)
	return err
}

func (d *DB) GetActiveAgents(ctx context.Context) ([]*Agent, error) {
	rows, err := d.sql.QueryContext(ctx,
		`SELECT id, name, description, token, vpn_pool, endpoint, wg_public_key,
		        is_active, last_seen_at, created_at
		 FROM agents WHERE is_active = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var agents []*Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(
			&a.ID, &a.Name, &a.Description, &a.TokenHash,
			&a.VPNPool, &a.Endpoint, &a.WGPublicKey,
			&a.IsActive, &a.LastSeenAt, &a.CreatedAt,
		); err != nil {
			return nil, err
		}
		agents = append(agents, &a)
	}
	return agents, rows.Err()
}

// scanAgent removed - use GetAgentByID in queries_extra.go

// ─────────────────────────────────────────────────────────────────────────────
// Metrics
// ─────────────────────────────────────────────────────────────────────────────

func (d *DB) InsertMetricSnapshot(ctx context.Context, snap *MetricSnapshot) error {
	snap.ID = newID()
	snap.RecordedAt = time.Now().UTC()
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO metric_snapshots (id, device_id, bytes_sent, bytes_received, last_handshake, recorded_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, snap.ID, snap.DeviceID, snap.BytesSent, snap.BytesReceived, snap.LastHandshake, snap.RecordedAt)
	return err
}

func (d *DB) ListMetricSnapshotsForDevice(ctx context.Context, deviceID string, since time.Time) ([]*MetricSnapshot, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT id, device_id, bytes_sent, bytes_received, last_handshake, recorded_at
		FROM metric_snapshots
		WHERE device_id = ? AND recorded_at >= ?
		ORDER BY recorded_at ASC
	`, deviceID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var snaps []*MetricSnapshot
	for rows.Next() {
		var s MetricSnapshot
		if err := rows.Scan(
			&s.ID, &s.DeviceID, &s.BytesSent, &s.BytesReceived,
			&s.LastHandshake, &s.RecordedAt,
		); err != nil {
			return nil, err
		}
		snaps = append(snaps, &s)
	}
	return snaps, rows.Err()
}

func (d *DB) PruneOldMetrics(ctx context.Context, before time.Time) (int64, error) {
	result, err := d.sql.ExecContext(ctx,
		`DELETE FROM metric_snapshots WHERE recorded_at < ?`, before)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit log
// ─────────────────────────────────────────────────────────────────────────────

func (d *DB) WriteAuditLog(ctx context.Context, entry *AuditLog) error {
	entry.ID = newID()
	entry.CreatedAt = time.Now().UTC()
	if entry.Metadata == "" {
		entry.Metadata = "{}"
	}
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO audit_log (id, user_id, device_id, agent_id, event, metadata, ip_address, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, entry.ID, entry.UserID, entry.DeviceID, entry.AgentID,
		entry.Event, entry.Metadata, entry.IPAddress, entry.CreatedAt)
	return err
}

func (d *DB) ListAuditLog(ctx context.Context, limit int) ([]*AuditLog, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT a.id, a.user_id, a.device_id, a.agent_id, a.event, a.metadata, a.ip_address, a.created_at,
		       u.email as user_email, dev.name as device_name
		FROM audit_log a
		LEFT JOIN users u ON u.id = a.user_id
		LEFT JOIN devices dev ON dev.id = a.device_id
		ORDER BY a.created_at DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []*AuditLog
	for rows.Next() {
		var e AuditLog
		var userEmail, deviceName sql.NullString
		if err := rows.Scan(
			&e.ID, &e.UserID, &e.DeviceID, &e.AgentID,
			&e.Event, &e.Metadata, &e.IPAddress, &e.CreatedAt,
			&userEmail, &deviceName,
		); err != nil {
			return nil, err
		}
		e.UserEmail = userEmail.String
		e.DeviceName = deviceName.String
		entries = append(entries, &e)
	}
	return entries, rows.Err()
}

func AuditMeta(kv ...any) string {
	if len(kv)%2 != 0 {
		panic("db.AuditMeta: must be called with an even number of arguments")
	}
	m := make(map[string]any, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		key, ok := kv[i].(string)
		if !ok {
			panic(fmt.Sprintf("db.AuditMeta: key at index %d is not a string", i))
		}
		m[key] = kv[i+1]
	}
	return mustJSON(m)
}
