package db

import (
	"context"
	"fmt"
	"time"
)

func (d *DB) AddUserToGroup(ctx context.Context, userID, groupID string) error {
	_, err := d.sql.ExecContext(ctx,
		`INSERT OR IGNORE INTO user_groups (id, user_id, group_id, created_at) VALUES (?, ?, ?, ?)`,
		newID(), userID, groupID, time.Now().UTC())
	return err
}

func (d *DB) RemoveUserFromGroup(ctx context.Context, userID, groupID string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM user_groups WHERE user_id = ? AND group_id = ?`, userID, groupID)
	return err
}

func (d *DB) AddRouteToGroup(ctx context.Context, groupID, routeID string) error {
	_, err := d.sql.ExecContext(ctx,
		`INSERT OR IGNORE INTO group_subnets (id, group_id, route_id, created_at) VALUES (?, ?, ?, ?)`,
		newID(), groupID, routeID, time.Now().UTC())
	return err
}

func (d *DB) RemoveRouteFromGroup(ctx context.Context, groupID, routeID string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM group_subnets WHERE group_id = ? AND route_id = ?`, groupID, routeID)
	return err
}

func (d *DB) AddSubnetToDevice(ctx context.Context, deviceID, routeID string) error {
	_, err := d.sql.ExecContext(ctx,
		`INSERT OR IGNORE INTO device_subnets (id, device_id, route_id, created_at) VALUES (?, ?, ?, ?)`,
		newID(), deviceID, routeID, time.Now().UTC())
	return err
}

func (d *DB) RemoveSubnetFromDevice(ctx context.Context, deviceID, routeID string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM device_subnets WHERE device_id = ? AND route_id = ?`, deviceID, routeID)
	return err
}

func (d *DB) DeleteRoute(ctx context.Context, id string) error {
	result, err := d.sql.ExecContext(ctx, `DELETE FROM subnets WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting subnet: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("subnet %s not found", id)
	}
	return nil
}

func (d *DB) DeactivateAgent(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE agents SET is_active = 0 WHERE id = ?`, id)
	return err
}

// DeleteAgent permanently removes an agent and its group assignments.
// Only call on revoked (is_active=0) agents.
func (d *DB) DeleteAgent(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM agents WHERE id = ? AND is_active = 0`, id)
	return err
}

// ─────────────────────────────────────────────────────────────────────────────
// Local admin accounts (fallback when OIDC is unavailable)
// ─────────────────────────────────────────────────────────────────────────────

// GetLocalAdminByUsername returns a local admin account by username.
func (d *DB) GetLocalAdminByUsername(ctx context.Context, username string) (*LocalAdmin, error) {
	row := d.reader.QueryRowContext(ctx,
		`SELECT id, username, password_hash, created_at FROM local_admins WHERE username = ?`, username)
	var a LocalAdmin
	err := row.Scan(&a.ID, &a.Username, &a.PasswordHash, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// CreateLocalAdmin inserts a new local admin account with a bcrypt-hashed password.
func (d *DB) CreateLocalAdmin(ctx context.Context, username, passwordHash string) error {
	_, err := d.sql.ExecContext(ctx,
		`INSERT INTO local_admins (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)`,
		newID(), username, passwordHash, time.Now().UTC())
	return err
}

// DeleteDevice removes a device and all its sessions and subnet assignments.
func (d *DB) DeleteDevice(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, id)
	return err
}

// DeleteGroup removes a group. Fails if devices are still assigned to it.
func (d *DB) DeleteGroup(ctx context.Context, id string) error {
	// Check for devices first
	var count int
	if err := d.reader.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM devices WHERE group_id = ?`, id).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("cannot delete group: %d device(s) still assigned to it", count)
	}
	_, err := d.sql.ExecContext(ctx, `DELETE FROM groups WHERE id = ?`, id)
	return err
}

// ListGroupRoutes returns a map of groupID -> []routeID for all groups.
func (d *DB) ListGroupRoutes(ctx context.Context) (map[string][]string, error) {
	rows, err := d.reader.QueryContext(ctx, `SELECT group_id, route_id FROM group_subnets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string][]string)
	for rows.Next() {
		var gid, sid string
		if err := rows.Scan(&gid, &sid); err != nil {
			return nil, err
		}
		result[gid] = append(result[gid], sid)
	}
	return result, rows.Err()
}

// GetLocalAdminByID returns a local admin account by ID.
func (d *DB) GetLocalAdminByID(ctx context.Context, id string) (*LocalAdmin, error) {
	row := d.reader.QueryRowContext(ctx,
		`SELECT id, username, password_hash, created_at FROM local_admins WHERE id = ?`, id)
	var a LocalAdmin
	err := row.Scan(&a.ID, &a.Username, &a.PasswordHash, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// RevokeAllSessionsForDevice revokes all active sessions for a device,
// keeping only the most recent one. Used to clean up duplicate sessions.
func (d *DB) RevokeAllSessionsForDevice(ctx context.Context, deviceID string) (int64, error) {
	result, err := d.sql.ExecContext(ctx, `
		UPDATE sessions SET status = 'revoked', revoked_at = ?, revoked_by = 'system:cleanup'
		WHERE device_id = ? AND status = 'active'
		  AND id NOT IN (
		      SELECT id FROM sessions
		      WHERE device_id = ? AND status = 'active'
		      ORDER BY authed_at DESC LIMIT 1
		  )
	`, time.Now().UTC(), deviceID, deviceID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// DeduplicateSessions removes duplicate active sessions across all devices,
// keeping only the most recent session per device.
func (d *DB) DeduplicateSessions(ctx context.Context) (int64, error) {
	result, err := d.sql.ExecContext(ctx, `
		UPDATE sessions SET status = 'revoked', revoked_at = ?, revoked_by = 'system:cleanup'
		WHERE status = 'active'
		  AND id NOT IN (
		      SELECT id FROM (
		          SELECT id, ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY authed_at DESC) as rn
		          FROM sessions WHERE status = 'active'
		      ) WHERE rn = 1
		  )
	`, time.Now().UTC())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// GetLatestMetricPerDevice returns the most recent snapshot for each device.
func (d *DB) GetLatestMetricPerDevice(ctx context.Context) (map[string]*MetricSnapshot, error) {
	rows, err := d.reader.QueryContext(ctx, `
		SELECT m.id, m.device_id, m.bytes_sent, m.bytes_received, m.last_handshake, m.recorded_at
		FROM metric_snapshots m
		INNER JOIN (
			SELECT device_id, MAX(recorded_at) as latest
			FROM metric_snapshots
			GROUP BY device_id
		) latest ON m.device_id = latest.device_id AND m.recorded_at = latest.latest
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]*MetricSnapshot)
	for rows.Next() {
		var s MetricSnapshot
		if err := rows.Scan(&s.ID, &s.DeviceID, &s.BytesSent, &s.BytesReceived,
			&s.LastHandshake, &s.RecordedAt); err != nil {
			return nil, err
		}
		result[s.DeviceID] = &s
	}
	return result, rows.Err()
}

// DeviceCountPerGroup returns a map of groupID -> count of approved devices.
func (d *DB) DeviceCountPerGroup(ctx context.Context) (map[string]int, error) {
	rows, err := d.reader.QueryContext(ctx, `
		SELECT group_id, COUNT(*) as cnt
		FROM devices
		WHERE is_approved = 1
		GROUP BY group_id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]int)
	for rows.Next() {
		var groupID string
		var cnt int
		if err := rows.Scan(&groupID, &cnt); err != nil {
			return nil, err
		}
		result[groupID] = cnt
	}
	return result, rows.Err()
}

// UpdateGroup updates a group's name, description, session duration, max extensions,
// routing mode and endpoint override.
func (d *DB) UpdateGroup(ctx context.Context, id, name, description string, sessionDuration time.Duration, maxExtensions *int64, endpointOverride string, isPublic bool) error {
	var maxExt interface{}
	if maxExtensions != nil {
		maxExt = *maxExtensions
	}
	_, err := d.sql.ExecContext(ctx, `
		UPDATE groups SET name = ?, description = ?, session_duration = ?, max_extensions = ?,
		                  endpoint_override = ?, is_public = ?
		WHERE id = ?
	`, name, description, int64(sessionDuration.Seconds()), maxExt, endpointOverride, isPublic, id)
	return err
}

// AssignAgentToGroup adds an agent to a group's agent list.
func (d *DB) AssignAgentToGroup(ctx context.Context, groupID, agentID string) error {
	_, err := d.sql.ExecContext(ctx,
		`INSERT OR IGNORE INTO group_agents (group_id, agent_id) VALUES (?, ?)`,
		groupID, agentID)
	return err
}

// RemoveAgentFromGroup removes an agent from a group.
func (d *DB) RemoveAgentFromGroup(ctx context.Context, groupID, agentID string) error {
	_, err := d.sql.ExecContext(ctx,
		`DELETE FROM group_agents WHERE group_id = ? AND agent_id = ?`,
		groupID, agentID)
	return err
}

// GetGroupAgents returns all agents assigned to a group.
func (d *DB) GetGroupAgents(ctx context.Context, groupID string) ([]*Agent, error) {
	rows, err := d.reader.QueryContext(ctx, `
		SELECT a.id, a.name, a.description, a.token, a.vpn_pool, a.endpoint, a.wg_public_key,
		       a.is_active, a.last_seen_at, a.created_at
		FROM agents a
		INNER JOIN group_agents ga ON ga.agent_id = a.id
		WHERE ga.group_id = ?
	`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var agents []*Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(&a.ID, &a.Name, &a.Description, &a.TokenHash,
			&a.VPNPool, &a.Endpoint, &a.WGPublicKey, &a.IsActive, &a.LastSeenAt, &a.CreatedAt); err != nil {
			return nil, err
		}
		agents = append(agents, &a)
	}
	return agents, rows.Err()
}

// GetGroupAgentMap returns a map of groupID -> []agentID for all groups.
func (d *DB) GetGroupAgentMap(ctx context.Context) (map[string][]string, error) {
	rows, err := d.reader.QueryContext(ctx, `SELECT group_id, agent_id FROM group_agents`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string][]string)
	for rows.Next() {
		var gid, aid string
		if err := rows.Scan(&gid, &aid); err != nil {
			return nil, err
		}
		result[gid] = append(result[gid], aid)
	}
	return result, rows.Err()
}

// UpdateAgentDetails updates an agent's name, description, vpn_pool and endpoint.
func (d *DB) UpdateAgentDetails(ctx context.Context, id, name, description, vpnPool, endpoint string) error {
	_, err := d.sql.ExecContext(ctx,
		`UPDATE agents SET name=?, description=?, vpn_pool=?, endpoint=? WHERE id=?`,
		name, description, vpnPool, endpoint, id) // wg_public_key updated via UpdateAgentPublicKey
	return err
}

// GetAgentByID returns a single agent by ID.
func (d *DB) GetAgentByID(ctx context.Context, id string) (*Agent, error) {
	row := d.reader.QueryRowContext(ctx, `
		SELECT id, name, description, token, vpn_pool, endpoint, wg_public_key,
		       is_active, last_seen_at, created_at
		FROM agents WHERE id = ?`, id)
	var a Agent
	err := row.Scan(&a.ID, &a.Name, &a.Description, &a.TokenHash,
		&a.VPNPool, &a.Endpoint, &a.WGPublicKey, &a.IsActive, &a.LastSeenAt, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// UpdateAgentPublicKey stores the agent's WireGuard public key.
// Called when the agent connects and sends its public key in the ready message.
func (d *DB) UpdateAgentPublicKey(ctx context.Context, agentID, pubKey string) error {
	_, err := d.sql.ExecContext(ctx,
		`UPDATE agents SET wg_public_key = ? WHERE id = ?`, pubKey, agentID)
	return err
}
