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

func (d *DB) AddSubnetToGroup(ctx context.Context, groupID, subnetID string) error {
	_, err := d.sql.ExecContext(ctx,
		`INSERT OR IGNORE INTO group_subnets (id, group_id, subnet_id, created_at) VALUES (?, ?, ?, ?)`,
		newID(), groupID, subnetID, time.Now().UTC())
	return err
}

func (d *DB) RemoveSubnetFromGroup(ctx context.Context, groupID, subnetID string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM group_subnets WHERE group_id = ? AND subnet_id = ?`, groupID, subnetID)
	return err
}

func (d *DB) AddSubnetToDevice(ctx context.Context, deviceID, subnetID string) error {
	_, err := d.sql.ExecContext(ctx,
		`INSERT OR IGNORE INTO device_subnets (id, device_id, subnet_id, created_at) VALUES (?, ?, ?, ?)`,
		newID(), deviceID, subnetID, time.Now().UTC())
	return err
}

func (d *DB) RemoveSubnetFromDevice(ctx context.Context, deviceID, subnetID string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM device_subnets WHERE device_id = ? AND subnet_id = ?`, deviceID, subnetID)
	return err
}

func (d *DB) DeleteSubnet(ctx context.Context, id string) error {
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

// ─────────────────────────────────────────────────────────────────────────────
// Local admin accounts (fallback when OIDC is unavailable)
// ─────────────────────────────────────────────────────────────────────────────

// GetLocalAdminByUsername returns a local admin account by username.
func (d *DB) GetLocalAdminByUsername(ctx context.Context, username string) (*LocalAdmin, error) {
	row := d.sql.QueryRowContext(ctx,
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
	if err := d.sql.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM devices WHERE group_id = ?`, id).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("cannot delete group: %d device(s) still assigned to it", count)
	}
	_, err := d.sql.ExecContext(ctx, `DELETE FROM groups WHERE id = ?`, id)
	return err
}

// ListGroupSubnets returns a map of groupID -> []subnetID for all groups.
func (d *DB) ListGroupSubnets(ctx context.Context) (map[string][]string, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT group_id, subnet_id FROM group_subnets`)
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
	row := d.sql.QueryRowContext(ctx,
		`SELECT id, username, password_hash, created_at FROM local_admins WHERE id = ?`, id)
	var a LocalAdmin
	err := row.Scan(&a.ID, &a.Username, &a.PasswordHash, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}
