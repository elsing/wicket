-- Migration 003: Enforce one active session per device.
-- First clean up any duplicate active sessions (keep most recent per device).
UPDATE sessions SET status = 'revoked', revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), revoked_by = 'system:migration'
WHERE status = 'active'
  AND id NOT IN (
      SELECT id FROM (
          SELECT id, device_id, MAX(authed_at) as latest
          FROM sessions
          WHERE status = 'active'
          GROUP BY device_id
      )
  );

-- Now safe to create the unique constraint.
CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_one_active_per_device
    ON sessions (device_id)
    WHERE status = 'active';
