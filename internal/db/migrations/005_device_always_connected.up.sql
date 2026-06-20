-- Migration 005: Add always_connected flag to devices.
-- Devices with this flag always have an active session regardless of group
-- session_duration, and are never evicted by the reconciler or expiry tracker.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS always_connected BOOLEAN NOT NULL DEFAULT FALSE;
