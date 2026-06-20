-- Migration 006: Add source_ip to metric_snapshots.
-- Stores the real public IP the client is connecting from (from WireGuard endpoint),
-- rather than the VPN-assigned IP.
ALTER TABLE metric_snapshots ADD COLUMN IF NOT EXISTS source_ip TEXT NOT NULL DEFAULT '';
