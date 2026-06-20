-- Migration 004: Store agent WireGuard private key server-side.
-- Allows agent records to be deleted and recreated without invalidating
-- existing device configs (public key stays stable).
ALTER TABLE agents ADD COLUMN IF NOT EXISTS wg_private_key TEXT NOT NULL DEFAULT '';
