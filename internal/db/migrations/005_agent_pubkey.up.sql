-- Migration 005: Store each agent's WireGuard public key.
-- When a device config is generated, the correct server public key
-- for the assigned agent is embedded rather than the global server key.
ALTER TABLE agents ADD COLUMN wg_public_key TEXT NOT NULL DEFAULT '';
