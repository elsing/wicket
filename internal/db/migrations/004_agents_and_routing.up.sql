-- Migration 004: Agent pools, group routing mode, and multi-agent group assignment.
-- ALTER TABLE ADD COLUMN statements are handled safely by the migration runner:
-- each column is only added if it doesn't already exist.

ALTER TABLE agents ADD COLUMN vpn_pool TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN endpoint TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN description TEXT NOT NULL DEFAULT '';

ALTER TABLE groups ADD COLUMN routing_mode TEXT NOT NULL DEFAULT 'routed';
ALTER TABLE groups ADD COLUMN endpoint_override TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS group_agents (
    group_id  TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    agent_id  TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, agent_id)
);