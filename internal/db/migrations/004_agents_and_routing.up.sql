-- Migration 004: Agent pools, group routing mode, and multi-agent group assignment.

-- Add vpn_pool and endpoint to agents table
ALTER TABLE agents ADD COLUMN vpn_pool TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN endpoint TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN description TEXT NOT NULL DEFAULT '';

-- Add routing_mode and endpoint_override to groups
-- routing_mode: 'routed' (default, device IPs visible on LAN) or 'masqueraded' (NAT at agent)
ALTER TABLE groups ADD COLUMN routing_mode TEXT NOT NULL DEFAULT 'routed';
ALTER TABLE groups ADD COLUMN endpoint_override TEXT NOT NULL DEFAULT '';

-- Group-to-agent assignments (many-to-many for masqueraded groups, one-to-one for routed)
CREATE TABLE IF NOT EXISTS group_agents (
    group_id  TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    agent_id  TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, agent_id)
);
