-- Migration 003: Fix audit_log foreign key constraints to allow SET NULL on delete.
-- Existing deployments may have been created with NOT NULL or CASCADE constraints
-- on device_id, user_id, and agent_id which prevent logging deletion events.

ALTER TABLE audit_log
    ALTER COLUMN device_id DROP NOT NULL,
    ALTER COLUMN user_id   DROP NOT NULL,
    ALTER COLUMN agent_id  DROP NOT NULL;

ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_device_id_fkey;
ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_user_id_fkey;
ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_agent_id_fkey;

ALTER TABLE audit_log
    ADD CONSTRAINT audit_log_device_id_fkey FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL,
    ADD CONSTRAINT audit_log_user_id_fkey   FOREIGN KEY (user_id)   REFERENCES users(id)   ON DELETE SET NULL,
    ADD CONSTRAINT audit_log_agent_id_fkey  FOREIGN KEY (agent_id)  REFERENCES agents(id)  ON DELETE SET NULL;
