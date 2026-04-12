-- Migration 001: Initial schema (PostgreSQL)

CREATE TABLE groups (
    id               TEXT        NOT NULL PRIMARY KEY,
    name             TEXT        NOT NULL UNIQUE,
    description      TEXT        NOT NULL DEFAULT '',
    session_duration INTEGER     NOT NULL DEFAULT 86400,
    max_extensions   INTEGER,
    is_public        BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE subnets (
    id          TEXT        NOT NULL PRIMARY KEY,
    name        TEXT        NOT NULL UNIQUE,
    cidr        TEXT        NOT NULL UNIQUE,
    description TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE group_subnets (
    id         TEXT        NOT NULL PRIMARY KEY,
    group_id   TEXT        NOT NULL REFERENCES groups(id)  ON DELETE CASCADE,
    route_id   TEXT        NOT NULL REFERENCES subnets(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(group_id, route_id)
);

CREATE INDEX idx_group_subnets_group_id ON group_subnets(group_id);
CREATE INDEX idx_group_subnets_route_id ON group_subnets(route_id);

CREATE TABLE users (
    id            TEXT        NOT NULL PRIMARY KEY,
    oidc_sub      TEXT        NOT NULL UNIQUE,
    email         TEXT        NOT NULL UNIQUE,
    display_name  TEXT        NOT NULL DEFAULT '',
    is_admin      BOOLEAN     NOT NULL DEFAULT FALSE,
    is_active     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);

CREATE INDEX idx_users_oidc_sub ON users(oidc_sub);
CREATE INDEX idx_users_email    ON users(email);

CREATE TABLE user_groups (
    id         TEXT        NOT NULL PRIMARY KEY,
    user_id    TEXT        NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    group_id   TEXT        NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, group_id)
);

CREATE INDEX idx_user_groups_user_id  ON user_groups(user_id);
CREATE INDEX idx_user_groups_group_id ON user_groups(group_id);

CREATE TABLE devices (
    id                TEXT        NOT NULL PRIMARY KEY,
    user_id           TEXT        NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    group_id          TEXT        NOT NULL REFERENCES groups(id) ON DELETE RESTRICT,
    name              TEXT        NOT NULL,
    public_key        TEXT        NOT NULL UNIQUE,
    assigned_ip       TEXT        NOT NULL UNIQUE,
    is_approved       BOOLEAN     NOT NULL DEFAULT FALSE,
    is_active         BOOLEAN     NOT NULL DEFAULT TRUE,
    auto_renew        BOOLEAN     NOT NULL DEFAULT FALSE,
    config_downloaded BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at      TIMESTAMPTZ,
    UNIQUE(user_id, name)
);

CREATE INDEX idx_devices_user_id    ON devices(user_id);
CREATE INDEX idx_devices_group_id   ON devices(group_id);
CREATE INDEX idx_devices_public_key ON devices(public_key);

CREATE TABLE device_subnets (
    id         TEXT        NOT NULL PRIMARY KEY,
    device_id  TEXT        NOT NULL REFERENCES devices(id)  ON DELETE CASCADE,
    route_id   TEXT        NOT NULL REFERENCES subnets(id)  ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(device_id, route_id)
);

CREATE INDEX idx_device_subnets_device_id ON device_subnets(device_id);
CREATE INDEX idx_device_subnets_route_id  ON device_subnets(route_id);

CREATE TABLE sessions (
    id              TEXT        NOT NULL PRIMARY KEY,
    device_id       TEXT        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    authed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    extended_at     TIMESTAMPTZ,
    extension_count INTEGER     NOT NULL DEFAULT 0,
    revoked_at      TIMESTAMPTZ,
    revoked_by      TEXT        REFERENCES users(id) ON DELETE SET NULL,
    ip_address      TEXT        NOT NULL DEFAULT '',
    status          TEXT        NOT NULL DEFAULT 'active'
                                CHECK(status IN ('active', 'expired', 'revoked'))
);

CREATE INDEX idx_sessions_device_id  ON sessions(device_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_status     ON sessions(status);
CREATE UNIQUE INDEX idx_sessions_one_active_per_device ON sessions(device_id) WHERE status = 'active';

CREATE TABLE agents (
    id            TEXT        NOT NULL PRIMARY KEY,
    name          TEXT        NOT NULL UNIQUE,
    description   TEXT        NOT NULL DEFAULT '',
    token         TEXT        NOT NULL UNIQUE,
    vpn_pool      TEXT        NOT NULL DEFAULT '',
    endpoint      TEXT        NOT NULL DEFAULT '',
    wg_public_key TEXT        NOT NULL DEFAULT '',
    is_active     BOOLEAN     NOT NULL DEFAULT TRUE,
    last_seen_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE group_agents (
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, agent_id)
);

CREATE TABLE metric_snapshots (
    id             TEXT        NOT NULL PRIMARY KEY,
    device_id      TEXT        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    bytes_sent     BIGINT      NOT NULL DEFAULT 0,
    bytes_received BIGINT      NOT NULL DEFAULT 0,
    last_handshake TIMESTAMPTZ,
    recorded_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_metric_snapshots_device_id   ON metric_snapshots(device_id);
CREATE INDEX idx_metric_snapshots_recorded_at ON metric_snapshots(recorded_at);

CREATE TABLE audit_log (
    id         TEXT        NOT NULL PRIMARY KEY,
    user_id    TEXT        REFERENCES users(id)   ON DELETE SET NULL,
    device_id  TEXT        REFERENCES devices(id) ON DELETE SET NULL,
    agent_id   TEXT        REFERENCES agents(id)  ON DELETE SET NULL,
    event      TEXT        NOT NULL,
    metadata   TEXT        NOT NULL DEFAULT '{}',
    ip_address TEXT        NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_user_id    ON audit_log(user_id);
CREATE INDEX idx_audit_log_device_id  ON audit_log(device_id);
CREATE INDEX idx_audit_log_event      ON audit_log(event);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);

CREATE TABLE local_admins (
    id            TEXT        NOT NULL PRIMARY KEY,
    username      TEXT        NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE groups_endpoint_override AS SELECT id, ''::TEXT AS endpoint_override FROM groups WHERE FALSE;

-- updated_at triggers
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER groups_updated_at  BEFORE UPDATE ON groups  FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER subnets_updated_at BEFORE UPDATE ON subnets FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER users_updated_at   BEFORE UPDATE ON users   FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER devices_updated_at BEFORE UPDATE ON devices FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER agents_updated_at  BEFORE UPDATE ON agents  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

ALTER TABLE groups ADD COLUMN IF NOT EXISTS endpoint_override TEXT NOT NULL DEFAULT '';
DROP TABLE IF EXISTS groups_endpoint_override;
