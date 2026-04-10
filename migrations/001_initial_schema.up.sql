-- Migration 001: Initial schema
-- All IDs are TEXT (UUIDs). Timestamps stored as DATETIME (ISO8601/RFC3339).
-- Foreign keys enforced. WAL mode for better concurrent read performance.

-- ─────────────────────────────────────────────────────────────────────────────
-- Groups
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE groups (
    id               TEXT     NOT NULL PRIMARY KEY,
    name             TEXT     NOT NULL UNIQUE,
    description      TEXT     NOT NULL DEFAULT '',
    session_duration INTEGER  NOT NULL DEFAULT 86400, -- seconds; default 24 hours
    max_extensions   INTEGER,                          -- NULL = unlimited
    is_public        INTEGER  NOT NULL DEFAULT 0,      -- 1 = any authed user can select
    created_at       DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at       DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Subnets
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE subnets (
    id          TEXT     NOT NULL PRIMARY KEY,
    name        TEXT     NOT NULL UNIQUE,
    cidr        TEXT     NOT NULL UNIQUE,
    description TEXT     NOT NULL DEFAULT '',
    created_at  DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Group ↔ Subnet (many-to-many)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE group_subnets (
    id         TEXT     NOT NULL PRIMARY KEY,
    group_id   TEXT     NOT NULL REFERENCES groups(id)  ON DELETE CASCADE,
    subnet_id  TEXT     NOT NULL REFERENCES subnets(id) ON DELETE CASCADE,
    created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(group_id, subnet_id)
);

CREATE INDEX idx_group_subnets_group_id  ON group_subnets(group_id);
CREATE INDEX idx_group_subnets_subnet_id ON group_subnets(subnet_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- Users
-- Created automatically on first OIDC login.
-- oidc_sub is the stable identifier — email can change.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE users (
    id            TEXT     NOT NULL PRIMARY KEY,
    oidc_sub      TEXT     NOT NULL UNIQUE,
    email         TEXT     NOT NULL UNIQUE,
    display_name  TEXT     NOT NULL DEFAULT '',
    is_admin      INTEGER  NOT NULL DEFAULT 0,
    is_active     INTEGER  NOT NULL DEFAULT 1,
    created_at    DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at    DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_login_at DATETIME
);

CREATE INDEX idx_users_oidc_sub ON users(oidc_sub);
CREATE INDEX idx_users_email    ON users(email);

-- ─────────────────────────────────────────────────────────────────────────────
-- User ↔ Group membership (for restricted groups)
-- Users can always see public groups without being in this table.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE user_groups (
    id         TEXT     NOT NULL PRIMARY KEY,
    user_id    TEXT     NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    group_id   TEXT     NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(user_id, group_id)
);

CREATE INDEX idx_user_groups_user_id  ON user_groups(user_id);
CREATE INDEX idx_user_groups_group_id ON user_groups(group_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- Devices
-- WireGuard peers belonging to a user.
-- Private keys are NEVER stored — discarded after one-time config download.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE devices (
    id                TEXT     NOT NULL PRIMARY KEY,
    user_id           TEXT     NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    group_id          TEXT     NOT NULL REFERENCES groups(id) ON DELETE RESTRICT,
    name              TEXT     NOT NULL,
    public_key        TEXT     NOT NULL UNIQUE,
    assigned_ip       TEXT     NOT NULL UNIQUE,
    is_approved       INTEGER  NOT NULL DEFAULT 0, -- admin must approve before use
    is_active         INTEGER  NOT NULL DEFAULT 1, -- admin-level disable toggle
    auto_renew        INTEGER  NOT NULL DEFAULT 0, -- activate session on portal login
    config_downloaded INTEGER  NOT NULL DEFAULT 0, -- one-time download guard
    created_at        DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at        DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_seen_at      DATETIME,
    UNIQUE(user_id, name)
);

CREATE INDEX idx_devices_user_id    ON devices(user_id);
CREATE INDEX idx_devices_group_id   ON devices(group_id);
CREATE INDEX idx_devices_public_key ON devices(public_key);

-- ─────────────────────────────────────────────────────────────────────────────
-- Device ↔ Subnet overrides (admin-only)
-- When present, these REPLACE the group's subnets for this device's AllowedIPs.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE device_subnets (
    id         TEXT     NOT NULL PRIMARY KEY,
    device_id  TEXT     NOT NULL REFERENCES devices(id)  ON DELETE CASCADE,
    subnet_id  TEXT     NOT NULL REFERENCES subnets(id)  ON DELETE CASCADE,
    created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(device_id, subnet_id)
);

CREATE INDEX idx_device_subnets_device_id ON device_subnets(device_id);
CREATE INDEX idx_device_subnets_subnet_id ON device_subnets(subnet_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- Sessions
-- A peer is present in WireGuard only when a valid (non-expired, non-revoked)
-- session exists for its device. The reconciler enforces this.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE sessions (
    id              TEXT     NOT NULL PRIMARY KEY,
    device_id       TEXT     NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    authed_at       DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at      DATETIME NOT NULL,
    extended_at     DATETIME,           -- last extension timestamp; NULL if never extended
    extension_count INTEGER  NOT NULL DEFAULT 0,
    revoked_at      DATETIME,           -- set on revocation; NULL if not revoked
    revoked_by      TEXT     REFERENCES users(id) ON DELETE SET NULL,
    ip_address      TEXT     NOT NULL DEFAULT '',
    status          TEXT     NOT NULL DEFAULT 'active'
                             CHECK(status IN ('active', 'expired', 'revoked'))
);

CREATE INDEX idx_sessions_device_id  ON sessions(device_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_status     ON sessions(status);

-- ─────────────────────────────────────────────────────────────────────────────
-- Agents
-- Remote WireGuard agents. Each manages its own WireGuard interface and
-- receives peer updates from the core over an authenticated WebSocket.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE agents (
    id           TEXT     NOT NULL PRIMARY KEY,
    name         TEXT     NOT NULL UNIQUE,
    description  TEXT     NOT NULL DEFAULT '',
    token        TEXT     NOT NULL UNIQUE, -- bcrypt hashed token
    is_active    INTEGER  NOT NULL DEFAULT 1,
    last_seen_at DATETIME,
    created_at   DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at   DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Metric snapshots
-- Point-in-time WireGuard stats per device, collected by the reconciler.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE metric_snapshots (
    id             TEXT     NOT NULL PRIMARY KEY,
    device_id      TEXT     NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    bytes_sent     INTEGER  NOT NULL DEFAULT 0,
    bytes_received INTEGER  NOT NULL DEFAULT 0,
    last_handshake DATETIME,
    recorded_at    DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_metric_snapshots_device_id  ON metric_snapshots(device_id);
CREATE INDEX idx_metric_snapshots_recorded_at ON metric_snapshots(recorded_at);

-- ─────────────────────────────────────────────────────────────────────────────
-- Audit log
-- Append-only. NEVER update or delete rows.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE audit_log (
    id         TEXT     NOT NULL PRIMARY KEY,
    user_id    TEXT     REFERENCES users(id)   ON DELETE SET NULL,
    device_id  TEXT     REFERENCES devices(id) ON DELETE SET NULL,
    agent_id   TEXT     REFERENCES agents(id)  ON DELETE SET NULL,
    event      TEXT     NOT NULL, -- e.g. "session.created", "peer.removed"
    metadata   TEXT     NOT NULL DEFAULT '{}', -- JSON
    ip_address TEXT     NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_audit_log_user_id    ON audit_log(user_id);
CREATE INDEX idx_audit_log_device_id  ON audit_log(device_id);
CREATE INDEX idx_audit_log_event      ON audit_log(event);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);

-- ─────────────────────────────────────────────────────────────────────────────
-- updated_at triggers
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TRIGGER groups_updated_at  AFTER UPDATE ON groups
    BEGIN UPDATE groups  SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;
CREATE TRIGGER subnets_updated_at AFTER UPDATE ON subnets
    BEGIN UPDATE subnets SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;
CREATE TRIGGER users_updated_at   AFTER UPDATE ON users
    BEGIN UPDATE users   SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;
CREATE TRIGGER devices_updated_at AFTER UPDATE ON devices
    BEGIN UPDATE devices SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;
CREATE TRIGGER agents_updated_at  AFTER UPDATE ON agents
    BEGIN UPDATE agents  SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;
