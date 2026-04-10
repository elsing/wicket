-- Migration 002: Local admin accounts for emergency fallback access
CREATE TABLE local_admins (
    id            TEXT     NOT NULL PRIMARY KEY,
    username      TEXT     NOT NULL UNIQUE,
    password_hash TEXT     NOT NULL,
    created_at    DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
