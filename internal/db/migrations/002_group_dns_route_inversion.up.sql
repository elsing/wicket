-- Migration 002: Per-group DNS and route inversion support.

ALTER TABLE groups ADD COLUMN IF NOT EXISTS dns TEXT NOT NULL DEFAULT '';

ALTER TABLE subnets ADD COLUMN IF NOT EXISTS is_excluded BOOLEAN NOT NULL DEFAULT FALSE;
