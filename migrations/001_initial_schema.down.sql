-- Migration 001 rollback: drops all tables and triggers.
DROP TRIGGER IF EXISTS agents_updated_at;
DROP TRIGGER IF EXISTS devices_updated_at;
DROP TRIGGER IF EXISTS users_updated_at;
DROP TRIGGER IF EXISTS subnets_updated_at;
DROP TRIGGER IF EXISTS groups_updated_at;

DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS metric_snapshots;
DROP TABLE IF EXISTS agents;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS device_subnets;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS user_groups;
DROP TABLE IF EXISTS group_subnets;
DROP TABLE IF EXISTS subnets;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS groups;
