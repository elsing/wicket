-- Migration 007: Ensure group_subnets and device_subnets use route_id column name.
-- The original schema used route_id but some deployments may have subnet_id
-- from before the subnet->route rename. This migration handles both cases.
-- SQLite 3.25.0+ supports RENAME COLUMN.

-- These will be skipped by the migration runner if the column doesn't exist
-- or if the rename would create a duplicate.
ALTER TABLE group_subnets RENAME COLUMN subnet_id TO route_id;
ALTER TABLE device_subnets RENAME COLUMN subnet_id TO route_id;
