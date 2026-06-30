-- Additive columns for databases created before these columns existed.
-- CREATE TABLE IF NOT EXISTS (0001) creates missing tables but never adds
-- missing columns to a pre-existing table, so they are applied explicitly here.
-- All statements are idempotent (ADD COLUMN IF NOT EXISTS).

ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);
ALTER TABLE tenant_git_providers ADD COLUMN IF NOT EXISTS inbound_secret_path VARCHAR(255);
