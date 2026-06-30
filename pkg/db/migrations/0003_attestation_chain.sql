-- Tamper-evidence hash chain columns for databases created before they existed.
ALTER TABLE attestations ADD COLUMN IF NOT EXISTS content_hash VARCHAR(64);
ALTER TABLE attestations ADD COLUMN IF NOT EXISTS prev_hash VARCHAR(64);
