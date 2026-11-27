-- Existing hashes keep their original format, including rows recorded before chaining.
ALTER TABLE attestations
    ADD COLUMN IF NOT EXISTS hash_version INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS evidence_inputs JSONB;
