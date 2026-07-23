-- Persistent interactive sessions (issue #299). Backs auth.NewDBSessionStore so
-- portal sessions survive restarts and are shared across replicas, instead of
-- living in a single process's memory. Enabled by FIDES_DB_SESSIONS=true.
--
-- Only the sha256 hash of the session token is stored, never the raw token, so a
-- database leak does not expose usable sessions. No FK on org_id/user_id: rows
-- are ephemeral (expiry-evicted) and the lookup runs pre-authentication, so it
-- must not depend on tenant scoping.
CREATE TABLE IF NOT EXISTS sessions (
    token_hash VARCHAR(64) PRIMARY KEY,
    org_id UUID NOT NULL,
    user_id UUID,
    email VARCHAR(255) NOT NULL DEFAULT '',
    role VARCHAR(50) NOT NULL DEFAULT '',
    kind VARCHAR(20) NOT NULL DEFAULT 'session',
    expiry TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expiry);
