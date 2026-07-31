-- Security training / awareness records (secure-SDLC "training" — audit evidence
-- that people completed required training, e.g. annual OWASP Top 10, onboarding).
CREATE TABLE IF NOT EXISTS training_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    person VARCHAR(255) NOT NULL,
    course VARCHAR(255) NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_training_org ON training_records(org_id);
