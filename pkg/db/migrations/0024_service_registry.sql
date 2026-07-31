-- Service ownership registry (secure-SDLC "service ownership" + risk-tier). Each
-- service records who owns / is on-call / is audit-responsible, and a criticality
-- tier (1..3) that scales which controls apply (controls carry a `level`; a
-- service needs controls with level <= its tier).
CREATE TABLE IF NOT EXISTS service_owners (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    service VARCHAR(200) NOT NULL,
    owner VARCHAR(255),
    on_call VARCHAR(255),
    audit_contact VARCHAR(255),
    tier INT NOT NULL DEFAULT 1,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, service)
);
