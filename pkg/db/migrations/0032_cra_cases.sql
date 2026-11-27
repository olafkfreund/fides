CREATE TABLE cra_cases (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('vulnerability', 'severe-incident')),
    title TEXT NOT NULL,
    cve TEXT NOT NULL DEFAULT '',
    awareness_at TIMESTAMPTZ NOT NULL,
    measure_available_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    created_by JSONB NOT NULL,
    UNIQUE (org_id, id),
    CHECK (kind = 'vulnerability' OR (cve = '' AND measure_available_at IS NULL))
);
CREATE INDEX cra_cases_tenant_created ON cra_cases (org_id, created_at DESC, id DESC);

CREATE TABLE cra_case_links (
    org_id UUID NOT NULL,
    case_id UUID NOT NULL,
    trail_id UUID NOT NULL REFERENCES trails(id) ON DELETE CASCADE,
    artifact_sha256 VARCHAR(64) REFERENCES artifacts(sha256) ON DELETE CASCADE,
    FOREIGN KEY (org_id, case_id) REFERENCES cra_cases(org_id, id) ON DELETE CASCADE,
    UNIQUE NULLS NOT DISTINCT (case_id, trail_id, artifact_sha256)
);

CREATE TABLE cra_case_deadlines (
    org_id UUID NOT NULL,
    case_id UUID NOT NULL,
    stage TEXT NOT NULL CHECK (stage IN ('early-warning', 'notification', 'final', 'intermediate')),
    revision BIGINT NOT NULL CHECK (revision > 0),
    due_at TIMESTAMPTZ,
    superseded_at TIMESTAMPTZ,
    satisfied_at TIMESTAMPTZ,
    PRIMARY KEY (case_id, stage, revision),
    FOREIGN KEY (org_id, case_id) REFERENCES cra_cases(org_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX cra_case_current_deadline ON cra_case_deadlines (case_id, stage)
    WHERE superseded_at IS NULL;

CREATE TABLE cra_case_intermediate_requests (
    org_id UUID NOT NULL,
    case_id UUID NOT NULL,
    stage TEXT NOT NULL DEFAULT 'intermediate' CHECK (stage = 'intermediate'),
    revision BIGINT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL,
    reference TEXT NOT NULL,
    recorded_by JSONB NOT NULL,
    PRIMARY KEY (case_id, revision),
    UNIQUE (case_id, reference),
    FOREIGN KEY (org_id, case_id) REFERENCES cra_cases(org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (case_id, stage, revision) REFERENCES cra_case_deadlines(case_id, stage, revision)
);

CREATE TABLE cra_case_exports (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL,
    case_id UUID NOT NULL,
    stage TEXT NOT NULL,
    revision BIGINT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    payload TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL CHECK (payload_sha256 ~ '^[a-f0-9]{64}$'),
    created_at TIMESTAMPTZ NOT NULL,
    created_by JSONB NOT NULL,
    UNIQUE (org_id, case_id, id),
    FOREIGN KEY (org_id, case_id) REFERENCES cra_cases(org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (case_id, stage, revision) REFERENCES cra_case_deadlines(case_id, stage, revision)
);
CREATE INDEX cra_case_exports_case ON cra_case_exports (case_id, created_at, id);

CREATE TABLE cra_case_submissions (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL,
    case_id UUID NOT NULL,
    export_id UUID NOT NULL UNIQUE,
    payload_sha256 TEXT NOT NULL CHECK (payload_sha256 ~ '^[a-f0-9]{64}$'),
    submitted_at TIMESTAMPTZ NOT NULL,
    external_reference TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    recorded_by JSONB NOT NULL,
    UNIQUE (org_id, case_id, id),
    FOREIGN KEY (org_id, case_id, export_id) REFERENCES cra_case_exports(org_id, case_id, id) ON DELETE CASCADE
);

CREATE TABLE cra_case_previously_supplied (
    org_id UUID NOT NULL,
    case_id UUID NOT NULL,
    stage TEXT NOT NULL CHECK (stage IN ('notification', 'final')),
    submission_id UUID NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    recorded_by JSONB NOT NULL,
    PRIMARY KEY (case_id, stage),
    FOREIGN KEY (org_id, case_id, submission_id) REFERENCES cra_case_submissions(org_id, case_id, id) ON DELETE CASCADE
);

CREATE TABLE cra_case_corrections (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL,
    case_id UUID NOT NULL,
    previous JSONB NOT NULL,
    corrected JSONB NOT NULL,
    reason TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    recorded_by JSONB NOT NULL,
    FOREIGN KEY (org_id, case_id) REFERENCES cra_cases(org_id, id) ON DELETE CASCADE
);

DO $$
DECLARE
    tenant_table TEXT;
BEGIN
    FOREACH tenant_table IN ARRAY ARRAY[
        'cra_cases', 'cra_case_links', 'cra_case_deadlines', 'cra_case_intermediate_requests',
        'cra_case_exports', 'cra_case_submissions', 'cra_case_previously_supplied', 'cra_case_corrections'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tenant_table);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tenant_table);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I
            USING (org_id = NULLIF(current_setting(''app.current_org'', true), '''')::uuid)
            WITH CHECK (org_id = NULLIF(current_setting(''app.current_org'', true), '''')::uuid)', tenant_table);
        IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'fides_app') THEN
            EXECUTE format('GRANT SELECT, INSERT ON %I TO fides_app', tenant_table);
        END IF;
    END LOOP;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'fides_app') THEN
        GRANT UPDATE ON cra_cases, cra_case_deadlines TO fides_app;
    END IF;
END $$;

-- Case ownership alone does not establish ownership of a referenced trail or artifact.
CREATE POLICY tenant_evidence_link ON cra_case_links AS RESTRICTIVE FOR INSERT
    WITH CHECK (
        EXISTS (SELECT 1 FROM trails t JOIN flows f ON f.id = t.flow_id
            WHERE t.id = cra_case_links.trail_id AND f.org_id = cra_case_links.org_id)
        AND (artifact_sha256 IS NULL OR EXISTS (
            SELECT 1 FROM artifacts a
            WHERE a.sha256 = cra_case_links.artifact_sha256 AND a.org_id = cra_case_links.org_id
              AND a.trail_id = cra_case_links.trail_id))
    );
