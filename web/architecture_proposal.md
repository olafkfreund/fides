# Fides: Open Source compliance, Provenance & Evidence Tracking System

This document outlines the detailed architecture for **Fides**, a self-hosted, multi-cloud compatible compliance, provenance, and evidence-tracking system. Fides is designed to capture, secure, evaluate, and verify the software supply chain, security scans, and runtime state. It acts as an audit-ready single source of truth to meet strict compliance standards (SOC 2, ISO 27001, and FDA 21 CFR Part 11).

> **Implementation status (2026-07):** This document is the system architecture and design rationale. The platform has since implemented (and in several areas surpassed) this design — a deep **ServiceNow** integration (CMDB/ITOM/ITSM/MCP), built-in evidence parsers, a **tamper-evident attestation hash chain**, **service accounts** with rotatable API keys, **environment policies** with tag conditions, per-environment **allow-lists**, an **event/outbox dispatcher** (webhooks, commit-status, ServiceNow, Slack), a **Kubernetes admission webhook**, **AWS Secrets Manager** (IRSA), **logical environments**, **audit packages**, search/diff, **DORA metrics**, and startup schema migrations. For the canonical surface see **[docs/features.md](docs/features.md)** and **[docs/cli-reference.md](docs/cli-reference.md)**; the live schema is **`schema.sql`** (31 tables).

---

## 1. Product Review: How Kosli Works

Kosli solves a critical problem in modern, fast-paced DevOps: **securing the software supply chain and automating compliance auditing**. Instead of using manual checklists, static spreadsheets, or scrolling through weeks of CI/CD logs to reconstruct what was built, tested, and deployed, Kosli tracks and evaluates every state change in real-time.

### Core Concepts & Building Blocks
Based on the documentation, Kosli organizes its data using the following concepts:

1. **Organization (Tenant)**: The high-level boundary for users, permissions, and resources.
2. **Flow**: A logical pipeline representing a repeatable software process (e.g., a service's CI/CD pipeline, infrastructure-as-code deployment).
3. **Trail**: An execution instance of a Flow. Typically identified by a Git commit SHA, PR number, or CI build number. This makes trails naturally mappable to developer concepts.
4. **Artifact**: A specific build output (Docker image, binary, file, directory) uniquely identified by its cryptographic SHA256 digest (fingerprint) rather than mutable tags (e.g., `latest`).
5. **Attestation**: Evidence recorded against a Trail or Artifact indicating a compliance/quality control was run. Each attestation has:
   - A **Type** (e.g., `junit`, `snyk`, `pull-request`, `sonar`, or `custom`).
   - A **Payload**: JSON data summarising findings (e.g., vulnerability counts, test pass rates).
   - **Attachments**: Compressed raw logs or report files (stored in the **Evidence Vault**).
6. **Attestation Type**: A template that defines how the attestation is validated using JSON Schema and/or `jq` rules (e.g., `.critical == 0` for vulnerability scans).
7. **Environment**: A digital representation of a deployment target (Kubernetes cluster, ECS service, AWS S3 bucket, Lambda, Docker host, server filesystem).
8. **Environment Snapshot**: A point-in-time capture of the artifacts currently running in an Environment. Kosli correlates running image digests with the build Trails/Flows that produced them.
9. **Environment Policy**: Enforceable compliance rules linked to environments (e.g., *"All artifacts running in production must have unit-tests, an SBOM, and a security scan with 0 critical findings"*).
10. **Audit Package**: An on-demand tarball containing the metadata and files for a Trail, Artifact, or Attestation, designed to be handed directly to compliance auditors.

---

## 2. Fides: System Architecture

Fides consists of four main architectural blocks:
1. **Fides CLI (`fides`)**: A lightweight, statically compiled command-line utility built in Go, ensuring cross-platform support (macOS, Windows, Linux) without dependencies. It runs inside CI/CD runners or host daemons.
2. **Fides Core API Server**: The central gateway. Written in Go, it coordinates database operations, communicates with the Object Storage and Secret Vault engines, and evaluates compliance policy rules.
3. **LLM Verification Gateway (Fides-AI)**: A pluggable intelligence layer. It translates natural language compliance requirements, parses large logs/reports (like SBOMs and compiler outputs), flags credential exposures, and assesses risk using both commercial and local models (Ollama, llama.cpp).
4. **Management Web Portal (Fides Dashboard)**: A modern, read-write dashboard (Next.js/React) for compliance officers and engineers to manage policies, view software provenance trails, review drift/shadow changes, and export signed audit packages. The compiled SPA is served as static assets by the Go server; additional admin UI is delivered as **Go-served pages** embedded in the server binary (e.g. the ServiceNow admin page at `/servicenow`) — see `CLAUDE.md`.

```mermaid
flowchart TD
    subgraph CI/CD Pipelines [CI/CD Pipelines (GitHub, GitLab, Jenkins)]
        CLI_Init[fides trail start] --> CLI_Report[fides artifact report]
        CLI_Report --> CLI_Scan[fides attest --type snyk/trivy/gitleaks]
        CLI_Scan --> CLI_Gate[fides assert --policy prod-policy]
    end

    subgraph Runtimes [Runtime Systems]
        Daemon[fides snapshot k8s/docker] -->|Report State| Server[Fides Core API Server]
    end

    CLI_Gate -->|Secure REST/HTTPS API| Server
    
    subgraph Fides Control Plane
        Server -->|Read/Write Metadata| Postgres[(PostgreSQL Database)]
        Server -->|Fetch Cloud Credentials| SecretVault[Secret Engines\nHashiCorp/AWS/GCP/Azure]
        Server -->|Upload raw SBOMs & Logs| CloudStorage[Evidence Vault\nS3/GCS/Azure/Local]
        Server -->|Review Logs & Risk| AIGateway[LLM Verification Gateway\nGemini/OpenAI/Ollama/llama.cpp]
    end

    subgraph Compliance Officers
        Portal[Web Management Portal] -->|Audit Review & Policy Setup| Server
    end
```

---

## 3. Database Schema Design (PostgreSQL)

To track software supply chain provenance, secret exposures, and LLM evaluations, the relational schema incorporates advanced metadata, timestamped trails, and electronic signatures.

> **Note:** The excerpt below shows the foundational tables. The implemented schema (canonical in **`schema.sql`**, applied/auto-migrated on startup via `pkg/db/migrations/*.sql`) now has **31 tables**, adding: `attestation_types`, `environment_policies`, `environment_allowlist`, `logical_environments` (+ members), `service_accounts` (+ `service_account_keys`), `tenant_servicenow_settings`, `tenant_slack_settings`, `tenant_webhooks`, `tenant_git_providers`, `integration_events` (the transactional outbox), `schema_migrations`, plus `content_hash`/`prev_hash` columns on `attestations` (the tamper-evidence chain) and `password_hash` on `users`.

```sql
-- Enable UUID and Cryptographic Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. Organizations
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Flows (Pipeline streams)
CREATE TABLE flows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    tags JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, name)
);

-- 3. Trails (Execution instances of flows)
CREATE TABLE trails (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    flow_id UUID REFERENCES flows(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL, -- Commit SHA, build number, or PR ID
    git_repository VARCHAR(255),
    git_commit VARCHAR(40),
    git_branch VARCHAR(100),
    git_message TEXT,
    tags JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(flow_id, name)
);

-- 4. Artifacts (Build deliverables, keyed by SHA256 fingerprint)
CREATE TABLE artifacts (
    sha256 VARCHAR(64) PRIMARY KEY, -- Primary key fingerprint
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    trail_id UUID REFERENCES trails(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'docker', 'binary', 'tarball', 'file'
    tags JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 5. Custom Attestation Types
CREATE TABLE attestation_types (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    schema JSONB, -- JSON Schema validation
    jq_rules TEXT[], -- JQ compliance rules
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, name)
);

-- 6. Attestations with Cryptographic Signatures (supporting FDA 21 CFR Part 11)
CREATE TABLE attestations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trail_id UUID REFERENCES trails(id) ON DELETE CASCADE,
    artifact_sha256 VARCHAR(64) REFERENCES artifacts(sha256) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL, -- 'unit-tests', 'snyk-scan', 'sbom', 'secret-scan'
    type_name VARCHAR(100) NOT NULL,
    payload JSONB NOT NULL, -- Structured JSON summary data
    is_compliant BOOLEAN NOT NULL DEFAULT TRUE,
    
    -- Cryptographic signing metadata for 21 CFR Part 11 compliance
    signed_by VARCHAR(255), -- IAM user/system identity
    signature TEXT, -- Cryptographic signature (RSA/ECDSA) of payload + attachments
    signature_algorithm VARCHAR(50),
    manifestation_reason TEXT, -- Statement of signature intent
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 7. Evidence Vault Attachments
CREATE TABLE evidence_attachments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attestation_id UUID REFERENCES attestations(id) ON DELETE CASCADE,
    file_name VARCHAR(255) NOT NULL,
    file_size BIGINT NOT NULL,
    file_hash VARCHAR(64) NOT NULL, -- SHA256 of the raw file
    storage_path VARCHAR(512) NOT NULL, -- URI/key inside storage bucket
    content_type VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 8. LLM Evidence Assessments
CREATE TABLE llm_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attestation_id UUID REFERENCES attestations(id) ON DELETE CASCADE,
    model_provider VARCHAR(50) NOT NULL, -- 'gemini', 'openai', 'ollama', 'llamacpp'
    model_name VARCHAR(100) NOT NULL,
    prompt_template_version VARCHAR(20) NOT NULL,
    assessment_raw TEXT NOT NULL, -- Raw text output/reasoning from LLM
    compliance_score INT NOT NULL, -- 0-100 score
    findings JSONB DEFAULT '[]'::jsonb, -- List of parsed issues/threats
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 9. Environments (Runtimes)
CREATE TABLE environments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'docker', 'k8s', 'ecs', 's3', 'server'
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, name)
);

-- 10. Environment Snapshots
CREATE TABLE environment_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id UUID REFERENCES environments(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 11. Snapshot Running Artifacts (for Drift and Shadow Change detection)
CREATE TABLE snapshot_artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id UUID REFERENCES environment_snapshots(id) ON DELETE CASCADE,
    artifact_sha256 VARCHAR(64) REFERENCES artifacts(sha256),
    service_name VARCHAR(255) NOT NULL, -- Name of deploy unit/container/service
    runtime_digest VARCHAR(255) NOT NULL, -- The SHA256 reported directly from host
    started_at TIMESTAMP WITH TIME ZONE,
    stopped_at TIMESTAMP WITH TIME ZONE
);

-- 12. Policies
CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    rules JSONB NOT NULL, -- Rule lists (YAML configuration converted to JSON)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, name)
);

-- 13. System Immutable Logs (Append-only audit trail)
CREATE TABLE system_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    org_id UUID NOT NULL,
    actor VARCHAR(255) NOT NULL,
    action_type VARCHAR(100) NOT NULL,
    target_type VARCHAR(50) NOT NULL,
    target_id UUID NOT NULL,
    old_state JSONB,
    new_state JSONB,
    request_ip VARCHAR(45),
    user_agent VARCHAR(512),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE system_audit_logs REPLICA IDENTITY FULL; -- Ensure audit triggers have full state
```

---

## 4. Multi-Cloud Evidence Vault Storage

A core requirement is that Fides can run in any environment and support pluggable storage providers. By abstracting the read/write mechanism in Go, the server maps attachments to:
* **Local Disk**: Mounted folders (useful for local development or on-premises server networks).
* **AWS S3 / MinIO**: Standard object storage bucket commands.
* **Google Cloud Storage (GCS)**: Authenticates natively via Application Default Credentials (ADC) or Service Account JSON.
* **Azure Blob Storage**: Interacts using Blob client endpoints and Account Keys.

```go
package storage

import (
	"context"
	"io"
)

type StorageBackend interface {
	Upload(ctx context.Context, bucket, key string, r io.Reader, contentType string) (string, error)
	Download(ctx context.Context, bucket, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, bucket, key string) error
}
```

---

## 5. Multi-Cloud Secrets Vault Integration

To eliminate hardcoded credentials from environment configurations, Fides abstracts configuration secrets behind a pluggable interface:

```go
package secrets

import "context"

type SecretsProvider interface {
	GetSecret(ctx context.Context, path string, key string) (string, error)
}
```

Supported secrets providers:
* **HashiCorp Vault**: Accesses KV engine paths using Token or K8s Service Account Token.
* **AWS Secrets Manager**: Queries secret values via AWS STS roles.
* **GCP Secret Manager**: Fetches secret payloads using service accounts.
* **Azure Key Vault**: Queries vaults using Active Directory secrets.
* **Local System Env**: Falls back to reading process environment variables for lightweight Docker setups.

---

## 6. Software Supply Chain & Vulnerability Integrations

Fides acts as the central ingestion portal for external security tools. The CLI runs the tools locally, parses the reports (or uploads the full report as an attachment), and posts the structured summary payload to the REST API.

```
       +--------------------+
       |  CI/CD Runner Host |
       +---------+----------+
                 |
  1. Scan   +----v---------------+
   ---->    | Scanner CLI        | (Trivy, Syft, Gitleaks, Trufflehog, JUnit)
            +----+---------------+
                 |
  2. Parse  +----v---------------+
   ---->    | fides CLI      | (Generates summary.json + signs files)
            +----+---------------+
                 |
  3. Upload | REST API (POST)
            v
  +------------------+
  | Fides Server |
  +------------------+
```

### Supported Ingestions
1. **Supply Chain (SBOM)**:
   - Tooling: **Syft** or **Trivy**.
   - Input format: SPDX JSON / CycloneDX JSON.
   - Attested fields: Unique package count, dependency lists, licencing checks.
2. **Vulnerable Software (CVEs)**:
   - Tooling: **Snyk**, **Trivy**, or **Grype**.
   - Input format: JSON / SARIF.
   - Attested fields: Critical/High/Medium vulnerability count, patch availability metrics.
3. **Secret & Credential Exposure**:
   - Tooling: **Gitleaks** or **Trufflehog**.
   - Input format: JSON.
   - Attested fields: Count of exposed keys, secret types (API keys, certificates), offending file names.

### Built-in evidence parsers

For common formats the CLI parses the report itself (no hand-built JSON):
`fides attest junit|snyk|trivy --file <report>` normalizes the report into a
`{format, compliant, summary{counts}, findings}` payload and attaches the raw
file. JUnit is compliant with no failures/errors; Snyk/Trivy with no
critical/high.

### Platform integrations (event-driven)

Beyond scanner ingestion, Fides ships outbound integrations driven by a
**transactional outbox + dispatcher** (`pkg/events`, gated by
`FIDES_EVENTS_ENABLED`). Compliance events (`compliance.evaluated`,
`snapshot.reported`, `snapshot.noncompliant`) fan out to per-tenant sinks:

- **ServiceNow** — CMDB reconciliation via IRE, ITOM `em_event` alerts on
  shadow/drift, and an ITSM change-control gate (`servicenow-change`
  attestation), plus MCP tools and a Go-served admin page at `/servicenow`.
- **Signed webhooks** — HMAC-signed JSON to tenant-configured URLs (SSRF-guarded).
- **GitHub/GitLab commit-status** — publishes the compliance verdict to the
  commit, gating PR merges.
- **Slack** — posts compliance events to an incoming webhook.
- **Inbound CI/CD webhooks** — signed GitHub/GitLab push events auto-create trails.

A **Kubernetes ValidatingAdmissionWebhook** additionally gates deploys at the
cluster, rejecting unregistered/non-compliant images.

### Tamper-evidence & machine identity

- Every attestation is linked into a per-trail **append-only hash chain**
  (`content_hash` over the canonical content + `prev_hash`), verifiable via
  `fides verify-chain` — any later edit/deletion/reorder is detectable.
- **Service accounts** hold hashed, rotatable API keys (prefix lookup, TTL,
  revocation) for machine-to-machine auth, replacing the single static token.

---

## 7. LLM Verification Gateway (Fides-AI)

A key differentiator is Fides's LLM engine. When an attestation is posted, the server can trigger an automated LLM evaluation. This supports commercial APIs and local LLM runners.

```
                                  +-------------------+
                                  |   Fides API   |
                                  +---------+---------+
                                            |
                                            | Trigger Assessment
                                            v
                                 +--------------------+
                                 |  AI-Gateway Client |
                                 +----+-----+----+----+
                                      |     |    |
           +--------------------------+     |    +-------------------------+
           |                                |                              |
           v (Local)                        v (Local)                      v (Cloud)
   +---------------+                +---------------+               +--------------+
   |  Ollama API   |                |  llama.cpp    |               | Commercial   |
   |  (e.g., Llama)|                |  (GGUF Endpoint)              | (Gemini/OpenAI)
   +---------------+                +---------------+               +--------------+
```

### LLM Use Cases
1. **Vulnerability Evaluation & Risk Context**:
   An LLM reviews high CVE counts against the deployment target's environment metadata and answers: *"Does this container vulnerability expose us, considering this container has no public internet ingress?"*
2. **Log Interpretation**:
   Parsing raw compiler warning logs or large integration test failure stacks, classifying the cause, and asserting if the failure violates code-safety guidelines.
3. **License Audits**:
   Reviewing unfamiliar package licenses found in the SBOM against corporate policy guidelines.
4. **Secret Scan Triage**:
   Confirming if Gitleaks flagged a real, operational credential or a false positive (e.g., mock keys in test suites).

### Provider Architecture API Client Example (Go)
```go
package ai

import (
	"context"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type LLMRequest struct {
	Model  string   `json:"model"`
	Prompt string   `json:"prompt"`
	Stream bool     `json:"stream"`
}

type LLMResponse struct {
	Response string `json:"response"`
}

type OllamaClient struct {
	Endpoint string
	Model    string
}

func (c *OllamaClient) EvaluateAttestation(ctx context.Context, payload string) (string, error) {
	prompt := fmt.Sprintf("Review the following security payload. Analyze the risk and confirm compliance:\n%s", payload)
	
	reqBody, _ := json.Marshal(LLMRequest{
		Model:  c.Model,
		Prompt: prompt,
		Stream: false,
	})

	req, err := http.NewRequestWithContext(ctx, "POST", c.Endpoint+"/api/generate", bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var llmResp LLMResponse
	if err := json.NewDecoder(resp.Body).Decode(&llmResp); err != nil {
		return "", err
	}

	return llmResp.Response, nil
}
```

---

## 8. Drift & Shadow Change Detection

Tracking runtime state is essential to prevent unauthorized modifications (shadow deployments) or accidental updates (drift).

```
   1. Collect Runtime State
   ------------------------
   Host Daemon executes:
   $ fides snapshot docker <env-name>
      |
      | Reports running image digests
      v
   
   2. Audit Verification & Drift Engine (Fides API)
   -----------------------------------------------------
   For each Running Digest:
      |
      +---> Is digest registered as an ARTIFACT in the database?
      |        |
      |        +--[YES]--> Trace to TRAIL -> Evaluate POLICY
      |        |              |
      |        |              +--[PASS]--> Compliant
      |        |              +--[FAIL]--> Flag NON-COMPLIANT (Drift detected)
      |        |
      |        +--[NO]---> Flag SHADOW CHANGE (Bypassed CI/CD pipeline!)
```

* **Drift**: A running container image is known, but it fails to meet the current environment policy (e.g. its Snyk scan has expired, or it lacks a signed approval).
* **Shadow Change**: A container digest is detected in production but is **completely missing** from the Fides database. This indicates that a developer bypassed the CI/CD pipeline and deployed directly using `kubectl` or local Docker commands. This triggers a high-severity alert.

---

## 9. Compliance Framework Support

Fides contains distinct features mapping directly to the controls required by standard framework audits:

### SOC 2 & ISO 27001
- **SDLC Control Verification**: Policies ensure that code cannot reach production without code coverage, pull request approvals, and static analysis scans.
- **Traceability (Provenance)**: The database forms a chain of custody linking the Git commit, the build runner identity, the test/security artifacts, and the eventual container deployment digest.
- **Access Logs**: The `system_audit_logs` table logs all administrator actions, token updates, policy shifts, and query exports.

### FDA 21 CFR Part 11
This regulation mandates electronic records, electronic signatures, and audit trails for life-sciences software systems.
- **Electronic Signatures**: In the `attestations` table, the signature block records the signer's identity, the cryptographic hash of the evidence, and the manifestation reason (e.g., *"I attest that these unit tests passed successfully"*).
- **Time-Stamped Audit Trail**: Records in `system_audit_logs` are write-once and can be combined with write-once PostgreSQL configurations (replica identity full, table locks, or export-to-ledger) to guarantee that history cannot be deleted or modified, even by database administrators.
- **Validation of Systems**: System validation scripts (verification tests) confirm that the policy engine behaves deterministically.

---

## 10. Self-Hosting Docker Setup (Docker Compose)

The compose configuration below includes the relational database, local object storage, the Fides server, and a local **Ollama** service to demonstrate local, self-hosted LLM assessment.

### `docker-compose.yml`
```yaml
version: '3.8'

services:
  # 1. Relational Database
  db:
    image: postgres:15-alpine
    container_name: fides-db
    environment:
      POSTGRES_DB: fides
      POSTGRES_USER: fides_user
      POSTGRES_PASSWORD: fides_password_secure
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U fides_user -d fides"]
      interval: 5s
      timeout: 5s
      retries: 5

  # 2. Local Evidence Storage (MinIO)
  minio:
    image: minio/minio:latest
    container_name: fides-minio
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      MINIO_ROOT_USER: minio_admin
      MINIO_ROOT_PASSWORD: minio_password_secure
    command: server /data --console-address ":9001"
    volumes:
      - minio_data:/data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/minio/health/live"]
      interval: 5s
      timeout: 5s
      retries: 5

  # 3. Bucket Creator
  mc:
    image: minio/mc:latest
    depends_on:
      minio:
        condition: service_healthy
    entrypoint: >
      /bin/sh -c "
      /usr/bin/mc alias set myminio http://minio:9000 minio_admin minio_password_secure;
      /usr/bin/mc mb myminio/fides-evidence;
      exit 0;
      "

  # 4. Local LLM Service (Ollama)
  ollama:
    image: ollama/ollama:latest
    container_name: fides-ollama
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama

  # 5. Fides Server (API / Portal)
  fides-server:
    image: fides/server:latest
    build:
      context: .
      dockerfile: Dockerfile.server
    container_name: fides-server
    ports:
      - "8080:8080"
    depends_on:
      db:
        condition: service_healthy
      minio:
        condition: service_healthy
      ollama:
        condition: service_started
    environment:
      - PORT=8080
      - ENV=production
      
      # Database
      - DB_DRIVER=postgres
      - DB_DSN=host=db port=5432 user=fides_user password=fides_password_secure dbname=fides sslmode=disable
      
      # Storage (MinIO)
      - STORAGE_DRIVER=s3
      - STORAGE_S3_ENDPOINT=http://minio:9000
      - STORAGE_S3_BUCKET=fides-evidence
      - STORAGE_S3_ACCESS_KEY=minio_admin
      - STORAGE_S3_SECRET_KEY=minio_password_secure
      - STORAGE_S3_USE_SSL=false
      - STORAGE_S3_REGION=us-east-1

      # Secrets Configuration
      - SECRETS_PROVIDER=env

      # AI Verification Gate Configuration
      - AI_PROVIDER=ollama
      - AI_OLLAMA_ENDPOINT=http://ollama:11434
      - AI_MODEL=llama3:8b

      # Root Token
      - VERITRAIL_ROOT_TOKEN=vt_root_secure_token_12345
    restart: always

volumes:
  postgres_data:
  minio_data:
  ollama_data:
```

---

## 11. CLI Tool Command Matrix

The statically compiled cross-platform CLI tool handles operations in CI/CD pipeline jobs and runtime environment monitoring.

Authentication is via environment variables (`FIDES_SERVER_URL`, `FIDES_API_TOKEN` — a static token or a service-account key), not a `login` command. Full reference: **[docs/cli-reference.md](docs/cli-reference.md)**.

| Command Group | Command Syntax | Description |
| :--- | :--- | :--- |
| **Trails** | `fides trail start --flow <f> --trail <t>` | Initialize a build trail |
| **Artifacts** | `fides artifact report --sha256 <s> --name <n>` | Record an artifact fingerprint |
| **Attestations** | `fides attest --type <t> --payload <json>` | Generic attestation |
| **Attestations (parsers)** | `fides attest junit\|snyk\|trivy --file <report>` | Parse a real report into a normalized attestation |
| **Verification** | `fides assert --policy <p> --sha256 <s>` | Policy gate for an artifact |
| **Tamper-evidence** | `fides verify-chain --trail <id>` | Verify the attestation hash chain (exit 2 if broken) |
| **Audit** | `fides audit --trail <id> [--output <zip>]` | Download a trail audit package |
| **Runtimes** | `fides snapshot docker\|k8s\|ecs\|lambda --env <id>` | Report a runtime snapshot |
| **Approvals** | `fides allowlist add\|list\|check\|remove --env <id> --sha <s>` | Per-environment artifact approvals (check exits 2) |
| **Policies** | `fides policy add\|list\|check --env <id>` | Environment policies (check exits 2 on non-compliance) |
| **Environments** | `fides env diff --env <id>` · `fides logical-env create\|add-member\|state` | Snapshot diff · logical environments |
| **Search** | `fides search artifacts\|attestations` | Query artifacts/attestations |
| **Metrics** | `fides metrics --days N` | DORA delivery metrics |
| **Service accounts** | `fides service-account create\|list\|issue-key\|revoke-key` | Machine credentials + key rotation |
| **Integrations** | `fides servicenow\|slack\|git-provider\|webhook config ...` | Configure integrations |
| **Users** | `fides user set-password --user <id> --password <pw>` | Set a local password |
