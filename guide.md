# Fides: Comprehensive Installation, Configuration & Integration Guide

This guide provides deep-dive walkthroughs, configuration examples, and production-ready code templates for deploying, configuring, and using Fides in real-world scenarios.

---

## 1. Installation & Self-Hosting Setup

Fides is designed to run in Docker environments. Below is a production-grade `docker-compose.yml` stack incorporating:
* **Fides Core API Server**: The central control plane.
* **PostgreSQL Database**: Relational storage for audit history.
* **MinIO Object Store**: S3-compatible Evidence Vault.
* **Ollama**: Local AI assistant sidecar.

### Production-Grade Docker Compose

Save this to `docker-compose.yml`:

```yaml
version: '3.8'

services:
  fides-db:
    image: postgres:15-alpine
    container_name: fides-db
    environment:
      POSTGRES_DB: fides
      POSTGRES_USER: fides_user
      POSTGRES_PASSWORD: fides_password_secure
    ports:
      - "5433:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U fides_user -d fides"]
      interval: 5s
      timeout: 5s
      retries: 5

  fides-vault:
    image: minio/minio
    container_name: fides-vault
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      MINIO_ROOT_USER: minio_admin
      MINIO_ROOT_PASSWORD: minio_password_secure
    command: server /data --console-address ":9001"
    volumes:
      - miniodata:/data

  fides-ollama:
    image: ollama/ollama:latest
    container_name: fides-ollama
    ports:
      - "11434:11434"
    volumes:
      - ollama:/root/.ollama

  fides-server:
    image: golang:1.22-alpine
    container_name: fides-server
    depends_on:
      fides-db:
        condition: service_healthy
    ports:
      - "8191:8191"
    environment:
      PORT: "8191"
      DB_DSN: "host=fides-db port=5432 user=fides_user password=fides_password_secure dbname=fides sslmode=disable"
      STORAGE_LOCAL_DIR: "./data/evidence"
      FIDES_ENCRYPTION_KEY: "passphrase-secret-passphrase-secret"
      AI_PROVIDER: "ollama"
      AI_OLLAMA_ENDPOINT: "http://fides-ollama:11434"
      AI_MODEL: "gemma:2b"
    volumes:
      - .:/app
    working_dir: /app
    command: go run cmd/server/main.go

volumes:
  pgdata:
  miniodata:
  ollama:
```

---

## 2. CLI Usage & Bootstrapping Scenarios

Once the server is running on `http://localhost:8191`, compile and configure the `fides` CLI:

```bash
# 1. Statically compile cross-platform CLI
go build -o fides cmd/cli/main.go

# 2. Configure CLI environment variables
export FIDES_SERVER_URL="http://localhost:8191"
export FIDES_API_TOKEN="payments-auditor-token"
export FIDES_ENCRYPTION_KEY="passphrase-secret-passphrase-secret"
```

### Command Reference

#### Creating a Compliance Flow
Register a pipeline tracking stream:
```bash
./fides flow create \
  --org "5d57b8c7-4328-4e1b-93df-4161b9a918a3" \
  --name "auth-service" \
  --desc "Authorization API Pipeline" \
  --tags "env=prod,team=payments"
```

#### Starting an Execution Run (Trail)
Register a build execution instance (typically mapping to a Git Commit SHA or Build ID):
```bash
./fides trail start \
  --flow "f83b3e8c-8dc7-4a0b-ae95-716d1ba1f122" \
  --trail "a1b2c3d4e5f67890" \
  --repository "https://github.com/company/auth-service" \
  --commit "a1b2c3d4e5f67890" \
  --branch "main" \
  --message "feat: upgrade encryption libraries"
```

#### Attesting Scans (Payload Encryption)
Securely upload evidence reports. The CLI will derive a key from `FIDES_ENCRYPTION_KEY` and symmetrically encrypt the JSON scan metrics using **AES-256-GCM** before transmission:
```bash
./fides attest \
  --trail "a1b2c3d4e5f67890" \
  --artifact-sha "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
  --name "security-audit" \
  --type "snyk-scan" \
  --payload snyk-summary.json \
  --attachments snyk-full-report.json \
  --encrypt
```

---

## 3. CI/CD Workflows Integration

### Scenario A: GitHub Actions Workflow

Save this configuration to `.github/workflows/fides-provenance.yml`:

```yaml
name: SECURE_SDLC_COMPLIANCE

on:
  push:
    branches: [ main ]

env:
  FIDES_SERVER_URL: "https://fides.internal.company.com"
  FIDES_API_TOKEN: ${{ secrets.FIDES_API_TOKEN }}
  FIDES_ENCRYPTION_KEY: ${{ secrets.FIDES_ENCRYPTION_KEY }}
  ORG_ID: "5d57b8c7-4328-4e1b-93df-4161b9a918a3"
  FLOW_ID: "f83b3e8c-8dc7-4a0b-ae95-716d1ba1f122"
  TRAIL_ID: ${{ github.sha }}

jobs:
  compliance-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      # 1. Download Fides CLI binary
      - name: Setup Fides CLI
        run: |
          curl -sSfL https://fides.internal.company.com/cli/install.sh | sh
          echo "/usr/local/bin" >> $GITHUB_PATH

      # 2. Boot Trail run
      - name: Initialize Audit Trail
        run: |
          fides trail start \
            --flow $FLOW_ID \
            --trail $TRAIL_ID \
            --repository "${{ github.repository }}" \
            --commit "${{ github.sha }}" \
            --branch "${{ github.ref_name }}" \
            --message "${{ github.event.head_commit.message }}"

      # 3. Build container and capture checksum digest
      - name: Build & Tag Container
        run: |
          docker build -t app-service:${{ github.sha }} .
          DIGEST=$(docker inspect --format='{{index .Id}}' app-service:${{ github.sha }})
          echo "IMAGE_DIGEST=$DIGEST" >> $GITHUB_ENV

      # 4. Report Artifact to registry
      - name: Register Artifact Provenance
        run: |
          fides artifact report \
            --org $ORG_ID \
            --trail $TRAIL_ID \
            --sha256 $IMAGE_DIGEST \
            --name "auth-service-image" \
            --type "docker"

      # 5. Run Security scan & upload encrypted evidence logs
      - name: Snyk Security Scan
        run: |
          npm install -g snyk
          snyk container test app-service:${{ github.sha }} --json > snyk-report.json || true
          CRITICAL_CVE=$(jq '[.vulnerabilities[] | select(.severity == "critical")] | length' snyk-report.json)
          echo "{\"vulnerabilities\": {\"critical\": $CRITICAL_CVE}}" > snyk-summary.json
          
          fides attest \
            --trail $TRAIL_ID \
            --artifact-sha $IMAGE_DIGEST \
            --name "snyk-vulnerabilities" \
            --type "snyk-scan" \
            --payload snyk-summary.json \
            --attachments snyk-report.json \
            --encrypt

      # 6. Assert Policy compliance rules
      - name: Enforce Policy Gate
        run: |
          fides assert \
            --sha256 $IMAGE_DIGEST \
            --policy "production-release-rules"

      # 7. Record deploy runtime snapshot state
      - name: Trigger Runtime Snapshot
        run: |
          fides snapshot k8s "production-k8s-cluster" --namespace "production"
```

### Scenario B: GitLab CI/CD Pipeline

Save this configuration to `.gitlab-ci.yml`:

```yaml
stages:
  - init
  - build
  - test
  - assert
  - deploy

variables:
  FIDES_SERVER_URL: "https://fides.internal.company.com"
  FIDES_API_TOKEN: $SECURE_FIDES_TOKEN
  FIDES_ENCRYPTION_KEY: $SECURE_FIDES_ENCRYPTION_KEY
  ORG_ID: "5d57b8c7-4328-4e1b-93df-4161b9a918a3"
  FLOW_ID: "f83b3e8c-8dc7-4a0b-ae95-716d1ba1f122"
  TRAIL_ID: $CI_COMMIT_SHA

before_script:
  - apk add --no-cache curl jq docker-cli
  - curl -sSfL https://fides.internal.company.com/cli/install.sh | sh

initialize-run:
  stage: init
  script:
    - fides trail start 
        --flow $FLOW_ID 
        --trail $TRAIL_ID 
        --repository $CI_PROJECT_URL 
        --commit $CI_COMMIT_SHA 
        --branch $CI_COMMIT_BRANCH 
        --message "$CI_COMMIT_MESSAGE"

compile-artifact:
  stage: build
  services:
    - docker:24.0.5-dind
  script:
    - docker build -t auth-service:$CI_COMMIT_SHA .
    - DIGEST=$(docker inspect --format='{{index .Id}}' auth-service:$CI_COMMIT_SHA)
    - echo "IMAGE_DIGEST=$DIGEST" > digest.env
    - fides artifact report 
        --org $ORG_ID 
        --trail $TRAIL_ID 
        --sha256 $DIGEST 
        --name "auth-service" 
        --type "docker"
  artifacts:
    reports:
      dotenv: digest.env

trivy-scan:
  stage: test
  script:
    - docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --format json --output trivy-report.json auth-service:$CI_COMMIT_SHA || true
    - CRITICAL_CVE=$(jq '.Results[].Vulnerabilities[] | select(.Severity=="CRITICAL")' trivy-report.json | jq -s '. | length')
    - echo "{\"vulnerabilities\":{\"critical\":$CRITICAL_CVE}}" > trivy-summary.json
    - fides attest 
        --trail $TRAIL_ID 
        --artifact-sha $IMAGE_DIGEST 
        --name "trivy-scan" 
        --type "vulnerability-scan" 
        --payload trivy-summary.json 
        --attachments trivy-report.json 
        --encrypt

evaluate-rules:
  stage: assert
  script:
    - fides assert 
        --sha256 $IMAGE_DIGEST 
        --policy "prod-verification"

deploy-service:
  stage: deploy
  script:
    - kubectl set image deployment/auth-service auth-container=auth-service:$CI_COMMIT_SHA
    - fides snapshot k8s "production-k8s" --namespace "prod"
```

---

## 4. Policy Configuration & Flows Editing

Policies are registered in JSON format using rules containing `jq` expressions. 

### Creating a Release Policy

```json
{
  "provenance": {
    "required": true
  },
  "attestations": [
    {
      "name": "unit-test-assertions",
      "type": "junit",
      "rules": [
        ".failures == 0",
        ".errors == 0"
      ]
    },
    {
      "name": "cve-scan-gate",
      "type": "vulnerability-scan",
      "rules": [
        ".vulnerabilities.critical == 0",
        ".vulnerabilities.high <= 3"
      ]
    }
  ]
}
```

Upload policies via the Core API:
```bash
curl -X POST http://localhost:8191/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "5d57b8c7-4328-4e1b-93df-4161b9a918a3",
    "name": "production-release-rules",
    "description": "Standard release rules enforcing Unit Tests and Snyk gates",
    "rules": "{\"provenance\": {\"required\": true}, \"attestations\": [{\"name\": \"unit-tests\", \"type\": \"junit\", \"rules\": [\".failures == 0\"]}]}"
  }'
```

In the **portal** (Policies page) rules are edited in a Monaco code editor with a
**Format** button and an AI **Check & fix** button (`POST /api/v1/ai/lint-policy`)
that reviews the JSON/jq for errors and best practices and rewrites it.

### Controls coverage & one-click enforcement

Adopt a framework's control catalog, then **enforce** its controls so each
environment gates on the right evidence. Enforcing a control creates an enabled
environment policy that requires the control's evidence types — which is what the
**Controls** page coverage bars measure.

```bash
fides control import  --framework SOC2                 # adopt the catalog
fides control enforce --all-controls --all-environments # gate every env on every control
fides control coverage                                  # per-control environment coverage
```

The portal's **Controls** page has a per-control **Enforce** button (choose one
environment or *All environments*); coverage updates immediately. Under the hood
this calls `POST /api/v1/controls/{key}/enforce` (`{"environment_id": "…"}` or
`{"all": true}`).

---

## 5. Storage Drivers & Cloud Secret Vaults

Fides utilizes a pluggable storage driver interface for evidence uploads (evidence vault attachments) and secret vaults to load cloud authentication credentials.

### Storage Drivers Config (`storage_driver` in settings)

#### 1. AWS S3 Storage Config
```json
{
  "storage_driver": "s3",
  "s3_endpoint": "s3.us-east-1.amazonaws.com",
  "s3_bucket": "production-fides-evidence-attachments",
  "s3_region": "us-east-1",
  "s3_access_key_path": "secret/data/aws/s3:access_key",
  "s3_secret_key_path": "secret/data/aws/s3:secret_key"
}
```

#### 2. Google Cloud Storage (GCS) Config
```json
{
  "storage_driver": "gcs",
  "gcs_bucket": "prod-fides-vault",
  "gcs_credentials_path": "secret/data/gcp/credentials:private_json_key"
}
```

### Pluggable Vault Providers Settings
In the **Settings** view under *Cloud Vault*, choose from the following provider backends to pull secure parameters:
* **ENV**: Server reads keys directly from environment variables.
* **HashiCorp Vault**: Server queries Key-Value (KV) engine over REST.
* **AWS Secrets Manager / GCP Secret Manager / Azure Key Vault**: Queries cloud vault paths.

#### HashiCorp Vault Settings Config:
```json
{
  "vault_provider": "vault",
  "vault_address": "https://vault.internal.company.com:8200",
  "vault_token_path": "/run/secrets/vault-app-token",
  "vault_role": "fides-auditor-role"
}
```

---

## 6. SSO, OAuth & Mappings

Ensure only verified developers and auditors can log into the Fides Web Portal.

### SSO Settings Configuration (SAML/OIDC OAuth)

Register OAuth endpoints inside the **Settings** panel:

```json
{
  "provider_name": "github",
  "client_id": "Iv1.e34ab56cd789ef",
  "client_secret_path": "secret/data/oauth/github:client_secret",
  "auth_url": "https://github.com/login/oauth/authorize",
  "token_url": "https://github.com/login/oauth/access_token",
  "userinfo_url": "https://api.github.com/user",
  "redirect_uri": "http://localhost:8191/api/v1/auth/callback",
  "enabled": true
}
```

### SSO Group Mappings
Map authentication scopes to internal roles:
* **Admin**: full rules/flows modifications.
* **Auditor**: read-only audit exports.
* **Writer**: registers artifacts/attestations.

#### SQL Mappings Seed Example:
```sql
INSERT INTO sso_group_mappings (org_id, external_group, role)
VALUES 
('5d57b8c7-4328-4e1b-93df-4161b9a918a3', 'github:security-team', 'Admin'),
('5d57b8c7-4328-4e1b-93df-4161b9a918a3', 'okta:compliance-auditors', 'Auditor');
```

---

## 7. Fides-AI Audits (LLM Verification)

Fides-AI performs automated evaluations of large log outputs and complex software bills of materials (SBOMs) to identify licensing violations or vulnerable packages.

### Selecting and configuring Providers

#### 1. Ollama (Self-hosted)
Runs models locally on your server host without external api calls:
* **Endpoint URL**: `http://localhost:11434`
* **Model Name**: `gemma4` or `llama3:8b`

#### 2. Google Gemini
* **Endpoint URL**: Cloud API
* **Model Name**: `gemini-1.5-pro`
* **API Key Path**: `secret/data/ai/gemini:api_key`

---

## 8. Telemetry & OpenTelemetry

Export metrics detailing DB connection pool statuses, response count averages, and assertions performance.

### Prometheus Configuration

Add this endpoint target to `/etc/prometheus/prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'fides-server'
    scrape_interval: 5s
    static_configs:
      - targets: ['localhost:8191']
    metrics_path: '/metrics'
```

### Sample Metrics Payload (`GET /api/v1/telemetry/metrics`)
```json
{
  "request_count": 1045,
  "average_latency_ms": 14.52,
  "database_connections_active": 4,
  "assertion_success_total": 489,
  "assertion_failed_total": 12
}
```

---

## 9. AI Agent & LLM client Integration (MCP Server)

Expose the entire compliance registry directly to LLMs using the Model Context Protocol (MCP).

### Stdio Configuration for Claude Desktop
Add this tool mapping to your configuration profile (`~/.config/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "fides-mcp": {
      "command": "/usr/local/bin/fides-mcp",
      "env": {
        "FIDES_SERVER_URL": "http://localhost:8191"
      }
    }
  }
}
```

### Querying Fides via AI Assistant (Examples)

AI agents can run queries conversational style inside cursor/claude interface:
* **User Query**: *"List all compliance pipelines for payments-team"*
  * **Agent Action**: Calls `list_flows` tool on `fides-mcp`.
* **User Query**: *"Check if docker image sha256:e3b0c442... is compliant"*
  * **Agent Action**: Calls `check_compliance` tool on `fides-mcp`.
* **User Query**: *"Are there any active security alerts or container drifts?"*
  * **Agent Action**: Calls `list_environments` tool on `fides-mcp` to identify mismatches.

---

## 7. New Capabilities (Feature Reference)

Recent releases added a broad set of capabilities. See the dedicated, example-rich
references:

* **[Feature guide with real examples](docs/features.md)** — evidence parsers, tamper-evidence chain, service accounts, allow-lists, environment policies, search/diff, audit packages, ECS/Lambda snapshots, logical environments, DORA metrics, Slack.
* **[Full CLI reference](docs/cli-reference.md)** — every `fides` command and flag.
* **[ServiceNow integration](docs/servicenow-integration.md)** — CMDB / ITOM / ITSM / MCP, plus the Go-served admin page at `/servicenow`.
* **[AWS Secrets Manager](docs/aws-secrets-manager.md)** — IRSA-based secret resolution.
* **[Environment MCP compliance](docs/environment-mcp-compliance.md)** — live runtime verification via a real MCP server.

### Quick examples

```bash
# Parse a real JUnit/Snyk/Trivy report directly into an attestation
fides attest junit  --trail $TRAIL --file ./reports/junit.xml --artifact-sha $DIGEST
fides attest trivy  --trail $TRAIL --file ./reports/trivy.json

# Gate a deploy on policy + approval + tamper-evidence (each exits non-zero on failure)
fides policy check    --env $ENV --trail $TRAIL
fides allowlist check --env $ENV --sha $DIGEST
fides verify-chain    --trail $TRAIL

# Issue a rotatable CI key and download an auditor package
fides service-account issue-key --account $SA_ID --label github-actions --expires-hours 720
fides audit --trail $TRAIL --output trail-audit.zip
```

---

## 10. Real-life Scenarios

End-to-end, copy-pasteable walkthroughs for the capabilities shipped in recent
releases. Each combines the CLI, the HTTP API, and the portal so you can pick the
surface that fits your workflow.

### 10.1 Adopt a framework and enforce its controls

**Goal:** adopt a compliance framework's control catalog, gate every environment on
the evidence each control needs, then watch coverage light up.

Enforcing a control is not just a label — it **creates an enabled environment
policy that requires the control's evidence types** (e.g. `junit`, `trivy`,
`sbom-cyclonedx`, `secret-scan`, `sast-semgrep-scan`, `deployment`). That is
exactly what the **Controls** page coverage bars measure, so coverage moves the
moment you enforce.

```bash
# 1. Discover the available catalogs, then adopt one (idempotent).
#    SOC2 | ISO27001 | NIST-800-53 | PCI-DSS | DORA | PSD2 | SOX
fides control frameworks
fides control import --framework SOC2

# 2. Enforce. Either blanket-enforce, or target one control/environment.
fides control enforce --all-controls --all-environments      # gate everything
fides control enforce --key SOC2-CC7.1 --env <environment-id> # or one at a time

# 3. Inspect per-control, per-environment coverage.
fides control coverage
```

Under the hood `--all-controls` first lists `GET /api/v1/controls`, then for each
control key `POST`s to `/api/v1/controls/{key}/enforce`. The request body is
`{"all": true}` for every environment, or `{"environment_id": "<uuid>"}` for a
single one:

```bash
curl -X POST http://localhost:8191/api/v1/controls/SOC2-CC7.1/enforce \
  -H "Content-Type: application/json" \
  -d '{"environment_id": "6d1f...c9"}'
```

**In the portal — Controls page:** a summary bar shows overall coverage, controls
are grouped per framework, and clicking a control drills into its per-environment
enforcement status with a one-click **Enforce** button (choose a single
environment or *All environments*). Coverage updates immediately after enforcing.

### 10.2 Author a policy with the Monaco editor + AI review

**Goal:** write and validate a release policy's `jq` rules without leaving the
browser, or generate one from the CLI.

**In the portal — Policies page:** rules are edited in a **Monaco JSON editor**
(resizable, with an **Expand** control for full-screen editing). A **Format**
button pretty-prints the JSON, and an AI **Check & fix** button reviews the JSON
and its embedded `jq` rules for errors and best practices, then rewrites them in
place. Check & fix calls:

```bash
curl -X POST http://localhost:8191/api/v1/ai/lint-policy \
  -H "Content-Type: application/json" \
  -d '{"rules": "{\"attestations\":[{\"type\":\"junit\",\"rules\":[\".failures = 0\"]}]}"}'
# → returns corrected rules (e.g. fixes ".failures = 0" → ".failures == 0")
```

Prefer the CLI? Draft rules with the LLM, then persist them:

```bash
fides policy generate --describe "block release if any critical CVE or failing unit test"
fides policy create   --name production-release-rules --file policy.json
```

### 10.3 Inspect an artifact and its SBOM

**Goal:** open an artifact, review its attestations, and read the parsed software
bill of materials.

**In the portal — Artifacts page:** click an artifact to see its metadata, the
attestations recorded against it, and the parsed **SBOM**. The viewer understands
the common shapes — **CycloneDX `components`**, **SPDX `packages`**, and **Syft
`artifacts`** — and renders each entry as *component / version / license*.

The backing API:

```bash
# All attestations for one artifact (by SHA).
curl "http://localhost:8191/api/v1/search/attestations?sha=$DIGEST"

# The full evidence payload for one attestation, plus signing / tamper metadata
# (signed_by, signature_algorithm, content_hash, manifestation_reason).
curl "http://localhost:8191/api/v1/attestations/<attestation-id>"
```

The Artifacts SBOM panel only has real components to show if the pipeline attests
an actual SBOM document. `fides attest` parses `junit`, `snyk`, `trivy`, and
`sbom` reports as first-class subcommands. `fides attest sbom` auto-detects
CycloneDX vs SPDX JSON, normalizes every component (name, version, purl,
licenses), and persists them linked to the artifact — powering
`fides search components` ("which artifacts contain component X?"). It records
the attestation named `sbom` and typed `sbom-cyclonedx` (so it satisfies the
SBOM control's evidence requirement, regardless of the source format):

```bash
# Produce a real CycloneDX SBOM from the image, then attest it.
syft myorg/auth-service:1.4.2 -o cyclonedx-json > sbom.json

fides attest sbom \
  --artifact-sha $DIGEST \
  --file sbom.json
  # --trail is optional here — it is resolved from the artifact.

# Which artifacts (across every trail) bundle a vulnerable lodash version?
fides search components --purl pkg:npm/lodash@4.17.20
```

Older pipelines that attested SBOMs via the generic form still work unchanged:

```bash
fides attest \
  --trail $TRAIL \
  --artifact-sha $DIGEST \
  --name sbom \
  --type sbom-cyclonedx \
  --payload sbom.json
```

### 10.4 Drive Fides from a local AI assistant via WebMCP

**Goal:** let a browser-integrated agent or a local LLM operate Fides directly from
the portal page, using your existing session.

The portal registers Fides tools on the browser's **WebMCP** surface — the native
W3C `document.modelContext` API when available, falling back to the `@mcp-b/global`
polyfill. Native WebMCP needs Chrome with the origin trial enabled; elsewhere the
polyfill bridges the tools, and it no-ops if the browser supports neither.

Exposed tools:

* **Read-only:** `fides_list_flows`, `fides_list_environments`,
  `fides_list_policies`, `fides_controls_coverage`, `fides_search_artifacts`,
  `fides_search_attestations`, `fides_deployment_frequency`,
  `fides_compliance_summary`.
* **Safe actions:** `fides_enforce_control`, `fides_import_framework`.

Because the tools run in the page, they inherit your logged-in session — no extra
token wiring. For editor-based agents (Claude Code, Cursor, Claude Desktop) use the
out-of-browser **`fides-mcp`** server instead (see Section 9); it ships in the
image at `/usr/local/bin/fides-mcp` and also exposes the docs as MCP resources
(`fides://docs/*`).

### 10.5 Talk to the Fides Assistant

**Goal:** ask compliance questions conversationally, hands-free.

The in-portal assistant popout (the "Fides Copilot" widget, bottom-right) supports
**voice input** via the microphone button and **spoken replies** via a toggle, in
addition to typed chat. It is backed by:

```bash
curl -X POST http://localhost:8191/api/v1/ai/chat \
  -H "Content-Type: application/json" \
  -d '{"messages": [{"role": "user", "content": "Which environments are missing SOC2-CC7.1 evidence?"}]}'
```

When the WebMCP plug toggle is on, the assistant can also invoke the WebMCP tools
from Section 10.4 to answer with live data or perform the safe actions.
