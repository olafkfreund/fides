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
