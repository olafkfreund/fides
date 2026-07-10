# Fides: Getting Started Guide & Pipeline Scenarios

This document guides you through setting up **Fides** locally, using the CLI, and integrating it into production CI/CD workflows for both **GitHub Actions** and **GitLab CI**.

---

## 1. Local Setup (Self-Hosting)

To run the complete Fides server stack locally, ensure you have Docker installed. The stack includes:
* **Fides Core Server** (API port: `:8080`)
* **PostgreSQL Database** (Port: `:5432` for metadata)
* **MinIO Object Store** (S3 compatible port: `:9000` / Console: `:9001` for the Evidence Vault)
* **Ollama** (Port: `:11434` for local LLM evidence verification)

### Step 1: Start the services
From your workspace directory, run:
```bash
docker compose up -d
```

### Step 2: Build the CLI
Statically compile the Fides CLI utility for your current operating system (the CLI is designed to run natively on macOS, Linux, and Windows):
```bash
go build -o fides cmd/cli/main.go
```
Verify the installation:
```bash
./fides --help
```

---

## 2. Bootstrapping Your First Flow (CLI Walkthrough)

To configure compliance tracing for a service, define its Flow (pipeline mapping) and Attestation Types (compliance templates).

### Step 1: Create an Organization and a Flow
Define the organization tenant and create a flow for a backend API service:
```bash
# 1. Create Organization
curl -X POST http://localhost:8080/api/v1/orgs \
  -H "Content-Type: application/json" \
  -d '{"name": "payments-team", "description": "Payments Engineering Division"}'

# Note the Org UUID returned (e.g. 5d57b8c7-4328-4e1b-93df-4161b9a918a3)
export ORG_ID="5d57b8c7-4328-4e1b-93df-4161b9a918a3"

# 2. Create the Flow representing the service pipeline
curl -X POST http://localhost:8080/api/v1/flows \
  -H "Content-Type: application/json" \
  -d "{\"org_id\": \"$ORG_ID\", \"name\": \"auth-service\", \"description\": \"Authentication Service Pipeline\"}"

# Note the Flow UUID returned (e.g. f83b3e8c-8dc7-4a0b-ae95-716d1ba1f122)
export FLOW_ID="f83b3e8c-8dc7-4a0b-ae95-716d1ba1f122"
```

### Step 2: Create Attestation Type Templates
Define the compliance parameters for vulnerability scans. For example, a custom JQ rule that forces Snyk scans to report 0 critical issues:
```bash
curl -X POST http://localhost:8080/api/v1/attestation-types \
  -H "Content-Type: application/json" \
  -d "{\"org_id\": \"$ORG_ID\", \"name\": \"snyk-scan\", \"description\": \"Snyk Vulnerability Scan Rule\", \"jq_rules\": [\".vulnerabilities.critical == 0\"]}"
```

---

## 3. Real-World Scenario: GitHub Actions Integration

In a GitHub workflow, the Fides CLI initiates a trail on checkout, uploads build logs and SBOMs, verifies policy criteria, and snapshots the target deployment environment.

Save this config to `.github/workflows/fides-audit.yml`:

```yaml
name: Secure Build & Deploy Pipeline (GitHub)

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
  audit-pipeline:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      # 1. Download and Install Fides CLI
      - name: Install Fides CLI
        run: |
          curl -sSfL https://fides.internal.company.com/cli/install.sh | sh
          echo "/usr/local/bin" >> $GITHUB_PATH

      # 2. Declare the Build Run (Initialize Trail)
      - name: Start Fides Trail
        run: |
          fides trail start \
            --flow $FLOW_ID \
            --trail $TRAIL_ID \
            --repository "${{ github.repository }}" \
            --commit "${{ github.sha }}" \
            --branch "${{ github.ref_name }}" \
            --message "${{ github.event.head_commit.message }}"

      # 3. Build Artifact & Extract Digest
      - name: Build Container Image
        run: |
          docker build -t auth-service:${{ github.sha }} .
          # Grab the unique cryptographic fingerprint
          DIGEST=$(docker inspect --format='{{index .Id}}' auth-service:${{ github.sha }})
          echo "IMAGE_DIGEST=$DIGEST" >> $GITHUB_ENV

      # 4. Report Artifact Digest to Fides (Supply Chain Provenance)
      - name: Report Artifact
        run: |
          fides artifact report \
            --org $ORG_ID \
            --trail $TRAIL_ID \
            --sha256 $IMAGE_DIGEST \
            --name "auth-service" \
            --type "docker"

      # 5. Run Snyk Security Scan & Attest Evidence
      - name: Run Snyk Security Scan
        run: |
          snyk container test auth-service:${{ github.sha }} --json > snyk-report.json || true
          
          # Distill summary for rule evaluation
          CRITICAL_COUNT=$(jq '[.vulnerabilities[] | select(.severity == "critical")] | length' snyk-report.json)
          echo "{\"vulnerabilities\": {\"critical\": $CRITICAL_COUNT}}" > snyk-summary.json
          
          # Attest to Fides, encrypting the payload and uploading the raw report into the Evidence Vault
          fides attest \
            --trail $TRAIL_ID \
            --artifact-sha $IMAGE_DIGEST \
            --name "snyk-vulnerabilities" \
            --type "snyk-scan" \
            --payload snyk-summary.json \
            --attachments snyk-report.json \
            --encrypt

      # 6. Run Secret Scanning (Gitleaks) & Attest
      - name: Run Secret Leak Scan
        run: |
          gitleaks detect --source=. --format=json --report-path=leak-report.json || true
          
          # Count exposed credentials
          LEAK_COUNT=$(jq '. | length' leak-report.json)
          echo "{\"leaks\": $LEAK_COUNT}" > leaks-summary.json
          
          fides attest \
            --trail $TRAIL_ID \
            --artifact-sha $IMAGE_DIGEST \
            --name "credential-leak-check" \
            --type "secret-scan" \
            --payload leaks-summary.json \
            --attachments leak-report.json \
            --encrypt

      # 7. Evaluate Policy Gate before Deployment
      - name: Compliance Policy Gate Check
        run: |
          # Fides will exit non-zero and fail the workflow if the artifact is non-compliant
          fides assert \
            --sha256 $IMAGE_DIGEST \
            --policy "production-release-rules"

      # 8. Deploy to Production (Kubernetes)
      - name: Deploy to K8s
        run: |
          kubectl set image deployment/auth-service auth-container=auth-service:${{ github.sha }}

      # 9. Snapshot Runtime to record state change
      - name: Update Runtime Snapshot
        run: |
          fides snapshot k8s "production-k8s-cluster" --namespace "production"
```

---

## 4. Real-World Scenario: GitLab CI Integration

For GitLab environments, configure your pipeline to run inside Docker. Define variables to handle paths and authenticate your jobs securely.

Save this config to `.gitlab-ci.yml`:

```yaml
stages:
  - init
  - build
  - scan
  - deploy

variables:
  FIDES_SERVER_URL: "https://fides.internal.company.com"
  FIDES_API_TOKEN: $SECURE_FIDES_TOKEN # Stored in GitLab Protected Variables
  FIDES_ENCRYPTION_KEY: $SECURE_FIDES_ENCRYPTION_KEY # Stored in GitLab Protected Variables
  ORG_ID: "5d57b8c7-4328-4e1b-93df-4161b9a918a3"
  FLOW_ID: "f83b3e8c-8dc7-4a0b-ae95-716d1ba1f122"
  TRAIL_ID: $CI_COMMIT_SHA

image: alpine:3.18

before_script:
  # Install CLI
  - apk add --no-cache curl jq docker-cli
  - curl -sSfL https://fides.internal.company.com/cli/install.sh | sh

init-trail:
  stage: init
  script:
    - fides trail start 
        --flow $FLOW_ID 
        --trail $TRAIL_ID 
        --repository $CI_PROJECT_URL 
        --commit $CI_COMMIT_SHA 
        --branch $CI_COMMIT_BRANCH 
        --message "$CI_COMMIT_MESSAGE"

build-image:
  stage: build
  services:
    - docker:24.0.5-dind
  script:
    - docker build -t auth-service:$CI_COMMIT_SHA .
    - DIGEST=$(docker inspect --format='{{index .Id}}' auth-service:$CI_COMMIT_SHA)
    # Save digest for down-stream scan jobs
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

run-security-scans:
  stage: scan
  script:
    # 1. Run Trivy vulnerability scan
    - trivy image --format json --output trivy-report.json auth-service:$CI_COMMIT_SHA || true
    - CRITICAL_CVE=$(jq '.Results[].Vulnerabilities[] | select(.Severity=="CRITICAL")' trivy-report.json | jq -s '. | length')
    - echo "{\"vulnerabilities\":{\"critical\":$CRITICAL_CVE}}" > trivy-summary.json
    
    # Post attestation
    - fides attest 
        --trail $TRAIL_ID 
        --artifact-sha $IMAGE_DIGEST 
        --name "trivy-scan" 
        --type "vulnerability-scan" 
        --payload trivy-summary.json 
        --attachments trivy-report.json \
        --encrypt

    # 2. Policy Assertion Check (Fails build if not compliant)
    - fides assert 
        --sha256 $IMAGE_DIGEST 
        --policy "prod-verification"

deploy-prod:
  stage: deploy
  script:
    - aws ecs update-service --cluster prod-cluster --service auth-service --force-new-deployment
    # Record runtime state in Fides
    - fides snapshot ecs "production-ecs-cluster" --container "auth-service"
```

---

## 5. Drift and Shadow Change Checks

To verify your systems are free from unauthorized modifications, write a scheduled verification job (a cron job or daemon) that runs inside production.

```bash
# Capture what is currently running on the server docker host
fides snapshot docker --env "prod-environment-uuid" --container "auth-service"
```

### Result Analysis in Server logs:
- **Case 1: Standard Deployment**
  The container digest running matches the artifact reported in the build pipeline. All JQ scan rules passed. Fides returns:
  `{"compliant": true, "drifts": [], "shadow_changes": []}`
  
- **Case 2: Shadow Change Detected**
  A developer logged directly into the container host and manually ran `docker run -d malicious-image`. The digest reported is unknown to Fides. Fides raises a compliance flag:
  `{"compliant": false, "drifts": [], "shadow_changes": ["service auth-service running unregistered artifact sha256:e3b0c442..."]}`
  
- **Case 3: Configuration Drift Detected**
  The container running is a registered artifact, but its associated build trail contains a failing scan attestation (e.g. a newly discovered critical CVE failed rules post-deploy). Fides reports:
  `{"compliant": false, "drifts": ["service auth-service running drifted artifact (failing control: trivy-scan)"], "shadow_changes": []}`

---

## 6. AI-Assisted Audits

If `AI_PROVIDER` is set in Fides server configurations, Fides streams your scan results and SBOM files to the integrated LLM (e.g. Ollama Llama 3 locally or Gemini API in cloud).

To review automated LLM risk analysis findings:
```bash
# Query the LLM audit findings for a specific attestation
curl -X GET http://localhost:8080/api/v1/compliance?sha256=<artifact-digest>
```
The response will include the detailed Markdown audit review:
> **Fides-AI Audit Finding Summary**:
> * Analyzed SBOM attestation: 124 packages found. 
> * The model identified `GPL-3.0` license present in `readline` package. Policy strictly forbids GPL copyleft packages.
> * Compliance Score: **45/100** (Vulnerable licensing found).

---

## 7. End-to-End Payload Encryption & Security

Fides prioritizes the secure flow of evidence. To prevent eavesdropping or tampering with compliance data in transit, the Fides CLI can symmetrically encrypt attestation payloads using **AES-256-GCM** before sending them to the API server.

### Key Derivation & Configuration
1. **Passphrase**: Configure the environment variable `FIDES_ENCRYPTION_KEY` on both the client (CI/CD environment) and the Fides server.
2. **Key Derivation**: The server and client use a key derivation function to expand or format the secret into a standard 32-byte key.
3. **Usage**:
   - Provide the `--encrypt` flag when running `fides attest`.
   - The CLI will automatically encrypt the payload, flag the request as encrypted, and transmit the ciphertext.
   - The Fides server will decrypt the payload on receipt using the matching key, validate policies, and store the resulting compliance data.

---

## New Capabilities

Recent releases added evidence parsers, a tamper-evident attestation chain,
service accounts with rotatable keys, per-environment allow-lists, environment
policies with tags, search & snapshot diff, audit packages, ECS/Lambda
snapshots, logical environments, DORA metrics, Slack notifications, and a
ServiceNow admin page at `/servicenow`.

See **[features.md](features.md)** for real examples, **[cli-reference.md](cli-reference.md)** for the full command list, and **[segregation-of-duties.md](segregation-of-duties.md)** for supplying the committer / approver / deployer identities end-to-end.
