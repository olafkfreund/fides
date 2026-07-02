# Fides: Trust, Provenance & Evidence Tracking System

Fides (named after the Roman goddess of trust and oaths) is a self-hosted, multi-cloud compatible compliance tracking system. It records and evaluates every state change in the software delivery lifecycle (SDLC) in real-time, acting as an audit-ready single source of truth to satisfy strict compliance frameworks such as SOC 2, ISO 27001, and FDA 21 CFR Part 11.

For detailed architecture diagrams, database schemas, and integration designs, see the **[architecture_proposal.md](file:///mnt/data/Source-home/Calitti/evidance-vault/architecture_proposal.md)** document.

---

## Core Features

* **Supply Chain Provenance**: Statically compile and trace artifacts by their cryptographic SHA256 digest, verifying the path from Git commits to running runtimes.
* **Evidence Vault**: Secure and immutable storage for external scans (SBOM, CVE reports, log files) using local folders or cloud providers (S3, GCS, Azure Blob).
* **Pluggable Secrets & Vaults**: Start dynamically using environment configurations or query credentials directly from HashiCorp Vault, AWS, GCP, and Azure.
* **LLM Auditing Gateway (`Fides-AI`)**: Out-of-the-box support for verifying compliance against natural language parameters using Ollama, llama.cpp, and Google Gemini.
* **Drift & Shadow Change Detection**: Continuously monitor running containers or server state to find unauthorized shadow deployments and configuration drift.
* **FDA 21 CFR Part 11 Ready**: Built-in support for time-stamped system log tables, electronic records, and ECDSA signature validation for attestation logs.
* **Regulated Control Frameworks**: One-command adoption of SOC 2, ISO 27001, NIST 800-53, PCI-DSS, DORA, PSD2, and SOX control catalogs (`fides control import --framework`), with per-framework, audit-ready reports (`fides report --framework`) and coverage across environments.
* **Change Gate & Risk Scoring**: An evidence-backed approve/hold verdict with a 0–100 risk score for any change (`fides change-gate`), driven by which controls pass, fail, or lack evidence — and written back onto the matching **ServiceNow Change Request** (work note + risk field). Fides advises; ServiceNow decides.
* **Segregation of Duties**: First-class approval evidence (`fides approve`) distinguishing human sign-off from machine automation; four-eyes requires two distinct human approvers, and the change gate will not recommend approval without a human review.
* **Tenant Isolation (RLS)**: Defense-in-depth Postgres Row-Level Security enforced at the database layer — the app runs as a least-privilege role so a tenant only ever sees its own data (`FIDES_RLS_ENABLED`).
* **WORM Evidence Retention**: Optional S3 Object Lock retention so stored evidence is immutable for a fixed window (`FIDES_OBJECT_LOCK_MODE` + `FIDES_EVIDENCE_RETENTION_DAYS`) — for DORA/SOX.
* **Git Providers**: Commit-status checks and signed inbound push webhooks for **GitHub, GitLab, Bitbucket, and Azure DevOps**.
* **Multi-Tenant Go API + Postgres**: A single Go compliance API backed by multi-tenant PostgreSQL with embedded, self-applying migrations (no separate migration step on boot).
* **Easy Install**: A Helm chart (`charts/fides`) with a one-step seed job, or `scripts/setup-db.sh` — see [docs/setup.md](docs/setup.md).

---

## Command-Line Interface (`fides`)

The statically compiled `fides` CLI drives the full evidence lifecycle from any pipeline:

* **`fides trail start`** — open a build trail bound to a flow, repository, commit, and branch.
* **`fides artifact report`** — register a built artifact by its SHA256 digest for supply-chain provenance.
* **`fides attest`** — attach signed evidence of many kinds: `junit`, `snyk`, `trivy`, `sbom-cyclonedx`, `secret-scan`, `sast`, `iac`, and more (with `--encrypt` and Evidence Vault attachments).
* **`fides verify-chain`** — validate the tamper-evident attestation chain for a trail or artifact.
* **`fides assert`** — deterministic policy gate; exits non-zero when an artifact is non-compliant.
* **`fides verify-image`** — verify a container image's cosign/Sigstore signature (keyless OIDC identity or key-based) and record a `cosign-verification` attestation; exits `2` on a failed/untrusted signature.
* **`fides change-gate`** — evidence- and risk-backed approve/hold verdict with a 0–100 risk score; exits `2` on hold and can write the verdict back to ServiceNow.
* **`fides allowlist`** — manage per-environment allow-lists of approved artifacts and rules.
* **`fides control import|coverage|enforce`** — import framework control catalogs, report coverage, and enforce controls across environments.
* **`fides report --framework`** — generate per-framework, audit-ready reports (SOC 2, ISO 27001, NIST 800-53, PCI-DSS, DORA, PSD2, SOX).
* **`fides metrics deployment-frequency`** — DORA-style delivery metrics.

---

## Project Structure

* `cmd/server/`: The entry point for the REST API backend.
* `cmd/cli/`: Statically compiled cross-platform CLI tool for macOS, Windows, and Linux.
* `pkg/models/`: Struct mapping PostgreSQL tables.
* `pkg/storage/`: Pluggable storage providers (local folder filesystem, AWS S3, etc.).
* `pkg/vault/`: Pluggable secrets vault interfaces.
* `pkg/policy/`: Compliance policy checking engine using JQ expressions.
* `pkg/ai/`: Artificial Intelligence gateway client supporting Ollama, llama.cpp, and Gemini.
* `pkg/api/`: REST server routers, request validators, and HTTP controllers.

---

## Installation

Three ways to get the `fides-server`, `fides`, `fides-mcp`, and `fides-mcp-sensor`
binaries — see the full **[Installation guide](installation.md)** for details:

* **Release downloads** — pre-built archives for Linux and macOS (amd64 + arm64),
  with SHA-256 checksums, on the
  **[Releases page](https://github.com/olafkfreund/fides/releases)**.
* **Nix / NixOS** — the repo is a flake:
  ```bash
  nix run github:olafkfreund/fides#server      # run the API server
  nix profile install github:olafkfreund/fides#fides   # install the CLI
  ```
  NixOS hosts can enable the service with the bundled module
  (`fides.nixosModules.default` → `services.fides`).
* **From source** — `go build ./cmd/cli` (Go 1.26+); see the Quick Start below.

For the full self-hosted stack (Postgres + object store), use the Helm chart
(`charts/fides`) or the [Getting Started guide](getting_started.md).

---

## Quick Start

1. Start the backend database, MinIO object store, and Ollama engine:
   ```bash
   docker compose up --build -d
   ```
2. Build the server, CLI, and MCP binaries locally:
   ```bash
   go build -o fides-server cmd/server/main.go
   go build -o fides cmd/cli/main.go
   go build -o fides-mcp cmd/mcp/main.go
   ```
3. Initialize the database schema:
   ```bash
   psql -h localhost -U veritrail_user -d veritrail -f schema.sql
   ```
4. Read the **[getting_started.md](file:///mnt/data/Source-home/Calitti/evidance-vault/getting_started.md)** guide to set up Fides gates inside **GitHub Actions** and **GitLab CI/CD**.

---

## Model Context Protocol (MCP) Server

Fides includes a built-in Model Context Protocol (MCP) server `fides-mcp` that exposes compliance monitoring, pipeline flows, policies, artifacts, attestations, controls coverage, and deployment metrics as LLM-executable **tools** — and the Fides documentation as MCP **resources** (`fides://docs/*`) that an assistant can read on demand. It integrates with **Claude Code**, Claude Desktop, Cursor, and other AI clients for conversational interaction with your builds, audits, and pipelines. The binary is also shipped in the server image at `/usr/local/bin/fides-mcp`. See the full guide: [mcp-server.md](mcp-server.md).

### Configuration for Claude Desktop
Add the following configuration to your `claude_desktop_config.json` (located at `~/.config/Claude/claude_desktop_config.json` on Linux/macOS or `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "fides-mcp": {
      "command": "/absolute/path/to/fides-mcp",
      "env": {
        "FIDES_SERVER_URL": "http://localhost:8191"
      }
    }
  }
}
```

### Supported Tools
- `list_flows`: Retrieve details and status of all pipeline flows.
- `list_environments`: List runtime environment snapshots, active services, and drifts.
- `list_policies`: Fetch compliance policies and JQ release gate rules.
- `check_compliance`: Query policies compliance validation status for a specific artifact signature SHA256.
- `search_artifacts` / `search_attestations`: Query recorded artifacts and evidence.
- `get_controls_coverage`: Report control coverage across frameworks and environments.
- `get_deployment_frequency`: Return DORA-style delivery metrics.
- `create_flow`: Converse with LLM to register new pipeline flow streams.
- `create_trail` / `report_artifact` / `report_attestation`: Programmatic inputs to register pipeline activities and evidence.
- ServiceNow tools for reading change events and driving change-gate write-back.

### WebMCP (in-browser)
Beyond the standalone `fides-mcp` binary, the portal ships an in-browser **WebMCP** endpoint so browser agents and local LLMs can drive Fides directly from the authenticated web session — no separate client install required.


## Web Portal Tour

Fides features a premium, state-of-the-art web portal for security auditors and DevSecOps controllers. Below is a tour of the portal pages:

### 1. Overview Dashboard (Dark & Light Modes)
The dashboard provides a real-time summary of compliance parameters via **clickable KPI cards** (Tracked Artifacts, Compliance Pass Rate, Active Alerts, and AI Evaluations) that drill down into the underlying records, alongside workload environment status and audit logs.
- **Dark Mode:**
  ![Fides Overview Dashboard - Dark Mode](assets/screenshots/screenshot_20260630_151424-region.png)
- **Light Mode:**
  ![Fides Overview Dashboard - Light Mode](assets/screenshots/screenshot_20260630_151711-region.png)

### 2. Artifacts & SBOM Management
Trace built software deliverables and drill down from an artifact into its SBOM packages and attestation evidence. Compliant builds show packages, licenses, and vulnerabilities, while pending builds indicate scans in progress.
![Artifacts & SBOM Management](assets/screenshots/screenshot_20260630_151450-region.png)

### Controls & Coverage
Adopt regulated control frameworks and see coverage **grouped by control**, drill down into the evidence behind each control, and apply **one-click Enforce** to gate environments on a control — the browser companion to `fides control import|coverage|enforce`.

### 3. Environments & MCP Connections
Monitor active deployment environments (EKS, ECS, etc.) and configure Model Context Protocol (MCP) sensors (e.g. `k8s-sensor`) to query and verify compliance rules directly.
![Environments & MCP Connections](assets/screenshots/screenshot_20260630_151515-region.png)

### 4. Policies & JQ Rule Configurator
Author deterministic compliance gates in a **Monaco editor** with syntax highlighting, or let the LLM Policy Wizard's **AI Check & fix** validate and repair your JQ rules from a text-described goal.
![Policies & JQ Rule Configurator](assets/screenshots/screenshot_20260630_151532-region.png)

### 5. AI Audits & LLM Evaluator Reports
Review deep risk and compliance assessments generated asynchronously by local or cloud LLMs for every reported attestation.
![AI Audits & LLM Evaluator Reports](assets/screenshots/screenshot_20260630_151543-region.png)

### 6. Telemetry & OpenTelemetry Metrics
Gain observability into the Fides API backend, request rates, error rates, DB connection pools, and export data directly to Prometheus `/metrics` or OpenTelemetry scrapers.
![Telemetry & OpenTelemetry Metrics](assets/screenshots/screenshot_20260630_151558-region.png)

### 7. Settings & SSO Group Mappings
Manage local directories, SSO group mappings (e.g. GitHub teams, Okta group claims), and define roles.
![Settings & SSO Group Mappings](assets/screenshots/screenshot_20260630_151619-region.png)

### 8. Help & Documentation Center
A built-in help center providing code templates, CLI usage instructions, and links to `/llms.txt` and `/llms-full.txt` standard context endpoints.
![Help & Documentation Center](assets/screenshots/screenshot_20260630_151625-region.png)

### 9. AI Assistant (with Voice)
A conversational AI Assistant is embedded in the portal — including **voice input** — and is backed by the in-browser WebMCP endpoint, so you can query flows, artifacts, controls coverage, and audits or drive Fides actions in natural language without leaving the browser.


