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

Fides includes a built-in Model Context Protocol (MCP) server `fides-mcp` that exposes compliance monitoring, pipeline flows, policies, and build attestations as LLM-executable tools. It can be integrated into modern AI clients (like Claude Desktop, Cursor, or Antigravity) to enable conversational interactions with your builds, audits, and pipelines.

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
- `create_flow`: Converse with LLM to register new pipeline flow streams.
- `create_trail` / `report_artifact` / `report_attestation`: Programmatic inputs to register pipeline activities and evidence.


## Web Portal Tour

Fides features a premium, state-of-the-art web portal for security auditors and DevSecOps controllers. Below is a tour of the portal pages:

### 1. Overview Dashboard (Dark & Light Modes)
The dashboard provides a real-time summary of compliance parameters (Tracked Artifacts, Compliance Pass Rate, Active Alerts, and AI Evaluations) alongside workload environment status and audit logs.
- **Dark Mode:**
  ![Fides Overview Dashboard - Dark Mode](assets/screenshots/screenshot_20260630_151424-region.png)
- **Light Mode:**
  ![Fides Overview Dashboard - Light Mode](assets/screenshots/screenshot_20260630_151711-region.png)

### 2. Artifacts & SBOM Management
Trace built software deliverables and verify SBOM package compatibility. Compliant builds show packages, licenses, and vulnerabilities, while pending builds indicate scans in progress.
![Artifacts & SBOM Management](assets/screenshots/screenshot_20260630_151450-region.png)

### 3. Environments & MCP Connections
Monitor active deployment environments (EKS, ECS, etc.) and configure Model Context Protocol (MCP) sensors (e.g. `k8s-sensor`) to query and verify compliance rules directly.
![Environments & MCP Connections](assets/screenshots/screenshot_20260630_151515-region.png)

### 4. Policies & JQ Rule Configurator
Configure deterministic compliance gates using JQ rules or let the **LLM Policy Wizard** automatically generate rule configurations based on text-described goals.
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


