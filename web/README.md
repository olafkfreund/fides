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
* **Easy Install**: A Helm chart (`charts/fides`) with a one-step seed job, or `scripts/setup-db.sh` — see [docs/setup.md](docs/setup.md).

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

* `list_flows`: Retrieve details and status of all pipeline flows.
* `list_environments`: List runtime environment snapshots, active services, and drifts.
* `list_policies`: Fetch compliance policies and JQ release gate rules.
* `check_compliance`: Query policies compliance validation status for a specific artifact signature SHA256.
* `create_flow`: Converse with LLM to register new pipeline flow streams.
* `create_trail` / `report_artifact` / `report_attestation`: Programmatic inputs to register pipeline activities and evidence.

## Web Portal Tour

Fides ships a premium web portal for security auditors and DevSecOps controllers.
Below is a tour of the portal pages. A light/dark theme toggle lives in the sidebar;
the screenshots below use dark mode.

### 1. Assurance Console

The live posture of every tracked artifact: compliance pass rate, a controls-coverage
donut segmented by framework, environment health with drift counts, cumulative and
24-hour check throughput, and a **streaming feed of checks as they land**. Integration
delivery (ServiceNow, webhooks) is on the same page, so a failed sink is visible
rather than silent.
![Fides Overview Dashboard](../docs/images/portal/00-overview.jpg)

### 2. Flows & Trails

Delivery pipelines (**Flows**) and their build **Trails**. Expand a flow to see each
trail's attestation count and act on it — **Change Gate**, **Approve**, **Verify chain**,
or **Download audit**.
![Flows & Trails](../docs/images/portal/01-flows.jpg)

Expanded, a flow lists every trail with its commit, attestation count and
per-trail actions:

![A flow expanded to its trails](../docs/images/portal/01b-flows-trails.jpg)

### 3. Artifacts, SBOM & Attestation drill-down

Search build artifacts by SHA256 and drill into an artifact's **SBOM** (CycloneDX / SPDX /
Syft components, licenses, vulnerabilities) and its full set of signed **attestations**.
![Artifacts, SBOM & Attestations](../docs/images/portal/02-artifacts.jpg)

Expanding an artifact shows its SBOM verdict and every attestation attached to
it:

![Artifact drill-down: SBOM and attestations](../docs/images/portal/02b-artifact-detail.jpg)

### 4. Attestations

Every piece of evidence recorded against build trails, with compliance status, evidence
type, and totals — filterable by name, type, and compliance.
![Attestations](../docs/images/portal/03-attestations.jpg)

Each attestation opens to its raw payload, the artifact it covers, and its
position in the hash chain:

![Attestation payload and chain hash](../docs/images/portal/03b-attestation-detail.jpg)

### 5. Environments & MCP Connections

Monitor runtime environments (EKS / ECS) with running / drift / shadow counts, and let
Fides run **live compliance checks** against each environment's **MCP sensors** (e.g. the
in-cluster `fides-mcp-sensor`) — plus per-environment artifact allow-lists.
![Environments & MCP Connections](../docs/images/portal/04-environments.jpg)

### 6. Policies Editor (Monaco + AI)

Author deterministic JQ compliance gates in a full **Monaco editor** with **Format** and an
AI **"Check & fix"** action, or generate rules from a described goal with the LLM Policy Wizard.
![Policies & JQ Rule Editor](../docs/images/portal/05-policies.jpg)

![Policy editor with jq rules](../docs/images/portal/05b-policy-editor.jpg)

### 7. Controls & Coverage

Adopt regulated frameworks (SOC 2, ISO 27001, NIST 800-53, PCI-DSS, DORA, PSD2, SOX) and see
coverage **grouped by framework**, with average coverage and gaps at a glance.
![Controls & Coverage](../docs/images/portal/06-controls.jpg)

![Control drill-down: per-environment enforcement](../docs/images/portal/06b-controls-enforcement.jpg)

Drill into any control to see the evidence it requires and its **per-environment
enforcement**, with one-click actions to enforce or archive it.

### 8. AI Audits & LLM Evaluator Reports

Deep, **parsed and scored** risk / compliance assessments generated by local or cloud LLMs
for every reported attestation — vulnerabilities, failures, licensing risks, and an overall score.
![AI Audits & LLM Evaluator Reports](../docs/images/portal/07-ai-audits.jpg)

### 9. Telemetry & OpenTelemetry Metrics

Live API backend observability — request / error rates, latency, DB connection pools, request
outcomes — plus **DORA weekly deployment frequency per environment**. Export to Prometheus
`/metrics` or OpenTelemetry.
![Telemetry & OpenTelemetry Metrics](../docs/images/portal/08-telemetry.jpg)

### 10. Settings & Integrations

Tabbed settings — **Infrastructure** (SSO / OAuth; evidence storage S3 / GCS / Azure / local;
secrets vault AWS / Vault / …; LLM provider — all by **secret reference**, never raw secrets),
**Directory & Group mappings** (map IdP groups to Fides roles), **ServiceNow**, **Slack**,
**Git & Webhooks** (commit-status + signed inbound webhooks), and **Service Accounts** (issue
CI/CD API keys).
![Settings](../docs/images/portal/09-settings.jpg)

![Directory & Groups — map IdP groups to Fides roles](../docs/images/portal/09b-settings-directory.jpg)

![Service Accounts — issue CI/CD API keys](../docs/images/portal/09e-settings-service-accounts.jpg)

A built-in **AI Assistant** — voice input and spoken replies, backed by the same Fides tools
exposed through in-browser WebMCP — floats on every page so agents can act inside the
authenticated session.

### 11. Help & Docs

Every guide, in-product — Getting Started, Small & Large Teams, User Stories, CI/CD Gate,
CLI Reference, and more.
![Help & Documentation](../docs/images/portal/10-help.jpg)

### 12. Risk Register

The risks the SDLC controls exist to reduce — supply-chain compromise, unauthorised
deployment, insider threat, configuration drift — each with its attack vectors and
the mitigating controls derived from the control catalog. Risks with **no control
mapped** are labelled as such rather than quietly omitted.
![Risk Register](../docs/images/portal/12-risks.jpg)

### 13. Secure SDLC

Your secure software lifecycle — **Build, Process, Runtime** — generated from the
control catalog, with every control marked preventive or detective and cross-mapped
to SOC 2, NIST 800-53, SLSA and SOX. One click downloads the audit pack.
![Secure SDLC](../docs/images/portal/14-sdlc.jpg)

### 14. Service Registry

Services and their ownership, so a gate verdict points at a team rather than a
repository name.
![Service Registry](../docs/images/portal/13-services.jpg)
