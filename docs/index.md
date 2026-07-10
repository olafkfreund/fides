# Fides

**Fides** (named after the Roman goddess of trust and oaths) is a self-hosted,
multi-cloud compatible **compliance, provenance & evidence-tracking system**. It
records and evaluates every state change in the software delivery lifecycle
(SDLC) in real time, acting as an audit-ready single source of truth for strict
compliance frameworks such as SOC 2, ISO 27001, NIST 800-53, PCI-DSS, DORA,
PSD2, SOX, and FDA 21 CFR Part 11.

## Architecture at a glance

Fides is a single **Go** compliance API backed by **multi-tenant PostgreSQL**
with embedded, self-applying migrations (no separate migration step on boot).
Tenant isolation is enforced in the database via Postgres Row-Level Security
(`FIDES_RLS_ENABLED`). Evidence is stored in a pluggable Evidence Vault (local
folder, S3, GCS, Azure Blob), optionally under S3 Object Lock for WORM
retention. Secrets come from a pluggable vault backend (environment, HashiCorp
Vault, AWS/GCP/Azure).

The statically compiled **`fides` CLI** drives the full evidence lifecycle from
any pipeline — trails, artifacts, signed attestations, policy gates, change
gates, and control-framework reporting. An **MCP server** (`fides-mcp`) exposes
the same capabilities to AI tools (Claude Code, Cursor, Claude Desktop).

## Core capabilities

- **Supply-chain provenance** — trace artifacts by cryptographic SHA256 digest
  from Git commit to running runtime; verify cosign/Sigstore signatures and SLSA
  in-toto provenance.
- **Evidence Vault** — immutable storage for external scans (SBOM, CVE reports,
  logs) with tamper-evident attestation chains.
- **Change gate & risk scoring** — an evidence-backed approve/hold verdict with
  a 0–100 risk score, written back onto the matching ServiceNow Change Request.
- **Segregation of Duties** — approval evidence distinguishing human sign-off
  from machine automation; four-eyes requires two distinct human approvers.
- **Regulated control frameworks** — one-command adoption of SOC 2, ISO 27001,
  NIST 800-53, PCI-DSS, DORA, PSD2, and SOX catalogs with per-framework,
  audit-ready reports and coverage across environments.

## Documentation

| Topic | Page |
|-------|------|
| Database seeding & brand-new setup | [Setup & Seeding](setup.md) |
| Full `fides` CLI command reference | [CLI Reference](cli-reference.md) |
| MCP server for AI tools | [MCP Server](mcp-server.md) |
| Features & real-world examples | [Features & Examples](features.md) |
| Supplying the three approval identities | [Segregation of Duties](segregation-of-duties.md) |
| Runtime compliance checks via MCP | [Environment MCP Compliance](environment-mcp-compliance.md) |
| ServiceNow integration overview | [ServiceNow Integration](servicenow-integration.md) |
| Consuming ServiceNow's MCP server | [ServiceNow MCP](servicenow-mcp.md) |
| Onboarding Fides as an MCP server in ServiceNow | [ServiceNow MCP Onboarding](servicenow-mcp-onboarding.md) |
| Grounding ServiceNow Now Assist with Fides evidence | [Now Assist Grounding](servicenow-now-assist-grounding.md) |
| ServiceNow DevGovOps spoke | [DevGovOps Spoke](servicenow/README.md) |
| Flow Designer actions | [Flow Designer Actions](servicenow/flow-designer-actions.md) |
| HMAC-signed inbound webhook verification | [HMAC Webhook Verification](servicenow/hmac-webhook-verification.md) |
| Pricing & open-core proposal | [Pricing](pricing.md) |
| Market position & competitive analysis | [Market Analysis 2026](market-analysis-2026.md) |
| AWS Secrets Manager secrets backend | [AWS Secrets Manager](aws-secrets-manager.md) |
