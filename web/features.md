# Fides Features & Real-World Examples

This guide covers the capabilities added across the platform, with copy-paste
examples for the CLI and API. All API calls use a bearer token
(`Authorization: Bearer $FIDES_API_TOKEN`) or a service-account key; the CLI
reads `FIDES_SERVER_URL` and `FIDES_API_TOKEN` from the environment.

> See also: [CLI reference](cli-reference.md) ·
> [ServiceNow](servicenow-integration.md) ·
> [AWS Secrets Manager](aws-secrets-manager.md) ·
> [Environment MCP compliance](environment-mcp-compliance.md)

---

## 1. Built-in evidence parsers (JUnit / Snyk / Trivy / SBOM)

Instead of hand-building JSON, point Fides at a raw report and it normalizes it
into a compliant/non-compliant attestation (attaching the original file).

```bash
# JUnit test results
fides attest junit  --trail $TRAIL --file ./reports/junit.xml --artifact-sha $DIGEST
# Snyk scan (compliant when no critical/high)
fides attest snyk   --trail $TRAIL --file ./reports/snyk.json
# Trivy image scan
fides attest trivy  --trail $TRAIL --file ./reports/trivy.json
```

The normalized payload (`{format, compliant, summary{counts}, findings}`) is
jq-evaluable, e.g. an attestation type with rule `.summary.failed == 0`.

`fides attest sbom` auto-detects CycloneDX vs SPDX JSON and additionally
persists a row per component (name, version, purl, licenses), linked to the
artifact — so you can search across every SBOM ever attested:

```bash
fides attest sbom --file ./sbom.json --artifact-sha $DIGEST   # --trail is optional

# Which artifacts contain a given component (e.g. auditing a CVE)?
fides search components --purl pkg:npm/lodash@4.17.20
fides search components --name log4j
```

## 2. Tamper-evident attestation chain

Every attestation is linked into a per-trail append-only hash chain. Any later
edit, deletion, or reorder is detectable.

```bash
fides verify-chain --trail $TRAIL          # exits non-zero (2) if the chain is broken
```
```bash
curl -H "Authorization: Bearer $FIDES_API_TOKEN" \
  $FIDES_SERVER_URL/api/v1/trails/$TRAIL/verify-chain
# {"valid":true,"count":4,"broken_at":-1}
```

## 3. Service accounts + rotatable API keys

Replace the single static token with per-tenant service accounts holding hashed,
rotatable keys.

```bash
fides service-account create --name ci-pipeline --role Writer
fides service-account issue-key --account $SA_ID --label "github-actions" --expires-hours 720
#  -> prints the full key ONCE: fides_<prefix>_<secret>
fides service-account list
# rotation: issue a new key, switch CI to it, then revoke the old one:
fides service-account revoke-key --account $SA_ID --key $OLD_KEY_ID
```

## 4. Per-environment artifact allow-lists / approvals

Explicitly approve a digest for an environment, and gate deploys on it.

```bash
fides allowlist add   --env $ENV --sha $DIGEST --reason "approved by release board"
fides allowlist check --env $ENV --sha $DIGEST    # exit 2 if not approved (use as a deploy gate)
fides allowlist list  --env $ENV
```

## 5. Environment policies + tags (conditional requirements)

Bind required attestation types to an environment, optionally only when a flow
tag matches (e.g. require a change record only for high-risk flows).

```bash
# tag a flow
curl -X POST $FIDES_SERVER_URL/api/v1/flows/$FLOW/tags \
  -H "Authorization: Bearer $FIDES_API_TOKEN" -d '{"tags":{"risk":"high"}}'

# policies on the environment
fides policy add --env $ENV --name tests     --require junit,trivy
fides policy add --env $ENV --name high-risk  --require servicenow-change --if-tag risk --if-value high

# gate a deploy: exits 2 if any applicable policy is unsatisfied
fides policy check --env $ENV --trail $TRAIL
```

## 6. Search & snapshot diff

```bash
fides search artifacts    --sha 3c8e7843 --name payments
fides search attestations --type junit --compliant false
fides env diff --env $ENV                  # diff the two most recent snapshots
fides env diff --env $ENV --from $SNAP_A --to $SNAP_B
```

## 7. Trail audit packages

Download a self-contained ZIP (trail, artifacts, attestations, chain verdict,
report) for auditors.

```bash
fides audit --trail $TRAIL --output trail-audit.zip
```

## 8. More runtimes (ECS / Lambda)

```bash
fides snapshot ecs    --env $ENV --cluster my-ecs-cluster
fides snapshot lambda --env $ENV
```

## 9. Logical environments

Aggregate physical environments into one compliance view.

```bash
fides logical-env create --name production --description "all prod runtimes"
fides logical-env add-member --id $LOGICAL --env $K8S_PROD_ENV
fides logical-env add-member --id $LOGICAL --env $ECS_PROD_ENV
fides logical-env state --id $LOGICAL       # unified running services across members
```

## 10. DORA delivery metrics

```bash
fides metrics --days 30
# {"deployments":42,"deployment_frequency_per_day":1.4,"compliance_rate":0.97,"change_failure_rate":0.03,...}

fides metrics deployment-frequency --weeks 12
# [{"environment":"prod","week":"2026-W27","deployments":7}, ...]  (weekly, per environment)
```

## 11. ServiceNow integration

Configure once, then CMDB sync + ITOM alerts + the ITSM change gate run on the
event engine. There is also a Go-served admin page at `/servicenow`
(view / verify / monitor). Full guide: [servicenow-integration.md](servicenow-integration.md).

```bash
fides servicenow config --instance-url https://acme.service-now.com \
  --auth-type basic --client-id svc-fides --secret-path fides/servicenow
fides servicenow change-check --trail $TRAIL --change CHG0030192
```

## 12. Slack notifications

```bash
# store the incoming-webhook URL as a secret (env var or Secrets Manager id), then:
fides slack config --secret-path fides/slack-webhook
```
Compliance events (`compliance.evaluated`, `snapshot.noncompliant`) are posted to
the channel when the event engine is enabled (`FIDES_EVENTS_ENABLED=true`).

## 13. Other integration config (CLI)

```bash
fides git-provider config --provider github --host github.com \
  --api-base https://api.github.com --token-path fides/gh-token --inbound-secret-path fides/gh-webhook
fides webhook config --name audit-sink --url https://example.com/hook --secret-path fides/hook-secret
fides user set-password --user $USER_ID --password 'S0me-Strong-Pass'
```

## 14. Flows, trails & artifacts from the CLI

```bash
fides flow list                    # all flows
fides flow trails --flow $FLOW     # the flow's build trails (name, commit, compliance)
fides flow artifacts --flow $FLOW  # artifacts across the flow's trails (with fingerprints)
```

## 15. Policies: create, delete & AI-drafted rules

```bash
# draft rules from plain English via the configured LLM
fides policy generate --framework SOC2 \
  --description "block critical CVEs and require passing unit tests plus an SBOM"

# create / delete a named policy
fides policy create --name production-release-rules --rules-file rules.json
fides policy delete --id $POLICY_ID
```

The same wizard (with AI drafting) is available in the portal at **Policies → New Policy**.
The portal edits rules in a **Monaco code editor** (JSON syntax highlighting,
bracket matching, line numbers) with two actions:

- **Format** — pretty-prints the rules JSON in place.
- **Check & fix** — sends the rules to `POST /api/v1/ai/lint-policy`, which reviews
  them for JSON errors and jq best practices and rewrites them (via the configured
  LLM; falls back to a deterministic validate-and-format when no LLM is set),
  showing review notes below the editor.

The editor is resizable (drag the bottom edge) and has an **Expand** toggle for a
near-fullscreen view.

## 16. AI tools — the Fides MCP server (`fides-mcp`)

Fides ships a Model Context Protocol server so **Claude Code**, Cursor, and Claude
Desktop can query your compliance data **and read the docs** in-conversation.

```jsonc
// .mcp.json
{ "mcpServers": { "fides": {
  "command": "/path/to/fides-mcp",
  "env": { "FIDES_SERVER_URL": "https://fides.example.com", "FIDES_API_TOKEN": "<service-account key>" }
} } }
```

Tools include `list_flows`/`list_environments`/`list_policies`, `check_compliance`,
`search_artifacts`, `search_attestations`, `get_controls_coverage`,
`get_deployment_frequency`, the ServiceNow tools, and provenance recording. It also
exposes the documentation as MCP **resources** (`fides://docs/*`). Full guide:
[mcp-server.md](mcp-server.md).

**In-browser WebMCP** — the portal also registers Fides tools with the browser's
WebMCP surface (the W3C `document.modelContext` API, with the `@mcp-b/global`
polyfill as a fallback), so a browser-integrated agent or a **local LLM/assistant**
can drive Fides directly from the page using your session. Exposed tools:
`fides_list_flows`, `fides_list_environments`, `fides_list_policies`,
`fides_controls_coverage`, `fides_search_artifacts`, `fides_search_attestations`,
`fides_deployment_frequency`, `fides_compliance_summary` (read-only), plus the
safe actions `fides_enforce_control` and `fides_import_framework`. Native WebMCP
needs Chrome with the origin trial; elsewhere the polyfill bridge is used, and it
no-ops if the browser has neither.

## 17. Regulated compliance & governance

Adopt a control framework, gather evidence for it, and turn the result into a change decision that flows into ServiceNow.

```bash
# adopt a framework's control catalog (idempotent); one of
#   SOC2 | ISO27001 | NIST-800-53 | PCI-DSS | DORA | PSD2 | SOX
fides control import --framework SOC2
fides control frameworks          # list catalogs
fides control coverage            # evidence + environment coverage per control

# enforce control(s) — creates an enabled environment policy requiring the
# control's evidence types, so coverage reflects it. Idempotent.
fides control enforce --key SOC2-CC7.1 --env <env-id>
fides control enforce --all-controls --all-environments   # raise coverage everywhere

# auditor-ready, control-by-control report for a framework
fides report --framework SOC2

# evidence-backed approve/hold verdict + 0-100 risk score (exits 2 on HOLD)
fides change-gate --trail <trail-id>

# record a segregation-of-duties approval (human vs machine; four-eyes = 2 humans)
fides approve --trail <trail-id> --reason "reviewed by platform lead"

# record the deploying identity's approval too, so the change gate can prove
# committer != approver != deployer
fides approve --trail <trail-id> --role deployer --reason "prod deploy"
```

- **Segregation-of-duties attestation**: every `fides change-gate` and `fides
  approve` call (re-)records a `segregation-of-duties` attestation on the trail,
  proving the committer (from the trail's `--committer` commit-metadata tag),
  the approver(s), and the deployer are distinct identities — `compliant: true`
  only when all three roles are pairwise-distinct. Required by PCI-DSS 4.0 and
  SOX ITGC change-management controls; the payload is shaped for ServiceNow to
  read directly. **See the [Segregation of duties guide](segregation-of-duties.md)**
  for how each identity is supplied (CLI + API) with a worked `compliant: true`
  example — note identities register under `/api/v1/tenant/users`, not `/api/v1/users`.

- **Change gate → ServiceNow**: `POST /api/v1/servicenow/change-gate {trail_id, change_number}`
  writes the verdict + risk onto the matching Change Request (work note + `risk`
  field). Fides advises; ServiceNow decides.
- **Segregation of duties**: the gate will not recommend approval without at least
  one human approval; a missing sign-off raises the risk score.
- **Portal**: the **Controls** page opens on an at-a-glance summary (control count,
  average coverage, fully-covered vs gaps) with coverage **grouped by framework**
  (least-covered first). **Click a control** to drill into its required evidence
  types and **per-environment enforcement** — enforce it in one environment or
  everywhere with a button; the backing environment policy is created and coverage
  updates immediately. Adopting a framework and adding custom controls live in a
  collapsible "Add or import controls" section. The **Dashboard** top stat cards are
  clickable and deep-link to their source (e.g. *Active Alerts* → non-compliant
  attestations, *Tracked Artifacts* → the artifacts list).

## 18. Tenant isolation, WORM retention & git providers

- **Row-Level Security**: enable database-enforced tenant isolation with
  `FIDES_RLS_ENABLED=true`. The app connects as a least-privilege `fides_app`
  role; `schema-rls.sql` policies isolate every tenant table. See
  [Setup & Seeding](setup.md).
- **WORM evidence retention**: set `FIDES_OBJECT_LOCK_MODE=GOVERNANCE|COMPLIANCE`
  and `FIDES_EVIDENCE_RETENTION_DAYS=<n>` to write evidence with an S3 Object Lock
  retain-until date (the bucket must have Object Lock enabled) — for DORA/SOX.
- **Git providers**: commit-status checks and signed inbound push webhooks for
  **GitHub, GitLab, Bitbucket, and Azure DevOps**
  (`fides git-provider config --provider <github|gitlab|bitbucket|azure-devops> ...`).

## 19. Install & seed

Use the Helm chart (server + a one-step seed job) or the seed script:

```bash
helm install fides ./charts/fides -n fides --create-namespace \
  --set database.host=<pg-host> --set database.ownerPassword=<pw> \
  --set database.appPassword=<pw> --set org.id=$(uuidgen) \
  --set portal.username=admin --set portal.password=<pw>
# or, against an existing Postgres:
ORG_NAME="Acme Corp" ./scripts/setup-db.sh
```

Full walkthrough (RLS role, secrets, first login, upgrade path): [Setup & Seeding](setup.md).

## 20. Vulnerability impact index & VEX

Turn point-in-time scan evidence into a live "which running environments ship
CVE-X?" query. CVE IDs from ingested trivy/snyk/sarif attestations are joined
through SBOM components and runtime snapshots to the environments running each
affected artifact. VEX `not_affected` statements suppress a CVE so teams focus on
*exploitable* exposure.

```bash
fides impact --cve CVE-2021-44228
fides vex --cve CVE-2021-44228 --status not_affected --justification "class never loaded"
```

## 21. AI-authored-code provenance (`code.authorship`)

Record whether a change was authored by a human or an AI agent, parsed from git
commit trailers. AI-authored changes without a human reviewer are non-compliant,
so a control requiring `code.authorship` holds the change gate until review.

```bash
fides attest authorship --trail $TRAIL --commit HEAD --reviewer "olaf@acme.com"
```

## 22. EU Cyber Resilience Act (CRA) framework

Built-in framework catalog mapping CRA Annex I essential requirements to Fides
evidence types; adopt and report on it like any other framework (OSCAL export
included).

```bash
fides control import --framework CRA
fides report --framework CRA
```

## 23. External RFC3161 timestamp anchoring

Anchor a trail's chain head to an external RFC3161 Time-Stamp Authority so an
auditor can prove the head existed at a point in time, independently of the Fides
database.

```bash
fides anchor --trail $TRAIL --tsa https://freetsa.org/tsr
fides verify-chain --trail $TRAIL   # response includes external_anchor{anchored,timestamp,head_matches}
```

## 24. SIEM streaming (Splunk HEC)

Stream governance events to a SIEM via the Splunk HTTP Event Collector. Opt in on
the server with `FIDES_EVENTS_ENABLED=true`, `FIDES_SIEM_HEC_URL`, and
`FIDES_SIEM_HEC_TOKEN`.

## 25. Persistent sessions (horizontal scale)

Enable the Postgres-backed session store for multi-replica / HA deployments so
sessions survive restarts and are shared across replicas (only a token hash is
stored):

```bash
FIDES_DB_SESSIONS=true fides-server   # requires migration 0020
```
