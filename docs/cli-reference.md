# Fides CLI Reference

Set `FIDES_SERVER_URL` and `FIDES_API_TOKEN` (a static token or a service-account
key). Optionally `FIDES_ENCRYPTION_KEY` to encrypt attestation payloads.

## Exit codes (gate commands)

Every gate command follows one convention so CI can tell "policy said no" apart
from "the command broke":

| Code | Meaning |
|------|---------|
| `0` | OK — success / verified / compliant |
| `1` | Error — operational failure (usage, network, parse); no verdict reached |
| `2` | Violation — the gate completed and the verdict is FAIL |

Gate deploys on `2`. Applies to `assert`, `verify-image`, `change-gate`,
`verify-chain`, `env verify`, `allowlist check`. (`assert` now exits `2` on
non-compliance — previously `1`.)

## Pipeline (build/CI)

| Command | Purpose |
|---|---|
| `fides trail start --flow <id> --trail <name> [--repository --commit --branch --message --committer <email>] [--committed-at <RFC3339>]` | Begin a build trail (`--committer` records commit-metadata identity for segregation-of-duties; `--committed-at`, or auto-derived from `--commit` via git, records the commit timestamp for true code-to-prod DORA lead time) |
| `fides artifact report --org <id> --trail <id> --sha256 <hex>\|--file <path> --name <n> --type docker` | Register an artifact |
| `fides attest --trail <id> --name <n> --type <t> --payload <json\|file> [--attachments a,b] [--encrypt]` | Generic attestation |
| `fides attest junit\|snyk\|trivy\|slsa --trail <id> --file <report> [--name --artifact-sha]` | Parse a report into an attestation (SLSA in-toto provenance records under type `slsa-provenance`) |
| `fides attest sbom --file <bom.json> --artifact-sha <hex> [--trail <id> --name]` | Ingest a CycloneDX/SPDX SBOM (auto-detected); persists a component per package, linked to the artifact (`--trail` optional — resolved from the artifact) |
| `fides attest fetch --trail <id> --artifact-sha <hex> [--provider github\|gitlab] [--repo <owner/repo>]` | Ingest platform-native GitHub/GitLab SLSA attestations for an artifact (records under type `slsa-provenance`) |
| `fides attest authorship --trail <id> [--commit <ref>] [--reviewer <name>]` | Record a `code.authorship` attestation from the commit's git trailers (human vs AI-agent author, reviewer). AI-authored changes without a human reviewer are non-compliant, so a control requiring `code.authorship` holds the change gate |
| `fides assert --sha256 <hex> --policy <name>` | Policy gate for an artifact |
| `fides verify-image --sha256 <hex> --signer <identity> [--issuer <oidc-issuer>] [--key <pubkey.pem>] [--image <repo> \| --bundle <path>] [--trail <id>]` | Verify a container image's cosign signature — keyless (OIDC identity+issuer) or key-based (`--key`) — and optionally record a `cosign-verification` attestation (deploy gate; exits 2 on failure). `--image ghcr.io/org/name` resolves the signature straight from the registry; `--bundle` uses a pre-fetched one (offline/air-gapped) |
| `fides verify-chain --trail <id>` | Verify the tamper-evidence chain (exit 2 if broken); also reports the external RFC3161 anchor status (`external_anchor`) if the trail was anchored |
| `fides anchor --trail <id> [--tsa <url>]` | Anchor the trail's chain head to an external RFC3161 timestamp authority (proves the head existed at a point in time, independently of the Fides DB). TSA URL from `--tsa` or the server's `FIDES_TSA_URL`; a `--tsa` host must be allowed by `FIDES_TSA_ALLOWED_HOSTS` |
| `fides audit --trail <id> [--output <file.zip>]` | Download the trail audit package |

## Runtime snapshots

| Command | Purpose |
|---|---|
| `fides snapshot docker --env <id> [--container <n>]` | Docker runtime |
| `fides snapshot k8s --env <id> [--namespace <ns>]` | Kubernetes (via kubectl) |
| `fides snapshot ecs --env <id> --cluster <name>` | AWS ECS (via aws CLI) |
| `fides snapshot lambda --env <id>` | AWS Lambda (via aws CLI) |

### What a snapshot will and will not report

A snapshot artifact is an **observation of what is running**. When the runtime
cannot tell Fides the digest, the container is skipped with a warning on stderr
rather than reported with a substitute value. A digest that is not the running
image's can never equal a CI-registered artifact or an allowlist entry, so it
becomes a shadow change no correct action can clear — an environment pinned at
non-compliant for a reason its operator cannot fix.

Two AWS cases where that happens, both outside Fides' control:

- **ECS reports `imageDigest` only for images pulled from a private Amazon ECR
  repository.** For Docker Hub, public ECR, GHCR or any other registry AWS omits
  the field ([containers-roadmap#1640](https://github.com/aws/containers-roadmap/issues/1640)).
  Those containers are skipped. To get full coverage, pull through private ECR.
- **Lambda container functions** are resolved through `aws lambda get-function`
  → `Code.ResolvedImageUri`, which is the ECR digest Lambda pinned at deploy
  time. This costs one extra API call per image function, and needs
  `lambda:GetFunction` in addition to `lambda:ListFunctions`. Zip functions use
  `CodeSha256` and need no extra call.

> `CodeSha256` is **not** the image digest for container functions. It is the
> hash of the function's *deployment package*, which for `PackageType: Image` is
> Lambda's own optimized copy — AWS states it is "not the same key that's used
> to protect your container image in Amazon ECR". It is 64 hex characters, so it
> looks exactly like a digest and passes every format check while never matching
> the artifact the build registered.

## Environments, policies, approvals

| Command | Purpose |
|---|---|
| `fides allowlist add\|list\|check\|remove --env <id> [--sha <hex>\|--image <ref>] [--reason <r>]` | Per-environment artifact approvals (`check` exits 2 if not approved). `add` **requires** `--reason` — the entry records an accepted risk, and one with no stated justification cannot be evaluated by an auditor later — plus either `--sha <hex>` or `--image <ref>`, which resolves the digest from the registry so you do not have to read it out of a pod's `imageID` by hand. For a multi-arch tag that resolves to the **index** digest, which is what a runtime reports. The approver comes from the authenticated principal and is never blank, including for machine credentials. |
| `fides flow list \| trails --flow <id> \| artifacts --flow <id>` | List flows and their trails / artifacts |
| `fides flag record --flag-key <key> --env <env> --from <state> --to <state> [--actor --source unleash\|flagsmith\|manual --flow <id>]` | Record a feature-flag change as a `flag.changed` attestation on a per-change trail (governs flag flips like deploys) |
| `fides flag list [--limit N]` | List recent feature-flag changes (flag_key, env, state, actor, compliant) for auditors |
| `fides policy create --name --rules-file \| delete --id \| generate --framework --description` | Global policies: create, delete, and AI-draft rules (via the LLM) |
| `fides policy add\|list\|check --env <id> [--name --require t1,t2 --if-tag --if-value --trail]` | Environment policies (`check` exits 2 on non-compliance) |
| `fides env diff --env <id> [--from <snap> --to <snap>]` | Diff two snapshots |
| `fides env diff --env <id> --reevaluate-change CHGxxxx [--from --to]` | Post-approval drift re-evaluation: diffs snapshots and, if drift is detected, escalates the ServiceNow change's risk + posts a work note (exits 2 on drift) |
| `fides env verify --env <id> --server <mcp-name> [--tool get_pods] --rule <jq> [--rule …] [--rules-file <f>]` | Ask the runtime MCP sensor about the live environment and gate on jq rules (exits 2 if non-compliant). `--rule` is repeatable |
| `fides logical-env create\|list\|add-member\|state [--name --id --env]` | Logical (aggregate) environments |
| `fides remediation propose\|list\|get\|approve\|reject\|apply [...]` | Policy-driven auto-remediation: propose a fix, then approve/reject/apply it |

## Controls, frameworks & change gate

| Command | Purpose |
|---|---|
| `fides control import --framework <SOC2\|ISO27001\|NIST-800-53\|PCI-DSS\|DORA\|PSD2\|SOX\|SLSA\|CRA>` | Adopt a regulated framework's control catalog (idempotent). `SLSA` is a supply-chain integrity catalog requiring `slsa-provenance`, `cosign-verification`, and `sbom-cyclonedx` evidence |
| `fides control frameworks` | List the available framework catalogs |
| `fides control coverage` | Show each control's evidence + environment coverage |
| `fides control timeline [--key <key>] [--days N]` | Continuous control-test evidence feed: each control's evidence events over time (default 90d) + latest derived status (passed/failed/missing), from the immutable attestation chain |
| `fides control enforce --key <key> --env <id>` / `--all-controls --all-environments` | Enforce control(s) — create enabled environment policies requiring their evidence types, raising coverage (idempotent) |
| `fides control add --key --name [--framework --require t1,t2]` | Add a custom control |
| `fides report --framework <name> [--format oscal]` | Auditor-ready per-framework report (control-by-control evidence + coverage); `--format oscal` emits a NIST OSCAL 1.x assessment-results JSON document instead (e.g. for FedRAMP 20x submission) |
| `fides report --cra-incidents [--hours N]` | EU CRA 24h reporting set: exploitable vulnerabilities (VEX `not_affected` excluded) discovered in the window, with affected artifacts + running environments |
| `fides change-gate --trail <id>` | Evidence-backed approve/hold verdict + 0–100 risk score (exits 2 on HOLD) |
| `fides approve --trail <id> [--reason <r>] [--role approver\|deployer]` | Record a segregation-of-duties approval (human vs machine; four-eyes = 2 distinct humans); refreshes the trail's `segregation-of-duties` attestation proving committer != approver != deployer |

## EU AI Act model provenance

Reuses trails/attestations — no parallel engine. A model version is a `Trail`
(register it under a `Flow` representing the model); training/eval/audit
evidence and inference/decision events are `Attestation`s of type
`model-provenance` on that trail, so they inherit the existing tamper-evident
hash chain, `fides verify-chain`, `fides audit`, and evidence-attachment
retention (`FIDES_EVIDENCE_RETENTION_DAYS` / S3 Object Lock).

| Command | Purpose |
|---|---|
| `fides model register --flow <id> --version <v> [--repository --commit --branch --framework --risk-category unacceptable\|high\|limited\|minimal --purpose --tags k=v,...]` | Register a model version (Art. 6/13 metadata) |
| `fides model attest --trail <id> --kind training-data\|evaluation\|bias-audit\|... [--summary --findings --metadata --compliant --name --artifact-sha --attachments --encrypt]` | Record training/eval/audit evidence (Art. 10/15) |
| `fides model inference-log --trail <id> --input-hash <sha256>\|--input-file <path> --decision <d> [--output-hash\|--output-file --confidence 0-1 --actor --metadata --name]` | Record an inference/decision event (Art. 12 automatic logging; inputs/outputs are hashed, never uploaded raw) |
| `fides model versions --flow <id>` | List a model's registered versions |
| `fides model timeline --trail <id>` | List a model version's evidence + inference/decision events |

## Search & metrics

| Command | Purpose |
|---|---|
| `fides search artifacts [--sha --commit --name]` | Search artifacts |
| `fides search attestations [--type --trail --compliant]` | Search attestations |
| `fides search components [--purl --artifact --name]` | Search SBOM components — "which artifacts contain component X" |
| `fides impact --cve <CVE-ID>` | Which artifacts + running environments are affected by a CVE (from ingested trivy/snyk/sarif scans), with `not_affected` VEX statements suppressed |
| `fides impact --backfill` | Re-extract CVEs from existing trivy/snyk/sarif scan attestations into the impact index (admin; idempotent) — for scans recorded before CVE extraction shipped |
| `fides vex --cve <CVE-ID> --status <not_affected\|affected\|fixed\|under_investigation> [--product <sha256>] [--justification <text>]` | Record a VEX statement; `not_affected` suppresses the CVE from `fides impact` (`--product`: empty = org-wide, an artifact sha256, or a component purl to suppress across every artifact containing it) |
| `fides metrics [--days N]` | DORA delivery metrics (deployment frequency, change-failure rate, **lead time**, **MTTR**) |
| `fides metrics deployment-frequency [--weeks N]` | Weekly deployment frequency per environment |
| `fides metrics compliance-correlation [--days N]` | Correlate compliance verdicts against delivery outcomes over the window |
| `fides dashboard` | Interactive live TUI of server stats (checks, artifacts, coverage) — no flags |

## Integration & admin config

| Command | Purpose |
|---|---|
| `fides servicenow config\|get\|change-check [...]` | ServiceNow connection + change gate |
| `fides servicenow link-control --trail <id> --change <CHGxxxx> --control <key> [--attestation <id>]` | Record that a ServiceNow change implemented a Fides control via a specific attestation (writes the reference back onto the change_request) |
| `fides servicenow mcp servers\|lookup\|tools\|call [...]` | Consume ServiceNow's MCP server: discover servers, governed record lookup (CMDB/change/GRC), list/call governed tools. See [servicenow-mcp.md](servicenow-mcp.md) |
| `fides servicenow grounding --change <CHGxxxx>` | Authoritative grounding pack (control-coverage + evidence + risk + a natural-language summary) for a change, to ground ServiceNow Now Assist. See [servicenow-now-assist-grounding.md](servicenow-now-assist-grounding.md) |
| `fides slack config --secret-path <ref> [--disable]` | Slack notifications |
| `fides git-provider config --provider <github\|gitlab\|bitbucket\|azure-devops> --host --api-base --token-path [--inbound-secret-path]` | Git provider (commit status + inbound webhooks) |
| `fides webhook config --name --url --secret-path [--events] [--disable]` | Outbound signed webhook |
| `fides service-account create\|list\|issue-key\|revoke-key [...]` | Service accounts + API keys |
| `fides user set-password --user <id> --password <pw>` | Set a user's local password |

## AI tools (MCP)

Fides ships **`fides-mcp`**, a Model Context Protocol server so Claude Code, Cursor, and Claude Desktop can query your compliance data (flows, environments, artifacts, attestations, controls coverage, deployment frequency) **and read the Fides docs** in-conversation. See **[mcp-server.md](mcp-server.md)**.

See [features.md](features.md) for worked examples of each.
