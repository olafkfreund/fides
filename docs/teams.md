# Using Fides in Small and Large Teams

This guide explains **what Fides does**, **how it works**, and **how to adopt it**
whether you're a two-person team shipping from `main` or a regulated enterprise
with dozens of pipelines and an auditor asking for evidence.

---

## What Fides does (and how)

Fides is a **self-hosted compliance, provenance, and evidence layer** for your
software delivery. It doesn't replace your CI, your scanners, or your change
board — it records what they produced as tamper-evident evidence and lets you
**gate** releases on that evidence.

The whole system is four nouns and two verbs:

| Concept | What it is |
|---------|------------|
| **Flow** | A pipeline/service you track (e.g. `auth-service`). |
| **Trail** | One build/run of a flow. Everything hangs off a trail. |
| **Artifact** | A thing a build produced, identified by its SHA256 (a container image, a binary). |
| **Attestation** | A piece of evidence attached to a trail/artifact — a scan result, an SBOM, a signature verification, an approval. |

Every attestation is appended to a **tamper-evident hash chain** per trail, so
the evidence can't be altered after the fact (`fides verify-chain`, optionally
anchored to an external RFC3161 timestamp authority with `fides anchor`).

The two verbs:

- **Record** — `fides trail start`, `fides artifact report`, `fides attest …`
  turn your existing pipeline output into evidence.
- **Gate** — `fides assert`, `fides verify-image`, `fides change-gate`,
  `fides verify-chain`, `fides env verify` return exit code **`2`** when the
  verdict is *fail*, so any CI job can block a merge or deploy on them.

On top of that, **Controls & Coverage** maps evidence to regulated frameworks
(SOC2, ISO27001, NIST 800-53, PCI-DSS, DORA, PSD2, SOX, SLSA, CRA), and the
**portal** (served at `/`) shows it all live: a real-time Assurance Console,
per-framework coverage, artifacts + SBOMs, attestations, and DORA metrics.

---

## The adoption ladder

You don't need all of it on day one. Fides is designed to be adopted one rung at
a time — start by *recording* evidence (no gates, nothing blocks), then turn on
gates in **warn-only** mode, then enforce.

```
Record evidence  →  Gate in warn-only  →  Enforce gates  →  Adopt control frameworks
   (visibility)        (no failures)       (blocks bad          (auditor-ready
                                            releases)             reports)
```

---

## Small teams (1–10 developers)

**Goal:** provenance and a safety net, with near-zero ceremony.

**Setup**
- Run one Fides server (single container + Postgres; see
  [installation](installation.md) / [getting started](getting_started.md)).
- One **Flow** per service. One shared **org**.
- Auth with a single service-account token (`FIDES_API_TOKEN`) — no user
  directory needed.

**In CI (GitHub Actions or GitLab CI)**
- Record a trail + artifact on every build, attach your existing scan output:
  ```bash
  fides trail start --flow $FLOW_ID --trail $CI_SHA --commit $CI_SHA --committer "$AUTHOR"
  fides artifact report --org $ORG_ID --trail $CI_SHA --file image.tar --name app --type docker
  fides attest trivy --trail $CI_SHA --file trivy.json
  ```
- Add **one** gate, in warn-only, so nothing breaks while you learn it:
  ```yaml
  # GitHub — see docs/ci-gate.md
  - uses: olafkfreund/fides/.github/actions/fides-gate@v0.3.0
    with: { command: assert, sha256: "${{ steps.build.outputs.digest }}",
            policy: no-critical-vulns, warn-only: true }
  ```

**What you get:** a live portal showing every build's evidence, `verify-chain`
proof nothing was tampered with, and DORA metrics (`fides metrics`) — without
changing how you ship.

**Skip for now:** control frameworks, segregation-of-duties, ServiceNow,
logical environments. You can turn these on later without redoing anything.

---

## Growing teams (10–50 developers)

**Goal:** enforce a baseline, split responsibilities, start mapping to a
framework.

**Add**
- **Service accounts per pipeline** instead of one shared token:
  ```bash
  fides service-account create --name ci-auth-service
  fides service-account issue-key --name ci-auth-service
  ```
- **Flip gates from warn-only to enforce.** Drop `warn-only` and the job now
  fails (exit `2`) on a bad verdict. Common gates: `assert` (policy),
  `verify-image` (signed by your CI), `verify-chain` (untampered).
- **Adopt your first framework** and enforce its controls:
  ```bash
  fides control import --framework SOC2
  fides control coverage                       # what's covered, what's missing
  fides control enforce --key CC7.2 --env $PROD_ENV_ID
  ```
- **Notifications**: `fides slack config …` so verdicts land in a channel.
- **Environments + drift**: snapshot what's actually running and detect shadow
  changes:
  ```bash
  fides snapshot k8s --env $PROD_ENV_ID --namespace production
  fides env verify --env $PROD_ENV_ID --server k8s-prod --tool get_pods \
    --rule '.pods[].status == "Ready"'
  ```

**What you get:** releases can't skip the baseline, evidence maps to SOC2
controls, and the portal's **Controls & Coverage** page shows coverage climbing.

---

## Large / regulated organizations (50+ developers)

**Goal:** multi-team isolation, segregation-of-duties, audit-ready reporting.

**Add**
- **Multiple orgs / tenants** (Postgres RLS via `app.current_org`) so teams'
  evidence is isolated.
- **Segregation of duties & four-eyes.** `change-gate` holds until the trail has
  the approvals your policy demands, and the committer can't self-approve:
  ```bash
  fides approve --trail $TRAIL_ID --role approver     # a *different* human
  fides change-gate --trail $TRAIL_ID                 # exit 2 until SoD is met
  ```
  See [segregation-of-duties](segregation-of-duties.md).
- **Logical environments** to aggregate many physical envs (e.g. all prod
  regions) for a single coverage view: `fides logical-env create|add-member`.
- **ServiceNow** as the system of record — the verdict is written back onto the
  Change Request, and Now Assist can be *grounded* on Fides evidence. See
  [servicenow-integration](servicenow-integration.md).
- **Auditor-ready exports**: per-framework reports, including NIST **OSCAL**:
  ```bash
  fides report --framework SOC2 --format oscal
  ```
- **External trust anchoring** for high-assurance trails:
  `fides anchor --trail $TRAIL_ID` (RFC3161 timestamp, independent of the DB).
- **AI in the loop**: the `fides-mcp` server lets Claude Code / Cursor / Claude
  Desktop query compliance data and read the docs in-conversation. See
  [mcp-server](mcp-server.md).

**What you get:** provable segregation of duties, tamper-evidence you can defend
in an audit, framework coverage across every environment, and the evidence layer
sitting underneath your existing ServiceNow change process.

---

## At a glance

| | Small (1–10) | Growing (10–50) | Large (50+) |
|---|---|---|---|
| **Auth** | 1 shared token | Service account per pipeline | Multi-org / RLS tenants |
| **Gates** | Warn-only, one gate | Enforced (`assert`, `verify-image`, `verify-chain`) | + `change-gate` w/ four-eyes SoD |
| **Frameworks** | — | First framework (e.g. SOC2) | Multiple; OSCAL exports |
| **Environments** | — | Snapshots + drift (`env verify`) | Logical envs, drift re-eval on change |
| **Integrations** | GitHub/GitLab CI | + Slack | + ServiceNow, MCP, RFC3161 anchor |
| **Portal use** | Watch evidence land | Track coverage climb | Auditor + exec assurance view |

Start at the left. Move right when the pain shows up — never before.

---

See also: [Getting Started](getting_started.md) · [CI/CD Gate](ci-gate.md) ·
[User Stories](user-stories.md) · [CLI Reference](cli-reference.md).
