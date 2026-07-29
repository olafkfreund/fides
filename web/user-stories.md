# Fides User Stories

Who uses Fides, what they're trying to do, and the exact command or portal page
that does it. For the CI/CD-gate stories specifically (block a deploy, require
four-eyes in a pipeline), see **[ci-gate.md](ci-gate.md)** — this page covers the
whole lifecycle.

---

## Developer

> *"As a developer, I want my build's evidence recorded automatically, so I don't
> have to think about compliance."*

Your pipeline runs three commands; everything else is downstream of them.

```bash
fides trail start --flow $FLOW_ID --trail $CI_SHA --commit $CI_SHA --committer "$AUTHOR"
fides artifact report --org $ORG_ID --trail $CI_SHA --file image.tar --name app --type docker
fides attest trivy --trail $CI_SHA --file trivy.json     # or junit/snyk/slsa/sbom
```

**Portal:** open **Flows & Trails** → your trail shows the artifact, its SBOM,
and every scan attached to it.

> *"As a developer, I want to know if my AI-assisted change needs a human
> reviewer before it can ship."*

```bash
fides attest authorship --trail $TRAIL_ID --commit HEAD
```
AI-authored changes with no human reviewer are non-compliant, so a control
requiring `code.authorship` holds the change gate until someone reviews.

---

## Release Manager

> *"As a release manager, I want a single yes/no verdict for a release, backed by
> evidence and a risk score."*

```bash
fides change-gate --trail $TRAIL_ID     # exit 2 = HOLD, plus a 0–100 risk score
```

**Portal:** the **Assurance Console** (`/`) updates live via SSE as checks run —
compliant vs total checks, tracked artifacts, and coverage by framework.

> *"As a release manager adopting Fides, I want to see verdicts without blocking
> anyone yet."* → run any gate with `warn-only` (see [ci-gate.md](ci-gate.md)).

---

## Compliance Owner / Auditor

> *"As a compliance owner, I want our evidence mapped to a framework and an
> export I can hand to an auditor."*

```bash
fides control import --framework SOC2        # or ISO27001, NIST-800-53, PCI-DSS, DORA, PSD2, SOX, SLSA, CRA
fides control coverage                       # control-by-control evidence + env coverage
fides report --framework SOC2 --format oscal # NIST OSCAL assessment-results JSON
```

**Portal:** **Controls & Coverage** shows grouped controls, drill-down, and
coverage %; **Attestations** filters to compliant evidence.

> *"As an auditor, I want proof the evidence wasn't altered after the fact."*

```bash
fides verify-chain --trail $TRAIL_ID    # exit 2 if broken; reports RFC3161 anchor status
fides audit --trail $TRAIL_ID --output audit.zip
```

> *"As a compliance owner, I want to enforce segregation of duties (four-eyes)."*
> → see [segregation-of-duties.md](segregation-of-duties.md); `change-gate`
> holds until committer ≠ approver ≠ deployer.

---

## SRE / Platform Engineer

> *"As an SRE, I want to know if what's running in prod is what we actually
> shipped — and catch shadow changes."*

```bash
fides snapshot k8s --env $PROD_ENV_ID --namespace production
fides env verify --env $PROD_ENV_ID --server k8s-prod --tool get_pods \
  --rule '.pods[].status == "Ready"'          # exit 2 = runtime non-compliant
fides env diff --env $PROD_ENV_ID              # drift between snapshots
```

**Portal:** **Environments** shows the inventory; **Telemetry** shows uptime and
DORA/runtime metrics.

> *"As a platform engineer, I want DORA metrics without a separate tool."*

```bash
fides metrics                                  # deploy freq, change-fail rate, lead time, MTTR
fides metrics deployment-frequency --weeks 12
```

---

## Security Engineer

> *"As a security engineer, I want to block releases whose scans break policy,
> and know the blast radius of a new CVE."*

```bash
fides assert --sha256 $DIGEST --policy no-critical-vulns   # exit 2 if non-compliant
fides impact --cve CVE-2026-12345                          # which artifacts + running envs are hit
fides vex --cve CVE-2026-12345 --status not_affected --product $DIGEST  # suppress false positives
```

> *"As a security engineer, I want to prove an image was signed by our own CI."*

```bash
fides verify-image --sha256 $DIGEST \
  --signer "https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main" \
  --issuer "https://token.actions.githubusercontent.com" --trail $TRAIL_ID
```

---

## AI / ML Lead

> *"As an ML lead, I want EU AI Act provenance for our models on the same
> tamper-evident rails as our software."*

```bash
fides model register --flow $MODEL_FLOW --version 1.4.0 --risk-category high --purpose "credit scoring"
fides model attest --trail $MODEL_TRAIL --kind bias-audit --summary "no disparate impact" --compliant
fides model inference-log --trail $MODEL_TRAIL --input-file req.json --decision approve --confidence 0.92
fides model timeline --trail $MODEL_TRAIL
```

Model versions are trails; training/eval/audit and inference events are
attestations — so they inherit `verify-chain`, `audit`, and retention.

**Portal:** **AI Audits** renders LLM compliance assessments with a score.

---

## Executive / Risk

> *"As a risk owner, I want a live, at-a-glance view of delivery assurance."*

**Portal:** the **Assurance Console** (`/`) is the exec view — live check stream,
compliant-check ratio, tracked artifacts, integration health, and a coverage
donut segmented by framework. No CLI required.

---

## How the personas connect

```
Developer records ──▶ evidence chain ──▶ Release Mgr gates ──▶ SRE verifies runtime
     │                     │                    │                      │
     └── Security policies ─┴── Compliance maps to frameworks ─┴── Exec sees it live
```

Everyone works off the **same evidence**. Recording it once (the developer's
three commands) is what makes every other story possible.

See also: [Teams guide](teams.md) · [CI/CD Gate](ci-gate.md) ·
[Getting Started](getting_started.md) · [CLI Reference](cli-reference.md).
