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

Once the gate is trusted enough to block, the next question is who is allowed to
sign off on it.

> *"As a release manager, I want our deploy tool to record a sign-off without
> handing it admin over the whole tenant."*

```bash
curl -X POST "$FIDES_SERVER_URL/api/v1/tenant/service-accounts/$SA_ID/delegation" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"may_delegate_approvals": true}'
```

`may_delegate_approvals` is its own permission, default off. A `Writer`-scoped
account holding it records an approval the change gate actually counts, while
still being unable to create service accounts, rewrite controls, or register
users. `Admin` continues to work, but it is the broader grant, not the intended
one. Granting the permission stays Admin-only — holding it is not
administrative, handing it out is.

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

Evidence can also be pushed into the GRC tool your auditors already live in.

> *"As a compliance owner, I want our release verdicts to land in ServiceNow GRC
> as control tests, not just as change requests."*

Enable the GRC sink and each trail verdict files as a control test against the
matching ServiceNow control, resolved by evidence type. Fides seeds its own
control catalogue on first run, so there is nothing to map by hand. See
[servicenow-integration.md](servicenow-integration.md).

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

> *"As an SRE, I want to approve a third-party image by name, without digging its
> digest out of a pod's `imageID` by hand."*

```bash
fides allowlist add --env $PROD_ENV --image ghcr.io/vendor/base:3.1 \
  --reason "vendor base image, reviewed 2026-08-20"
```

`--image` resolves the reference against the registry and approves the digest it
resolves to (for a multi-arch tag, the index digest — which is what a runtime
actually reports). The approval is still per-digest, so a vendor bump needs a new
entry; Fides reports that as an **upgrade of an approved image** rather than an
unknown one, so you can tell a routine bump from a genuine shadow change.

`--reason` is mandatory on purpose: an allowlist entry is an accepted risk, and
one with no stated reason cannot be re-evaluated later by anyone, including the
person who added it.

> *"As an SRE, I want a retired cluster to stop dragging our compliance numbers
> down."*

```bash
fides env archive   --env $ENV_ID     # retire it from the picture
fides env unarchive --env $ENV_ID     # put it back
```

Control coverage divides by the number of live environments, so every
environment that ever existed counts until it is archived. A CI suite that
creates one per run and deletes none will lower every control's coverage
week after week for reasons that have nothing to do with compliance.

Archiving is not deleting, deliberately: the environment keeps its snapshots,
policies and allow-lists and still resolves by id, so anything pointing at it
goes on working. An environment owns evidence, and evidence is not deleted to
improve a percentage.

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

> *"As a security engineer, I want to gate on vulnerabilities this change
> introduced, not on the backlog we already knew about."*

```bash
fides vuln diff base-scan.json current-scan.json --format trivy --fail-on-new
```

Exits 2 only when a CVE appears that was not in the baseline. Gating on a total
count means the gate is red from the day you turn it on and everyone learns to
ignore it; gating on the delta means red always means "this change did that".

Same shape for dependencies:

```bash
fides sbom diff old-bom.json new-bom.json     # added, removed, version-changed
```

Both read local files and never contact a server, so they run before anything
has been recorded.

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

```text
Developer records ──▶ evidence chain ──▶ Release Mgr gates ──▶ SRE verifies runtime
     │                     │                    │                      │
     └── Security policies ─┴── Compliance maps to frameworks ─┴── Exec sees it live
```

Everyone works off the **same evidence**. Recording it once (the developer's
three commands) is what makes every other story possible.

See also: [First run](first-run.md) · [Teams guide](teams.md) · [CI/CD Gate](ci-gate.md) ·
[Getting Started](getting_started.md) · [CLI Reference](cli-reference.md).
