# Adding a control

A **control** is a named compliance requirement — "artifacts pass vulnerability
scanning", "changes are peer reviewed" — expressed as the evidence that proves
it. This page is the process for adding one, what has to be true first, and why
each step exists.

Two routes, and the first one covers most cases:

| You want | Do this |
|:--|:--|
| A control from SOC 2, ISO 27001, NIST 800-53, PCI-DSS, DORA, PSD2, SOX, SLSA or CRA | [Import the framework](#route-1-import-a-framework) — one command |
| A requirement specific to your organisation | [Define your own](#route-2-define-your-own-control) — the six steps below |

## The one idea to understand first

A control in Fides is not a description. It is a **list of evidence types**:

```text
control  SOC2-CC7.1  "Artifacts pass vulnerability scanning"
         required_types = ["trivy", "snyk"]
```

Everything else follows from that list. The control is satisfied when
attestations of those types exist and are compliant; it is *enforced* in an
environment when a policy there requires those types; and coverage is just the
count of environments where that is true.

Which leads to the rule that decides whether this works at all:

> **A control can only require evidence your pipeline already produces.**

Fides does not run scanners. It records what yours emit. Writing a control that
requires `dast-scan` when nothing in CI emits `dast-scan` does not create a
finding — it creates a control that reads 0% forever and tells you nothing.

**`required_types` is AND, not OR.** A control requiring `["trivy", "snyk"]`
needs *both*. If you mean "either scanner is acceptable", that is one type name
that both paths write, not two types.

## Prerequisites

### Technical

| # | Requirement | Why | Check it |
|:--|:--|:--|:--|
| 1 | **The evidence exists in CI** | A control is a claim about evidence. No evidence, no control. | `fides attest <parser> --trail $TRAIL --file <report>` runs green |
| 2 | **You know its exact `type_name`** | Matching is string equality — `trivy` ≠ `Trivy` ≠ `trivy-scan` | **Attestations** page, or `fides search attestations` |
| 3 | **The evidence is marked compliant** | Only `is_compliant = true` attestations satisfy a policy | The attestation shows **Compliant**, not just present |
| 4 | **An `Admin` role** | Creating and enforcing controls is admin-only | `fides service-account list` shows your role |
| 5 | **At least one environment** | Coverage is a fraction of environments; with none it is undefined | **Environments** page is not empty |

### Organisational

These are the ones that actually decide whether a control is worth having.

- **An owner.** Someone answers "why is this red?" A control nobody owns gets
  archived within a quarter.
- **A decision about failure.** When this control is not satisfied, does the
  release stop? If the answer is "we'd look into it", you want a *detective*
  control and a dashboard, not a gate.
- **Agreement on the evidence.** Auditors accept evidence, not intentions. Settle
  what artefact proves the control *before* writing it, or you will rewrite it
  after the first audit.
- **A scope.** Which environments must enforce it? "Production only" is a
  legitimate answer and is what per-environment enforcement is for.

## Route 1: import a framework

If the control belongs to a standard, do not hand-write it. Fides ships
catalogues for nine frameworks, with the evidence mappings already made:

```bash
fides control import --framework SOC2
```

Available: `SOC2`, `ISO27001`, `NIST-800-53`, `PCI-DSS`, `DORA`, `PSD2`, `SOX`,
`SLSA`, `CRA`. **Portal:** **Controls** → **Add or import controls**.

Import is idempotent, so re-running it is safe and picks up catalogue additions.
It creates the controls; it does not enforce them — that is step 5 below.

## Route 2: define your own control

### Step 1 — Find the evidence you already have

Start from evidence, not from the requirement. Open **Attestations** in the
portal and read the **type** column, or:

```bash
fides search attestations               # add --type/--trail/--compliant to narrow
```

These are the type names available to you. Common built-ins:

| `type_name` | Produced by |
|:--|:--|
| `junit` | `fides attest junit --file junit.xml` |
| `trivy` / `snyk` | `fides attest trivy` / `fides attest snyk` |
| `sbom-cyclonedx` | `fides attest sbom --file bom.json` |
| `slsa-provenance` | `fides attest slsa`, or `fides attest fetch --provider github` |
| `cosign-verification` | `fides verify-image` |
| `secret-scan` | your secret scanner, via `fides attest --type secret-scan` |
| `deployment` | recorded on deploy |
| `approval` | the change gate's sign-off |

Anything else is a custom type, which is fine — see step 2.

### Step 2 — If the evidence does not exist yet, produce it first

Add the scanner to CI and record its output *before* creating the control:

```bash
fides attest --trail $TRAIL --name license-check --type license-scan \
  --payload ./licenses.json
```

`--type` is the string your control will require. Choose it once and keep it
stable: renaming a type later silently drops every control that required the old
name to 0%, because matching is by string.

Run the pipeline once and confirm the attestation appears and reads
**Compliant**. Only then continue.

### Step 3 — Create the control

```bash
fides control add \
  --key ACME-LIC-1 \
  --name "Dependencies carry approved licences" \
  --description "No GPL-family licence in a production artifact." \
  --framework ACME \
  --require license-scan
```

**Portal:** **Controls** → **Add or import controls**.

On the fields:

- **`--key`** is the stable identifier and the primary key with your org. Use the
  standard's own numbering where one exists (`SOC2-CC7.1`), or a prefixed scheme
  of your own (`ACME-LIC-1`). Re-adding the same key **updates** the control
  rather than creating a second one — that is how you edit it, and it also
  un-archives it.
- **`--require`** is the comma-separated evidence types. This is the control.
- **`--framework`** is a free-text grouping label. It does not have to be a real
  standard; it is what the portal groups by.

> `--require` is **not validated** against known types. A typo is accepted and
> produces a control that can never be satisfied. Copy the type name from an
> existing attestation rather than typing it.

### Step 4 — Check it reads 0%, and that you know why

```bash
fides control coverage
```

A new control shows **0%** — correct, because nothing enforces it yet. If it
shows 0% *after* step 5, the cause is almost always a type-name mismatch.

### Step 5 — Enforce it where it applies

Creating a control does not apply it. Enforcing writes an environment policy
requiring its evidence types:

```bash
fides control enforce --key ACME-LIC-1 --env $PROD_ENV_ID   # one environment
fides control enforce --key ACME-LIC-1 --all-environments   # everywhere
```

**Portal:** **Controls** → expand the control → **Enforce** per environment, or
**Enforce everywhere**.

Enforce deliberately per environment when the requirement is not universal. A
licence control may belong in production and be noise in a scratch cluster.

> **Enforce everywhere** covers every environment that is not archived. If your
> environment list contains retired clusters or test fixtures, archive them
> first — otherwise coverage is diluted by environments nobody deploys to. See
> [Retiring an environment](environment-mcp-compliance.md#retiring-an-environment).

### Step 6 — Verify it actually gates

Coverage says the control is *required*. It does not say a build *passes*. Prove
the loop closes:

```bash
fides policy check --env $PROD_ENV_ID --trail $TRAIL   # exit 2 if evidence is missing
```

Then run it against a trail that is deliberately missing the evidence and
confirm it exits 2. **A control that cannot fail is not a control.**

## How the pieces connect

```text
CI emits a report
   └─ fides attest --type license-scan ────────▶ attestation (type_name, is_compliant)
                                                          │
control ACME-LIC-1  required_types=[license-scan]         │
   └─ fides control enforce ──▶ environment_policy        │
                                 required_types=[…]       │
                                        │                 │
                    coverage: control counts where        │
                    control.required_types ⊆ policy.required_types
                                        │                 │
                    fides policy check ─┴─────────────────┘
                    compares the policy's types against the trail's
                    COMPLIANT attestations → exit 0 or exit 2
```

Two separate questions, and it is worth keeping them apart:

- **Coverage** — is this control *required* in this environment? A property of
  configuration.
- **Policy check** — does *this build* satisfy it? A property of evidence.

A control at 100% coverage with every build failing its check is a working
setup, correctly telling you something is wrong.

## Troubleshooting

| Symptom | Cause | Fix |
|:--|:--|:--|
| Control stays 0% after enforcing | Type-name typo in `--require` | Compare against a real attestation's type; re-add the control with the same `--key` to correct it |
| Coverage lower than expected | Retired environments still in the denominator | Archive them |
| Control never fails, even on empty builds | `required_types` is empty | A control with no types cannot be enforced — re-add it with `--require` |
| Requires two scanners, only one runs | `required_types` is AND | Either emit both, or use one shared type name |
| Enforced but `policy check` passes when it should not | Evidence present but recorded non-compliant is *absent* for AND purposes — check it is actually there | Confirm the attestation exists and reads Compliant |
| Control disappeared | Archived, not deleted | **Controls** → **Archived controls** → restore |

## Retiring a control

Controls are archived, never deleted, so history survives:

```bash
fides control list                      # find the control's UUID
fides control archive --id <control-uuid>
```

Note `archive` takes `--id` (the UUID from `control list`), not `--key`.

An archived control leaves coverage and the framework report. The environment
policies it created stay behind — remove them separately if you also want the
gate to stop applying.

## See also

- [Features](features.md) — the full control and policy surface
- [CI/CD Gate](ci-gate.md) — turning a verdict into a pipeline gate
- [First run](first-run.md) — the whole loop, once, end to end
- [Environment MCP compliance](environment-mcp-compliance.md) — environments and archiving
