# Scanner → Fides: record SCA/vuln scans as evidence and gate on them

Fides is a **compliance & provenance ledger + gate**, not a scanner. It does not
walk source trees, build dependency graphs, or maintain a vulnerability database.
Instead it **records** what a scanner found as tamper-evident evidence, and
**gates** deploys on policy over that evidence.

So the pattern is: **your scanner produces → `fides attest` records → `fides assert`
(or the [Fides Gate action](ci-gate.md)) gates.** This needs *no new Fides code* —
every piece already exists.

## What Fides ingests

`fides attest <format> --file <report>` understands: `junit`, `snyk`, `trivy`,
`sarif`, `slsa`, `sbom` (CycloneDX **and** SPDX, auto-detected). That covers the
common scanners directly or via SARIF/SBOM:

| Scanner | Emit | Record with |
|---------|------|-------------|
| Trivy | `trivy image -f json` | `fides attest trivy --file report.json` |
| Grype | `grype -o sarif` | `fides attest sarif --file report.sarif` |
| Snyk | `snyk test --json` | `fides attest snyk --file report.json` |
| Syft | `syft -o cyclonedx-json` / `spdx-json` | `fides attest sbom --file sbom.json` |
| Bomly | `bomly scan -o cyclonedx=sbom.cdx.json` | `fides attest sbom --file sbom.cdx.json` |

Recorded vuln scans also feed the **CVE → environment impact** index
(`fides impact --cve CVE-2021-44228`) and VEX suppression — things a one-shot
scanner can't answer across your whole estate.

## The gate

A policy rule evaluates a JQ expression against the recorded scan payload, e.g.
`.critical == 0` or `.high <= 2`. Two ways to gate in CI:

- **`fides assert --sha256 <artifact> --policy <name>`** — evaluates the artifact's
  recorded evidence against a named policy; exits non-zero to fail the step.
- **[Fides Gate action](ci-gate.md) `change-gate`** — the evidence-backed approval
  verdict for the whole trail (includes recorded-scan compliance); exits `2` on hold.

---

## GitHub Actions — full recipe

```yaml
name: Build, scan, record, gate
on: [pull_request]

env:
  FIDES_SERVER_URL: ${{ vars.FIDES_SERVER_URL }}
  FIDES_API_TOKEN:  ${{ secrets.FIDES_API_TOKEN }}

jobs:
  supply-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      # 1. Build your image and capture its digest.
      - id: build
        run: |
          IMAGE=ghcr.io/${{ github.repository }}:${{ github.sha }}
          docker build -t "$IMAGE" .
          echo "digest=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE" | cut -d@ -f2)" >> "$GITHUB_OUTPUT"

      # 2. Scan with Trivy (SCA + vulns) and Syft (SBOM).
      - run: |
          trivy image --format json --output trivy.json ghcr.io/${{ github.repository }}:${{ github.sha }}
          syft ghcr.io/${{ github.repository }}:${{ github.sha }} -o cyclonedx-json > sbom.json

      # 3. Get the fides CLI (via the released binary — same as the Gate action).
      - run: |
          ver=$(curl -fsSL https://api.github.com/repos/olafkfreund/fides/releases/latest | jq -r .tag_name)
          base="fides_${ver}_linux_amd64"
          curl -fsSL "https://github.com/olafkfreund/fides/releases/download/${ver}/${base}.tar.gz" | tar -xz
          echo "$PWD/${base}" >> "$GITHUB_PATH"

      # 4. Record the scans as evidence on the trail.
      - run: |
          fides attest trivy --file trivy.json --trail "$TRAIL_ID"
          fides attest sbom  --file sbom.json  --artifact-sha "${{ steps.build.outputs.digest }}" --trail "$TRAIL_ID"

      # 5. Gate: fail the PR if the artifact violates policy.
      - run: fides assert --sha256 "${{ steps.build.outputs.digest }}" --policy no-critical-vulns
```

## GitLab CI — full recipe

```yaml
stages: [build, scan, gate]

variables:
  FIDES_SERVER_URL: "$FIDES_SERVER_URL"   # set FIDES_API_TOKEN as a masked variable

.fides-cli: &fides-cli
  - ver=$(curl -fsSL https://api.github.com/repos/olafkfreund/fides/releases/latest | jq -r .tag_name)
  - base="fides_${ver}_linux_amd64"
  - curl -fsSL "https://github.com/olafkfreund/fides/releases/download/${ver}/${base}.tar.gz" | tar -xz
  - export PATH="$PWD/${base}:$PATH"

scan-and-record:
  stage: scan
  image: aquasec/trivy:latest
  script:
    - trivy image --format json --output trivy.json "$IMAGE@$DIGEST"
    - apk add --no-cache curl jq tar
    - *fides-cli
    - fides attest trivy --file trivy.json --trail "$TRAIL_ID"

policy-gate:
  stage: gate
  image: alpine:3.20
  script:
    - apk add --no-cache curl jq tar
    - *fides-cli
    - fides assert --sha256 "$DIGEST" --policy no-critical-vulns
```

## Defining the policy

```bash
# A rule that fails the gate on any critical vulnerability in a recorded scan.
fides policy add --env prod --name no-critical-vulns --rule '.critical == 0'
```

### License policy

A recorded SBOM attestation summarizes its licenses (`ParseSBOM` populates
`summary.licenses` — unique, sorted — and `summary.unlicensed`), so you can gate
on them with a JQ rule:

```bash
# Allow-list: fail if any component uses a license outside the allowed set.
fides policy add --env prod --name allowed-licenses \
  --rule '(.summary.licenses - ["MIT","Apache-2.0","BSD-3-Clause"]) | length == 0'

# Or: fail if any component is unlicensed.
fides policy add --env prod --name no-unlicensed --rule '.summary.unlicensed == 0'
```

---

## What Fides deliberately does NOT do

By design — bring these upstream (Trivy/Grype/Syft/Bomly), Fides records + gates:

- Generate SBOMs or run vulnerability enrichment / maintain a vuln DB
- Reachability analysis, dependency-graph diffing, typosquat detection
- Container-layer / source-tree scanning

See the [Fides Gate action](ci-gate.md) for the signature/approval/runtime gates
that complement this flow.

## Gate on NEW vulnerabilities only

To fail a PR only on vulnerabilities it *introduces* (not the pre-existing
backlog), diff the current scan against a baseline:

```bash
# Exits 2 if the current scan has any CRITICAL/HIGH CVE not in the baseline.
fides vuln diff baseline-trivy.json current-trivy.json --format trivy --fail-on-new
```

Produce `baseline-trivy.json` from the merge base (or the last release) and
`current-trivy.json` from the PR head. Works with `--format trivy|snyk|sarif`.

## Related enhancements

- `fides assert` now exits `2` on non-compliance and is a first-class
  [Fides Gate action](ci-gate.md) command (`command: assert`), so the policy gate
  in the recipes above can run as the action instead of a raw step.
- License-policy gating is now supported via `summary.licenses` (see above);
  `fides sbom diff` compares two SBOM files today, with diffing two *recorded*
  attestations as a follow-up.
