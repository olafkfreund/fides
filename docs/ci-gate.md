# Fides Gate — CI/CD action for GitHub & GitLab

Gate any pipeline on a **Fides compliance & provenance verdict** before it merges or
deploys. The action is a thin wrapper around the `fides` CLI: it downloads the
released binary, runs one gate command, and fails the job when the verdict is a
violation (the CLI exits `2`). No scanner, no server-side changes — it reuses the
gate commands Fides already ships.

- **GitHub Action:** [`.github/actions/fides-gate`](../.github/actions/fides-gate)
- **GitLab template:** [`ci/gitlab/fides-gate.yml`](../ci/gitlab/fides-gate.yml)

Both take the same inputs and share identical download → checksum-verify → run →
gate logic.

## Setup (once)

Store two secrets/variables in your CI project:

| Name | Value |
|------|-------|
| `FIDES_API_TOKEN` | A Fides service-account token (masked/secret). |
| `FIDES_SERVER_URL` | Your Fides server, e.g. `https://fides.example.com`. |

The gate commands and their exit codes:

| `command` | What it proves | Exits `2` when |
|-----------|----------------|----------------|
| `change-gate` | Evidence-backed approval verdict + risk score for a trail | Verdict is *hold* (missing approvals, four-eyes/SoD not met, risk too high) |
| `verify-image` | A container image's cosign signature (keyless or key-based) | Signature missing/untrusted |
| `verify-chain` | A trail's tamper-evidence chain (incl. external RFC3161 anchor) | Chain broken / tampered |
| `env-verify` | Live runtime matches a compliance rule (via the runtime MCP sensor) | Runtime is non-compliant |

---

## User stories

### 1. "As a release manager, block the deploy unless the image is signed by our CI"

Prove the artifact you're about to ship carries a valid keyless cosign signature
from your own GitHub Actions workflow — otherwise fail.

**GitHub**
```yaml
name: Deploy gate
on: [deployment]
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: olafkfreund/fides/.github/actions/fides-gate@v0.3.0
        with:
          command: verify-image
          server-url: ${{ vars.FIDES_SERVER_URL }}
          api-token: ${{ secrets.FIDES_API_TOKEN }}
          sha256: ${{ github.event.deployment.payload.image_digest }}
          signer: "https://github.com/${{ github.repository }}/.github/workflows/build.yml@refs/heads/main"
          issuer: "https://token.actions.githubusercontent.com"
          trail: ${{ env.TRAIL_ID }}   # optional: records the verdict as evidence
```

**GitLab**
```yaml
include:
  - remote: 'https://raw.githubusercontent.com/olafkfreund/fides/main/ci/gitlab/fides-gate.yml'
    inputs:
      command: verify-image
      sha256: "$IMAGE_DIGEST"
      signer: "$CI_PROJECT_URL//.gitlab-ci.yml@refs/heads/main"
      issuer: "https://gitlab.com"
```

### 2. "As a compliance owner, require four-eyes / segregation-of-duties before merge"

`change-gate` returns *hold* until the trail has the approvals your policy demands
(and the author can't self-approve). Wire it into the PR/MR pipeline.

**GitHub**
```yaml
- uses: olafkfreund/fides/.github/actions/fides-gate@v0.3.0
  with:
    command: change-gate
    server-url: ${{ vars.FIDES_SERVER_URL }}
    api-token: ${{ secrets.FIDES_API_TOKEN }}
    trail: ${{ env.TRAIL_ID }}
```

**GitLab**
```yaml
include:
  - remote: 'https://raw.githubusercontent.com/olafkfreund/fides/main/ci/gitlab/fides-gate.yml'
    inputs:
      command: change-gate
      trail: "$TRAIL_ID"
```

### 3. "As an SRE, don't promote to prod unless the live runtime is compliant"

`env-verify` asks the runtime MCP sensor a question about the actual cluster and
fails if the answer breaks the rule.

```yaml
- uses: olafkfreund/fides/.github/actions/fides-gate@v0.3.0
  with:
    command: env-verify
    server-url: ${{ vars.FIDES_SERVER_URL }}
    api-token: ${{ secrets.FIDES_API_TOKEN }}
    env: ${{ vars.PROD_ENV_ID }}
    mcp-server: k8s-prod
    tool: list_pods
    rule: '.pods[].status == "Ready"'
```

### 4. "As an auditor, prove the evidence chain wasn't tampered with"

Run `verify-chain` in a nightly/pre-audit pipeline; it also checks the external
RFC3161 timestamp anchor.

```yaml
- uses: olafkfreund/fides/.github/actions/fides-gate@v0.3.0
  with:
    command: verify-chain
    server-url: ${{ vars.FIDES_SERVER_URL }}
    api-token: ${{ secrets.FIDES_API_TOKEN }}
    trail: ${{ env.TRAIL_ID }}
```

### 5. "As a team adopting Fides, warn first, enforce later"

Set `warn-only: true` (GitHub) / `warn_only: "true"` (GitLab) to surface the
verdict without failing the pipeline while you roll out.

```yaml
- uses: olafkfreund/fides/.github/actions/fides-gate@v0.3.0
  with:
    command: change-gate
    server-url: ${{ vars.FIDES_SERVER_URL }}
    api-token: ${{ secrets.FIDES_API_TOKEN }}
    trail: ${{ env.TRAIL_ID }}
    warn-only: true
```

---

## Inputs

`command` (required) plus the fields that command needs — see the table above.
Common: `server-url`, `api-token`, `version` (default `latest`), `warn-only`.
`args` is a raw escape hatch appended verbatim. Full list in
[`action.yml`](../.github/actions/fides-gate/action.yml).

## Outputs (GitHub)

- `verdict` — `pass` | `violation` | `error`
- `exit-code` — the raw CLI exit code

## Pinning & publishing

Pin to a released tag (`@v0.3.0`) for reproducibility. Referencing the action by
subpath (`olafkfreund/fides/.github/actions/fides-gate@<tag>`) works today without
the Marketplace. To publish as an official Marketplace action, mirror this
directory into a dedicated `fides-gate` repo with `action.yml` at its root.
