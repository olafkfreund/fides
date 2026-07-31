# Fides in CI — quickstart

Everything you need to wire Fides into a release pipeline: install the CLI, record
provenance and evidence, gate the deploy, and snapshot the runtime. All of it is
packaging over the `fides` CLI — no server-side changes.

## Building blocks

| Piece | What it is |
|-------|-----------|
| [`setup-fides`](https://github.com/olafkfreund/fides/tree/main/.github/actions/setup-fides) | GitHub Action that installs the `fides` CLI (checksum-verified) and adds it to `PATH` — like `actions/setup-node`. |
| [`fides-gate`](https://github.com/olafkfreund/fides/tree/main/.github/actions/fides-gate) | GitHub Action / GitLab template that runs one gate command (`change-gate`, `verify-image`, `verify-chain`, `assert`) and fails the job on a violation (exit `2`). |
| [`fides-k8s-reporter`](https://github.com/olafkfreund/fides/tree/main/charts/fides-k8s-reporter) | Helm chart: a CronJob that snapshots running workloads → drift / shadow-change detection. |
| [`terraform-aws-fides-reporter`](https://github.com/olafkfreund/fides/tree/main/terraform/fides-aws-reporter) | The AWS analogue: a scheduled Fargate task snapshotting ECS/Lambda. |

## Worked examples (copy-paste)

- **GitHub Actions:** [`examples/github-release`](https://github.com/olafkfreund/fides/tree/main/examples/github-release)
- **GitLab CI:** [`examples/gitlab-release`](https://github.com/olafkfreund/fides/tree/main/examples/gitlab-release)

Both take a build through the full flow, each step mapped to a control in
`fides control catalog`:

```
trail start          → Version Control          (FIDES-CTRL-0001)
artifact report      → Artifact Provenance      (FIDES-CTRL-0002)
attest sbom          → Software Bill of Materials(FIDES-CTRL-0003)
attest trivy         → Vulnerability Scanning   (FIDES-CTRL-0008)
attest authorship    → Peer Review / Four-Eyes  (FIDES-CTRL-0005)
change-gate          → Deployment Approval Gate (FIDES-CTRL-0006)
approve --role …     → Segregation of Duties    (FIDES-CTRL-0007)
snapshot k8s         → Drift Detection          (FIDES-CTRL-0009)
```

## Minimal GitHub setup

1. Repo **secret** `FIDES_API_TOKEN`; **variables** `FIDES_SERVER_URL`,
   `FIDES_ORG_ID`, `FIDES_FLOW_ID` (create a flow once; `fides flow list`).
2. Add the workflow from `examples/github-release`.
3. Import a framework so the gate has controls: `fides control import --framework SOC2`.

```yaml
- uses: olafkfreund/fides/.github/actions/setup-fides@main
- run: |
    out=$(fides trail start --flow "${{ vars.FIDES_FLOW_ID }}" --trail "$GITHUB_SHA" --commit "$GITHUB_SHA")
    echo "TRAIL_ID=$(echo "$out" | grep -oE '"id":"[^"]+"' | head -1 | sed 's/.*"id":"//;s/"//')" >> "$GITHUB_ENV"
- uses: olafkfreund/fides/.github/actions/fides-gate@main
  with: { command: change-gate, server-url: "${{ vars.FIDES_SERVER_URL }}", api-token: "${{ secrets.FIDES_API_TOKEN }}", trail: "${{ env.TRAIL_ID }}" }
```

> **Note on the trail id:** the CLI's `--trail` takes the trail **UUID**, so capture
> the id from `trail start` and reuse it (the examples do this).

## The human approver (four-eyes)

The change-gate **holds** until controls pass **and** a human approver has signed
off — a *person* runs `fides approve --role approver` with a **session** token
(e.g. from the portal), deliberately distinct from the CI service-account token.
Gate deploys behind a GitHub environment / GitLab `when: manual` for a second
human check.

This flow is proven end-to-end in
[`olafkfreund/fides-release-demo`](https://github.com/olafkfreund/fides-release-demo).
