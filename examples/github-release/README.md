# Fides release example (golden path)

A complete, copy-pasteable GitHub Actions pipeline that takes a build all the way
through **Fides**: record provenance, attach evidence, gate the release on an
evidence-backed verdict, deploy with a recorded approval, and snapshot the
runtime so drift is detected afterwards.

> This example does **not** run inside the fides repo — it lives under
> `examples/` and GitHub only runs workflows at the repo root. Copy
> `.github/workflows/fides-release.yml` into your own repo.

## What it demonstrates

| Step | Command / Action | Control (see `fides control catalog`) |
|------|------------------|----------------------------------------|
| Start a trail (records committer identity) | `fides trail start` | Version Control (FIDES-CTRL-0001) |
| Record artifact provenance | `fides artifact report` | Artifact Provenance (FIDES-CTRL-0002) |
| Attach SBOM | `fides attest sbom` | Software Bill of Materials (FIDES-CTRL-0003) |
| Attach vulnerability scan | `fides attest trivy` | Vulnerability Scanning (FIDES-CTRL-0008) |
| Record code authorship | `fides attest authorship` | Peer Review / Four-Eyes (FIDES-CTRL-0005) |
| Gate the release | `fides-gate` action (`change-gate`) | Deployment Approval Gate (FIDES-CTRL-0006) |
| Record deployer sign-off | `fides approve --role deployer` | Segregation of Duties (FIDES-CTRL-0007) |
| Snapshot the runtime | `fides snapshot k8s` | Runtime Snapshot & Drift Detection (FIDES-CTRL-0009) |

The install + gate use the reusable actions:
`setup-fides` (`.github/actions/setup-fides`) and `fides-gate` (`.github/actions/fides-gate`).

## Setup (once, in the consuming repo)

1. **Secret** `FIDES_API_TOKEN` — a Fides API token.
2. **Variables**:
   - `FIDES_SERVER_URL` — e.g. `https://fides.example.com`
   - `FIDES_FLOW_ID` — the flow UUID. Create a flow once (portal, or `fides flow create`) and copy its id from `fides flow list`.
   - `FIDES_ENV_ID` — (optional) the environment UUID to snapshot (`fides env create --name prod --type k8s`).
3. (Recommended) Import a control framework so the gate has controls to evaluate:
   `fides control import --framework SOC2`.

## The human approver (four-eyes)

The `change-gate` **holds** until controls pass **and** a human approver has
signed off. That sign-off is a *person* running `fides approve --role approver`
with a **session** token (e.g. from the portal) — deliberately distinct from the
CI service-account token. The pipeline's `deploy` job also sits behind the
GitHub `production` environment's required reviewers as a second human gate.

## Files

- `.github/workflows/fides-release.yml` — the pipeline.
- `app/` — a trivial sample artifact (an Alpine image) so the build step has
  something to fingerprint. Replace with your real build.

> ✅ Proven live in `olafkfreund/fides-release-demo` against https://fides.freundcloud.org.uk.
