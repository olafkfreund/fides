# Fides release example — GitLab CI (golden path)

The GitLab twin of `../github-release`: a complete `.gitlab-ci.yml` that takes a
build through **Fides** — provenance, evidence, change-gate, approved deploy, and
a runtime snapshot.

Copy `.gitlab-ci.yml` into your own project (adjust the `examples/gitlab-release/app`
build path to your app).

## What it demonstrates

| Stage | Command | Control (`fides control catalog`) |
|-------|---------|-----------------------------------|
| Start trail (committer identity) | `fides trail start` | FIDES-CTRL-0001 Version Control |
| Artifact provenance | `fides artifact report` | FIDES-CTRL-0002 Artifact Provenance |
| SBOM | `fides attest sbom` | FIDES-CTRL-0003 SBOM |
| Code authorship | `fides attest authorship` | FIDES-CTRL-0005 Peer Review |
| Change-gate | `fides change-gate` | FIDES-CTRL-0006 Deployment Approval |
| Deployer sign-off | `fides approve --role deployer` | FIDES-CTRL-0007 Segregation of Duties |
| Runtime snapshot | `fides snapshot k8s` | FIDES-CTRL-0009 Drift Detection |

## Setup (Project → Settings → CI/CD → Variables)

- `FIDES_API_TOKEN` (masked) — a Fides API token
- `FIDES_SERVER_URL` — e.g. `https://fides.example.com`
- `FIDES_ORG_ID` — your Fides org UUID
- `FIDES_FLOW_ID` — flow UUID (`fides flow list`)
- `FIDES_ENV_ID` — (optional) environment UUID to snapshot

## Notes

- The **gate** job runs `fides change-gate` inline. You can instead `include` the
  reusable template shipped in this repo:
  ```yaml
  include:
    - remote: 'https://raw.githubusercontent.com/olafkfreund/fides/main/ci/gitlab/fides-gate.yml'
      inputs: { args: "change-gate --trail $CI_COMMIT_SHA", server-url: "$FIDES_SERVER_URL" }
  ```
- **Deploy is `when: manual`** so a human triggers it (four-eyes). The change-gate
  itself also holds until a human approver has signed off with a session token —
  distinct from the CI service-account token.
