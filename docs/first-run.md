# First run: your first hour with Fides

A step-by-step walkthrough from "I can log into the portal" to "a pipeline that
blocks a bad release." Eleven steps, in the order they have to happen.

This page starts where [Database seeding & brand-new setup](setup.md) ends: the
server is deployed and you have `PORTAL_USERNAME` / `PORTAL_PASSWORD`. If you do
not have a server yet, start at [Installation](installation.md) or
[Getting Started](getting_started.md) for the local Docker stack.

If your goal is to onboard a repository that already builds somewhere, and you
have used Fides before, skip to
[Onboarding a repository](onboarding-a-repo.md) — this page is the layer
underneath it.

## What you are building

Fides has one core loop. Every feature hangs off it:

```text
record ──▶ prove ──▶ gate ──▶ map ──▶ report
```

- **record** — your CI says what it built and attaches the evidence it already
  produces (test results, scans, SBOM).
- **prove** — the evidence is hash-linked, so you can show nobody edited it.
- **gate** — a release asks for a verdict. Exit 0 ships, exit 2 holds.
- **map** — the same evidence answers a control in SOC2, ISO 27001, DORA, and
  the rest.
- **report** — an auditor gets OSCAL, not a spreadsheet.

Steps 1–7 below get you through that loop by hand, once. Step 8 puts it in CI so
it happens on every build. Steps 9–10 extend it to runtime and to your other
systems.

## Step 1 — Log in

Open the portal and sign in with the `PORTAL_USERNAME` / `PORTAL_PASSWORD` you
set during deployment.

You land on **Overview** — the dashboard. It is empty on a fresh install, which
is expected: there is no evidence yet. The four cards across the top (tracked
artifacts, compliance pass rate, active alerts, AI evaluations) are the numbers
you will watch fill in over the next few steps.

If SSO is what you actually want, configure it under
**Settings → Infrastructure → SSO & OAuth**, and map your IdP groups to Fides
roles under **Settings → Directory & Groups**. You can come back to that; local
login is enough to finish this page.

## Step 2 — Issue a service account key

Your pipeline must not authenticate as you. Create a machine identity instead.

**Portal:** **Settings → Service Accounts** → enter a name (e.g. `ci-pipeline`),
pick a role, **Create** → **Issue key**.

Roles, in short:

| Role | Use it for |
|:--|:--|
| `Writer` | Pipelines. Can record trails, artifacts, attestations, snapshots. |
| `Auditor` | Read-only. Dashboards, exports, evidence review. |
| `Admin` | Humans who configure integrations and users. |

Same thing from the CLI:

```bash
fides service-account create --name ci-pipeline --role Writer
fides service-account issue-key --account $SA_ID --label github-actions --expires-hours 720
```

The full key is printed **once**, in the form `fides_<prefix>_<secret>`. Put it
straight into your CI secret store. If you lose it, issue a new one and revoke
the old — there is no way to read it back.

Now point your shell at the server:

```bash
export FIDES_SERVER_URL=https://fides.example.com
export FIDES_API_TOKEN=fides_...        # the key you just issued
fides flow list                          # should return [] and exit 0
```

That last command is the checkpoint. If it fails, nothing below will work — fix
the URL or the token first.

## Step 3 — Create a flow

A **flow** is one service or pipeline. A **trail** is one build of it. Every
piece of evidence hangs off a trail.

**Portal:** **Flows & Trails** → fill in **NEW FLOW** (name + description) →
**Create flow**.

Name it after the thing that builds, not the team that owns it —
`payments-api`, not `payments-squad`. You will be reading these names in gate
output at 2am.

## Step 4 — Record a build

Three commands. This is the whole developer-facing surface of Fides, and in
practice these live in your pipeline, not your terminal.

```bash
# 1. open a trail for this build
TRAIL=$(fides trail start --flow $FLOW_ID --trail $CI_SHA \
          --commit $CI_SHA --committer "$AUTHOR" --quiet)

# 2. say what the build produced — SHA256 is the artifact's identity
fides artifact report --trail $TRAIL --sha256 $DIGEST --name payments-api --type docker

# 3. attach the evidence your scanners already emit
fides attest trivy --trail $TRAIL --file trivy.json
fides attest junit --trail $TRAIL --file junit.xml
```

`fides attest` has built-in parsers for `junit`, `snyk`, `trivy`, `slsa`, and
`sbom`, so you point it at the raw report rather than hand-building JSON.

**Check it landed:** **Artifacts & SBOM** in the portal. Your artifact is there
by digest; expanding it shows the SBOM and every attestation attached.

## Step 5 — Prove the evidence is intact

```bash
fides verify-chain --trail $TRAIL      # exit 2 if the chain is broken
```

Attestations are hash-linked: each one commits to the one before it. Editing
history after the fact breaks the chain, and this command is how you show that.

For evidence that has to stand up outside your own infrastructure, anchor the
chain head to a public timestamp authority:

```bash
fides anchor --trail $TRAIL
```

That produces an RFC3161 token — third-party proof the evidence existed at a
point in time, not just your word for it.

## Step 6 — Write a policy

A **policy** is a named set of rules that decide whether a build is compliant.
Rules are jq expressions evaluated against attestation payloads.

**Portal:** **Policies** → **New Policy**. The editor has **Format** and
**Check & fix** buttons; use them, because a policy that fails to parse fails
open in ways you will not enjoy discovering later.

A starting policy that is worth having on day one:

```json
{
  "provenance": { "required": true },
  "attestations": [
    { "name": "unit-tests", "type": "junit",
      "rules": [".failures == 0", ".errors == 0"] },
    { "name": "vuln-scan", "type": "vulnerability-scan",
      "rules": [".vulnerabilities.critical == 0"] },
    { "name": "secret-scan", "type": "secret-scan",
      "rules": [".leaks == 0"] }
  ]
}
```

Check an artifact against it directly:

```bash
fides assert --sha256 $DIGEST --policy no-critical-vulns    # exit 2 if non-compliant
```

You can also have an LLM draft a first policy from your existing evidence with
`fides policy generate`, then edit it. Read what it writes before saving it.

## Step 7 — Ask for a verdict

```bash
fides change-gate --trail $TRAIL       # exit 0 = ship, exit 2 = HOLD
```

This is the command CI runs, and **the exit code is the entire integration** —
your job either fails or it doesn't. The verdict combines policy results,
evidence completeness, and a 0–100 risk score.

Adopting Fides on a pipeline people already depend on? Run it in `warn-only`
first so it reports without blocking. See [CI/CD Gate](ci-gate.md). Turning the
gate on hard, on day one, on a pipeline whose evidence you have not looked at
yet, is how a rollout dies in week two.

## Step 8 — Map it to a framework

Now the compliance half of the loop, using exactly the evidence you already
recorded:

```bash
fides control import --framework SOC2     # ISO27001, NIST-800-53, PCI-DSS, DORA, PSD2, SOX, SLSA, CRA
fides control coverage                    # control-by-control evidence + per-environment coverage
fides report --framework SOC2 --format oscal > soc2.json
```

**Portal:** **Controls & Coverage** groups controls by framework and shows
coverage per environment. Expanding a control tells you which evidence type it
requires and which environments actually enforce it — which is where you find
out that the control you thought was covered is covered in dev only.

## Step 9 — Put it in CI

Everything above, in a pipeline. The full GitHub Actions and GitLab CI
templates are in [CI/CD Gate](ci-gate.md); the shape is:

```yaml
- name: Record build evidence
  env:
    FIDES_SERVER_URL: ${{ vars.FIDES_SERVER_URL }}
    FIDES_API_TOKEN:  ${{ secrets.FIDES_API_TOKEN }}
  run: |
    TRAIL=$(fides trail start --flow $FLOW_ID --trail $GITHUB_SHA \
              --commit $GITHUB_SHA --committer "$GITHUB_ACTOR" --quiet)
    fides artifact report --trail $TRAIL --sha256 $DIGEST --name app --type docker
    fides attest trivy --trail $TRAIL --file trivy.json
    fides attest junit --trail $TRAIL --file junit.xml
    fides change-gate --trail $TRAIL          # exit 2 fails the job
```

`FIDES_SERVER_URL` is a variable; `FIDES_API_TOKEN` is a secret. Keep it that
way — the URL is not sensitive and making it a secret only makes your logs
harder to read.

## Step 10 — Connect a runtime environment

Recording what you built answers half the question. The other half is whether
that is what is actually running.

**Portal:** **Environments** → **Advanced — custom check & add connection**.
Fides connects to the environment's MCP servers (e.g. the in-cluster
`fides-mcp-sensor`) and runs runtime compliance checks itself.

```bash
fides snapshot k8s --env $ENV_ID --namespace production
fides env diff --env $ENV_ID            # drift between snapshots
fides env verify --env $ENV_ID --server k8s-prod --tool get_pods \
  --rule '.pods[].status == "Ready"'    # exit 2 = runtime non-compliant
```

An environment showing **DRIFT** with shadow changes usually means one of two
things: CI is not recording digests by value, or third-party images are not
allowlisted. Both are covered in
[Onboarding a repository](onboarding-a-repo.md).

Images you do not build need explicit approval, or the environment can never go
green:

```bash
fides allowlist add --env $ENV_ID --sha $DIGEST --reason "vendor base image, reviewed 2026-08-20"
```

## Step 11 — Wire in the systems you already use

All under **Settings**, all optional, all safe to defer past your first hour:

| Tab | What it gets you |
|:--|:--|
| **ServiceNow** | Change requests carry evidence; verdicts file as GRC control tests. See [ServiceNow Integration](servicenow-integration.md). |
| **Slack** | Real-time alerts when a build fails a policy or an environment drifts. |
| **Git & Webhooks** | Commit-status checks back onto PRs; signed outbound webhooks to your own automation. |
| **Directory & Groups** | Map IdP groups to Fides roles, so access is managed in your directory rather than per-user here. |
| **Infrastructure** | Evidence storage (S3/GCS/Azure), secret engines, and the LLM used for AI audits. |

Integration credentials are stored by **reference** (`fides/servicenow`,
`fides/slack-webhook`), not by value — the secret itself lives in your secrets
backend. See [AWS Secrets Manager](aws-secrets-manager.md).

## Where to go next

| You want to… | Read |
|:--|:--|
| Add a control of your own | [Adding a control](adding-controls.md) |
| See the whole feature surface | [Features](features.md) |
| Find the command for a task | [CLI Reference](cli-reference.md) |
| Onboard an existing repo properly | [Onboarding a repository](onboarding-a-repo.md) |
| Record provenance from CI | [Recording build provenance from CI](ci-provenance.md) |
| Enforce four-eyes / SoD | [Segregation of Duties](segregation-of-duties.md) |
| See it by role rather than by step | [User Stories](user-stories.md) |
| Scale from one team to many | [Small & Large Teams](teams.md) |
| Use Fides from Claude Code or Cursor | [MCP Server](mcp-server.md) |

## Troubleshooting the first hour

| Symptom | Cause | Fix |
|:--|:--|:--|
| `fides flow list` hangs or 401s | Wrong URL or a revoked/expired key | Re-check `FIDES_SERVER_URL`; issue a fresh key in Settings → Service Accounts |
| Everything returns `[]` but you know data exists | The token belongs to a different org | Org comes from the token, never from a flag — issue a key in the right tenant |
| `change-gate` holds and you cannot see why | Missing evidence, not failing evidence | `fides control coverage` shows which required evidence type is absent |
| Environment permanently shows DRIFT | Third-party images not allowlisted | `fides allowlist add` for each, with a reason |
| Every runtime digest is a shadow change | CI records tags, not digests | Record the digest by value in `artifact report` |
| Policy saves but never fails anything | jq rule matches nothing | Use **Check & fix** in the policy editor; a rule over an absent field is not a failure |

A note on that third row, because it catches most people: Fides distinguishes
*failing* evidence from *absent* evidence, and holds on both. A gate that holds
on a build with no scans attached is working correctly.
