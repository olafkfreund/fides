# Onboarding a repository onto Fides

What has to exist before a project's builds and its running environment mean
anything to Fides, in the order it has to exist.

Written from doing it for the first external repository — DORA Dashboard, onto
the AWS instance, on 2026-08-14. Every command here was run; the failures
described are the ones that actually happened, not anticipated ones.

If you only want to add provenance to a pipeline that is already onboarded, you
want [Recording build provenance from CI](ci-provenance.md) instead. This page
is the layer underneath it.

## The shape of it

Four things have to line up, and a verdict is meaningless unless all four do:

1. **A flow and an environment** exist in Fides for this project.
2. **CI records what it built** — the digest, by value, on a trail.
3. **Something reports what is running** — the reporter, in the target cluster.
4. **Images the project does not build are allowlisted**, or the environment
   can never be compliant no matter what CI does.

Miss (2) and every runtime digest is a shadow change. Miss (3) and there is
nothing to compare against. Miss (4) and the third-party images sit there
permanently red. A verdict that cannot go green carries exactly as much
information as one that is always green.

## 1. Create the flow and the environment

Both are one API call. Keep the IDs — you need the flow ID in CI and the
environment ID in the reporter.

```bash
export FIDES_SERVER_URL=https://fides.example.internal
export FIDES_API_TOKEN=...      # see "Credentials" below

curl -sS -X POST -H "Authorization: Bearer $FIDES_API_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"my-service","description":"One trail per commit, built by .github/workflows/deploy.yml"}' \
     "$FIDES_SERVER_URL/api/v1/flows"

curl -sS -X POST -H "Authorization: Bearer $FIDES_API_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"my-service-prod","type":"K8S","description":"EKS my-cluster, namespace my-ns"}' \
     "$FIDES_SERVER_URL/api/v1/environments"
```

One environment per **deployment target**, not per project. A namespace on one
cluster is one environment; the same app in staging is a different one.

## Credentials

Prefer a service account over the shared token. The static `FIDES_API_TOKEN`
the server is configured with is `Admin` and org-wide, so handing it to a
project's CI grants that CI everything.

```bash
fides service-account create --name my-service-ci        # -> {"id": "...", "role": "Writer"}
fides service-account issue-key --account <id>           # shown ONCE
```

`Writer` is the right role for CI: it can record trails, artifacts and
attestations, and manage the allowlist, but not administer the org.

> Service-account keys were broken on RLS-enabled deployments before v0.5.1 —
> the pre-auth lookup ran before the tenant was known and matched nothing, so
> every key returned `401 invalid credentials`. If you are on an older server,
> either upgrade or fall back to the shared token. Fixed by applying
> `schema-rls.sql` on boot; see the v0.5.1 notes.

## 2. Record what CI builds

The pipeline needs three settings. Gate every Fides step on all three being
present so a fork or a fresh clone stays green:

| setting | kind | value |
|---|---|---|
| `FIDES_SERVER_URL` | secret | the server URL |
| `FIDES_API_TOKEN` | secret | the service-account key |
| `FIDES_FLOW_ID` | variable | the flow UUID (not a credential) |

Secrets and variables cannot be read in a step-level `if:`, so expose them as
job-level `env:` and gate on `env.*`.

The recording itself, placed **after** whatever gates the build (CVE scan,
signing) so a digest only enters the vault once it has passed everything:

```bash
trail_id="$(fides trail start --flow "${FIDES_FLOW_ID}" --trail "${GITHUB_SHA}" \
  --repository "${REPO_URL}" --commit "${GITHUB_SHA}" --committer "${COMMITTER}" --quiet)"

fides artifact report --trail "${trail_id}" --sha256 "${DIGEST#sha256:}" \
  --name my-service --type docker
```

### Register the per-platform digests too

This is the step everyone misses, and it is not optional.

`docker/build-push-action` returns the **index** digest, and the index carries
a provenance attestation that embeds the commit. A rebuild whose image content
is byte-identical therefore gets a **new index digest** — while containerd,
which already holds that content, keeps reporting the index digest it first
resolved. The runtime then reports a digest CI never registered, and the
environment shows a shadow change forever.

```bash
docker buildx imagetools inspect "${IMAGE}@${DIGEST}" --raw \
  | jq -r '.manifests[]? | select(.platform.os != "unknown") | .digest' \
  | while read -r child; do
      fides artifact report --trail "${trail_id}" --sha256 "${child#sha256:}" \
        --name my-service --type docker
    done
```

Register both and whichever one the runtime reports is known.

### Do not put a gate before the recording

If the pipeline also verifies signatures with `fides verify-image`, run it
**last**. A gate placed before the recording it guards destroys the evidence it
exists to certify: when verification failed mid-step on the Fides pipeline
itself, it took out the platform-digest registration and the deploy with it.

Record everything, then gate.

## 3. Report what is running

Install the reporter into the **target** cluster — the one the workload runs
in, which is usually not the one Fides runs in.

```bash
kubectl -n my-ns create secret generic fides-reporter-token --from-literal=token="$KEY"

helm upgrade --install fides-reporter charts/fides-k8s-reporter --namespace my-ns \
  --set serviceAccount.permissionScope=namespace \
  --set fides.namespace=my-ns \
  --set fides.serverUrl="$FIDES_SERVER_URL" \
  --set fides.environmentId=<environment-uuid> \
  --set image.tag=<commit-sha>
```

Two things worth being deliberate about:

- **`permissionScope=namespace`.** The default is cluster-wide, which makes the
  reporter report every workload on the cluster into one environment. On a
  shared cluster that produced 78 shadow changes for a single app.
- **`image.tag` is required in practice.** The chart's `appVersion` is not a
  published tag, so leaving `tag` empty resolves to an image that does not
  exist and the pod sits in `ImagePullBackOff` with `NotFound`. Pin a commit
  SHA; it is immutable, which is what a compliance system wants anyway.

Trigger one immediately rather than waiting for the schedule:

```bash
kubectl -n my-ns create job --from=cronjob/fides-reporter-fides-k8s-reporter check
kubectl -n my-ns logs job/check
```

## 4. Allowlist what the project does not build

Anything running that your CI did not produce — a database, an ingress
controller, the reporter itself — will never have a registered artifact. Those
are approved, not built:

```bash
fides allowlist add --env <environment-uuid> --sha <64-hex-digest>
```

Use the **running** digest, not the tag:

```bash
kubectl -n my-ns get pods -o jsonpath='{range .items[*]}{.status.containerStatuses[*].imageID}{"\n"}{end}'
```

Note that an allowlist entry approves one digest. Upgrading an allowlisted
image means approving the new digest — the environment correctly goes red in
between, because a new unapproved image genuinely is a change.

## What "done" looks like

```json
{"compliant": true, "drifts": null, "shadow_changes": null}
```

and on the trail:

```json
{"name": "<commit>", "compliant": true, "attestations": 2}
```

If it is not green, work the four numbered items above in order. The verdict
tells you which one is missing: unregistered digests mean (2), no snapshot at
all means (3), and a shadow for an image you do not build means (4).

## Failures worth expecting

These all happened during the first onboarding.

**The deploy pipeline had never succeeded.** Cloud credentials were absent —
the repo had no secrets at all, while the deploy workflow had been switched on.
Check that the pipeline you are adding evidence to actually runs before adding
evidence to it.

**Turning on the CVE gate failed the build.** It had been `exit-code: "0"`, so
8 fixable CVEs had been shipping in every image while the pipeline signed it
and attested an SBOM to it. Expect the first enforced run to fail, and treat
that as the gate working rather than as a regression.

**Tests existed and had never run.** Verify what the pipeline actually executes
rather than what `package.json` offers.

**A tag was recorded as a digest.** Before v0.5.1 the snapshot fell back to the
image reference and truncated it to 64 characters, producing a shadow change no
allowlist entry could match. If you see a "digest" with a slash in it, upgrade.

## See also

- [Recording build provenance from CI](ci-provenance.md) — the CI half in more depth
- [CI gates](ci-gate.md) — `assert`, `verify-image`, `verify-chain`, `change-gate`
- [CLI reference](cli-reference.md)
