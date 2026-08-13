# Recording build provenance from CI

How to make a Fides environment report a verdict that means something — and
what has to be true for it to ever go green.

This is written from doing it for Fides' own pipeline on 2026-08-13, where the
environment had reported `compliant: false` on **1529 consecutive snapshots**
and could never have reported anything else.

## The short version

Four things must all be true. Miss any one and the environment is permanently
red, which carries exactly as much information as permanently green.

| # | Requirement | Symptom if missing |
|---|---|---|
| 1 | CI records every image it builds as an **artifact** | every running image is a "shadow change" |
| 2 | The reporter is **scoped** to what you actually govern | third-party images you never built count as shadows |
| 3 | Third-party images you *do* run are **allowlisted** | one unfixable shadow keeps the verdict red |
| 4 | The digest CI registers is the digest the **runtime reports** | provenance is recorded and still never matches |

Item 4 is the one that will surprise you. See
[Digests: the part that bites](#digests-the-part-that-bites).

## 1. Record provenance from CI

### What you need

| Kind | Name | Value |
|---|---|---|
| secret | `FIDES_SERVER_URL` | e.g. `https://fides.example.com` |
| secret | `FIDES_API_TOKEN` | a **service-account** key — see below |
| variable | `FIDES_FLOW_ID` | the flow these builds belong to |

The flow id is not a credential, so it is a variable rather than a secret.

### Create a scoped service account, not a general token

Do **not** put the instance's general API token in CI. It is Admin-equivalent,
so every workflow run — including one added by a future PR — could administer
the tenant.

Fides service accounts carry a role: `Viewer`, `Writer`, `Auditor`, `Admin`.
**`Writer`** is exactly the authority CI needs: it can open trails and report
artifacts, and nothing else.

```bash
# Create the account (needs an admin token, once).
curl -sX POST "$FIDES_SERVER_URL/api/v1/tenant/service-accounts" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"ci-provenance","role":"Writer"}'
# -> {"id":"<sa-id>","name":"ci-provenance","role":"Writer"}

# Issue a key for it.
curl -sX POST "$FIDES_SERVER_URL/api/v1/tenant/service-accounts/<sa-id>/keys" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"github-actions"}'
# -> {"api_key":"...","prefix":"...","expires_at":null}
```

The `api_key` is shown **once**. Put it straight into the secret and shred any
local copy.

Verify it is genuinely limited before you trust it — a role you did not test
is a role you are guessing at:

```bash
# Should work (Writer can read):
fides flow list

# Should be 403 — Writer must not be able to administer the tenant:
curl -so /dev/null -w '%{http_code}\n' -X POST \
  "$FIDES_SERVER_URL/api/v1/tenant/service-accounts" \
  -H "Authorization: Bearer $CI_KEY" -H 'Content-Type: application/json' \
  -d '{"name":"escalation-probe","role":"Admin"}'
```

Keys issued this way have no expiry (`expires_at: null`). Rotate by issuing a
new key and revoking the old one via
`DELETE /api/v1/tenant/service-accounts/{id}/keys/{keyId}`.

### Set them

```bash
gh secret set FIDES_SERVER_URL --body 'https://fides.example.com'
gh secret set FIDES_API_TOKEN  --body '<api_key>'
gh variable set FIDES_FLOW_ID  --body '<flow-uuid>'
```

### The workflow steps

Two CLI calls. `fides trail start --quiet` prints only the trail id, which is
what makes it usable in a shell.

```yaml
- uses: ./.github/actions/setup-fides

- name: Record provenance
  env:
    # Pass EVERY interpolation through the environment. A commit author sets
    # their own email, so inlining it is a script-injection hole — actionlint
    # flags this one by name.
    COMMITTER: ${{ github.event.head_commit.author.email }}
    COMMIT_SHA: ${{ github.sha }}
    DIGEST: ${{ steps.build.outputs.digest }}
  run: |
    set -euo pipefail
    trail_id="$(fides trail start \
      --flow "${FIDES_FLOW_ID}" \
      --trail "${COMMIT_SHA}-${IMAGE_NAME}" \
      --repository "${REPO_URL}" \
      --commit "${COMMIT_SHA}" \
      --committer "${COMMITTER}" \
      --quiet)"
    fides artifact report --trail "${trail_id}" \
      --sha256 "${DIGEST#sha256:}" --name "${IMAGE_NAME}" --type docker
```

Three things worth copying rather than re-deriving:

- **Place it after your CVE gate and after signing.** A digest should only
  enter the evidence vault once it has passed everything.
- **Report the digest, not the tag.** A tag can be re-pointed afterwards; the
  digest is the bytes.
- **Put the image name in the trail name** if you build a matrix. Trails are
  `UNIQUE(flow_id, name)`, so one trail per commit means parallel matrix jobs
  race each other into a 409.

The `--committer` value is not decoration: it is what the
[segregation-of-duties](segregation-of-duties.md) attestation reads. Without
it, SoD has nothing to evaluate.

## 2. Scope the reporter

An unscoped `fides snapshot k8s` reports **every pod in the cluster**. On a
shared cluster that means argocd, gitlab, keycloak, minio, kyverno — none of
which you built, all of which count as shadow changes.

Set the namespace so the environment covers what you actually govern:

```yaml
# charts/fides-k8s-reporter values
fides:
  namespace: fides        # adds --namespace to the CLI
```

On Fides' own p510 cluster this took the snapshot from **78 shadow changes to
1**.

> **RBAC caveat.** The chart's `serviceAccount.permissionScope: namespace`
> creates a Role in the **release** namespace. If the reporter is deployed
> somewhere other than the namespace it reports (e.g. release
> `fides-reporter`, target `fides`), that grants the wrong namespace. Keep
> `permissionScope: cluster` and let the CLI filter, or deploy the reporter
> into the namespace it reports.

## 3. Allowlist third-party images

You will run images you did not build — a database, a proxy. They will never
have Fides provenance, and that is not a defect.

`environment_allowlist` records an explicit, attributed exception:
`approved_by` and `reason`. That is the compliance concept of an accepted
risk, and it is auditable in a way that "we turned the check off" is not.

```bash
curl -sX POST "$FIDES_SERVER_URL/api/v1/environments/$ENV_ID/allowlist" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"artifact_sha256":"<digest-without-sha256:-prefix>",
       "reason":"postgres:15-alpine — upstream base image, no first-party provenance by design"}'
```

Write a real reason. It is the only thing a future auditor — or a future you —
has to judge the exception by.

**The allowlist is keyed by digest**, so an entry does not survive an upstream
image update. That is deliberate (a new digest is new bytes and deserves a new
decision) but it means allowlisting dozens of third-party images is not
maintainable. If you find yourself doing that, scope the environment instead.

## Digests: the part that bites

CI knows the image by `steps.build.outputs.digest`. The runtime reports
whatever its container runtime recorded. **These are not always the same
value**, and when they differ, provenance is recorded correctly and still
never matches.

`docker/build-push-action` pushes an OCI **image index** containing the
platform manifest plus a SLSA provenance attestation. The attestation embeds
the commit, so **a rebuild with byte-identical image content still gets a new
index digest**:

```text
tag 6f5848c3  index 5c0c7c42...  amd64 child dd510945...
tag 09157f3c  index c127b692...  amd64 child dd510945...   <- same content
```

containerd already holds that content and keeps reporting the index digest it
first resolved — the older one. A commit that changes only workflow YAML or
docs reproduces this exactly.

Two mitigations, both cheap:

1. **Register the platform manifest digests too.** The platform digest is the
   image content, so it is stable across content-identical rebuilds:

   ```bash
   docker buildx imagetools inspect "${IMAGE}@${DIGEST}" --raw \
     | jq -r '.manifests[]? | select(.platform.os != "unknown") | .digest' \
     | while read -r child; do
         fides artifact report --trail "$trail_id" \
           --sha256 "${child#sha256:}" --name "$IMAGE_NAME" --type docker
       done
   ```

2. **Expect a transitional gap.** Images built *before* you switched
   provenance on were never registered, so anything still running from them
   reads as a shadow. Either wait for the next content change or backfill
   those digests once, with a trail name that says so.

## Checking your work

```bash
# What is registered?
psql -c "SELECT name, substring(sha256,1,16), created_at::date FROM artifacts ORDER BY created_at DESC LIMIT 5;"

# What is actually running?
kubectl -n <ns> get pods -o jsonpath='{range .items[*]}{.status.containerStatuses[*].imageID}{"\n"}{end}'
```

If a digest appears in the second list and not the first, the snapshot will
call it a shadow change. That is the whole mechanism.

A healthy snapshot looks like this:

```json
{"snapshot_id":"88c9cf2d-...","compliant":true,"drifts":null,"shadow_changes":null}
```

## Related

- [CI gate](ci-gate.md) — gating a pipeline on the verdict once it means something
- [Segregation of duties](segregation-of-duties.md) — what `--committer` feeds
- [CLI reference](cli-reference.md) — `fides trail`, `fides artifact`, `fides env`
