# Fides Features & Real-World Examples

This guide covers the capabilities added across the platform, with copy-paste
examples for the CLI and API. All API calls use a bearer token
(`Authorization: Bearer $FIDES_API_TOKEN`) or a service-account key; the CLI
reads `FIDES_SERVER_URL` and `FIDES_API_TOKEN` from the environment.

> See also: [CLI reference](cli-reference.md) ·
> [ServiceNow](servicenow-integration.md) ·
> [AWS Secrets Manager](aws-secrets-manager.md) ·
> [Environment MCP compliance](environment-mcp-compliance.md)

---

## 1. Built-in evidence parsers (JUnit / Snyk / Trivy)

Instead of hand-building JSON, point Fides at a raw report and it normalizes it
into a compliant/non-compliant attestation (attaching the original file).

```bash
# JUnit test results
fides attest junit  --trail $TRAIL --file ./reports/junit.xml --artifact-sha $DIGEST
# Snyk scan (compliant when no critical/high)
fides attest snyk   --trail $TRAIL --file ./reports/snyk.json
# Trivy image scan
fides attest trivy  --trail $TRAIL --file ./reports/trivy.json
```

The normalized payload (`{format, compliant, summary{counts}, findings}`) is
jq-evaluable, e.g. an attestation type with rule `.summary.failed == 0`.

## 2. Tamper-evident attestation chain

Every attestation is linked into a per-trail append-only hash chain. Any later
edit, deletion, or reorder is detectable.

```bash
fides verify-chain --trail $TRAIL          # exits non-zero (2) if the chain is broken
```
```bash
curl -H "Authorization: Bearer $FIDES_API_TOKEN" \
  $FIDES_SERVER_URL/api/v1/trails/$TRAIL/verify-chain
# {"valid":true,"count":4,"broken_at":-1}
```

## 3. Service accounts + rotatable API keys

Replace the single static token with per-tenant service accounts holding hashed,
rotatable keys.

```bash
fides service-account create --name ci-pipeline --role Writer
fides service-account issue-key --account $SA_ID --label "github-actions" --expires-hours 720
#  -> prints the full key ONCE: fides_<prefix>_<secret>
fides service-account list
# rotation: issue a new key, switch CI to it, then revoke the old one:
fides service-account revoke-key --account $SA_ID --key $OLD_KEY_ID
```

## 4. Per-environment artifact allow-lists / approvals

Explicitly approve a digest for an environment, and gate deploys on it.

```bash
fides allowlist add   --env $ENV --sha $DIGEST --reason "approved by release board"
fides allowlist check --env $ENV --sha $DIGEST    # exit 2 if not approved (use as a deploy gate)
fides allowlist list  --env $ENV
```

## 5. Environment policies + tags (conditional requirements)

Bind required attestation types to an environment, optionally only when a flow
tag matches (e.g. require a change record only for high-risk flows).

```bash
# tag a flow
curl -X POST $FIDES_SERVER_URL/api/v1/flows/$FLOW/tags \
  -H "Authorization: Bearer $FIDES_API_TOKEN" -d '{"tags":{"risk":"high"}}'

# policies on the environment
fides policy add --env $ENV --name tests     --require junit,trivy
fides policy add --env $ENV --name high-risk  --require servicenow-change --if-tag risk --if-value high

# gate a deploy: exits 2 if any applicable policy is unsatisfied
fides policy check --env $ENV --trail $TRAIL
```

## 6. Search & snapshot diff

```bash
fides search artifacts    --sha 3c8e7843 --name payments
fides search attestations --type junit --compliant false
fides env diff --env $ENV                  # diff the two most recent snapshots
fides env diff --env $ENV --from $SNAP_A --to $SNAP_B
```

## 7. Trail audit packages

Download a self-contained ZIP (trail, artifacts, attestations, chain verdict,
report) for auditors.

```bash
fides audit --trail $TRAIL --output trail-audit.zip
```

## 8. More runtimes (ECS / Lambda)

```bash
fides snapshot ecs    --env $ENV --cluster my-ecs-cluster
fides snapshot lambda --env $ENV
```

## 9. Logical environments

Aggregate physical environments into one compliance view.

```bash
fides logical-env create --name production --description "all prod runtimes"
fides logical-env add-member --id $LOGICAL --env $K8S_PROD_ENV
fides logical-env add-member --id $LOGICAL --env $ECS_PROD_ENV
fides logical-env state --id $LOGICAL       # unified running services across members
```

## 10. DORA delivery metrics

```bash
fides metrics --days 30
# {"deployments":42,"deployment_frequency_per_day":1.4,"compliance_rate":0.97,"change_failure_rate":0.03,...}
```

## 11. ServiceNow integration

Configure once, then CMDB sync + ITOM alerts + the ITSM change gate run on the
event engine. There is also a Go-served admin page at `/servicenow`
(view / verify / monitor). Full guide: [servicenow-integration.md](servicenow-integration.md).

```bash
fides servicenow config --instance-url https://acme.service-now.com \
  --auth-type basic --client-id svc-fides --secret-path fides/servicenow
fides servicenow change-check --trail $TRAIL --change CHG0030192
```

## 12. Slack notifications

```bash
# store the incoming-webhook URL as a secret (env var or Secrets Manager id), then:
fides slack config --secret-path fides/slack-webhook
```
Compliance events (`compliance.evaluated`, `snapshot.noncompliant`) are posted to
the channel when the event engine is enabled (`FIDES_EVENTS_ENABLED=true`).

## 13. Other integration config (CLI)

```bash
fides git-provider config --provider github --host github.com \
  --api-base https://api.github.com --token-path fides/gh-token --inbound-secret-path fides/gh-webhook
fides webhook config --name audit-sink --url https://example.com/hook --secret-path fides/hook-secret
fides user set-password --user $USER_ID --password 'S0me-Strong-Pass'
```
