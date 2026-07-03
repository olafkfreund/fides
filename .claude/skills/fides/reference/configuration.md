# Fides Configuration Reference

Every environment variable Fides reads, grouped by concern. **The CLI (`fides`) only
reads the three "CLI" variables below** — all others configure the **server**
(`cmd/server`), the **MCP server** (`fides-mcp`), or the **sensor** (`cmd/mcp-sensor`).

---

## CLI (`fides`)

| Variable | Purpose | Default |
|---|---|---|
| `FIDES_SERVER_URL` | Fides server base URL the CLI talks to | `http://localhost:8080` |
| `FIDES_API_TOKEN` | Bearer auth — a service-account key (`fides_<prefix>_<secret>`) or a static token | — |
| `FIDES_ENCRYPTION_KEY` | Passphrase to encrypt attestation payloads (AES-256-GCM via PBKDF2). If set, `attest` auto-encrypts | — |

`fides-mcp` and `cmd/mcp-sensor` also use `FIDES_SERVER_URL` / `FIDES_API_TOKEN`
to reach the server. The sensor additionally uses `MCP_SENSOR_RESPONSE`
(runtime response payload) and honors `FIDES_MCP_ALLOWED_COMMANDS`.

---

## Server — core & HTTP

| Variable | Purpose | Notes |
|---|---|---|
| `PORT` | HTTP listen port | default `8080` |
| `FIDES_PUBLIC_URL` | External URL of the portal/API | used for links, webhooks, OAuth redirects |
| `FIDES_ORG_ID` / `FIDES_API_ORG_ID` | Default/seed org (tenant) UUID | multi-tenant scoping |
| `PORTAL_USERNAME` / `PORTAL_PASSWORD` | Initial portal admin login | set at seed/first boot |
| `FIDES_AUTO_MIGRATE` | Apply embedded DB migrations on boot | `true`/`false` |

## Server — database

| Variable | Purpose |
|---|---|
| `DB_DSN` | Postgres DSN (e.g. `postgres://user:pass@host:5432/fides?sslmode=require`) |
| `FIDES_RLS_ENABLED` | Enable Postgres Row-Level Security tenant isolation (connects as least-privilege `fides_app`; applies `schema-rls.sql`) |
| `FIDES_TEST_DB_DSN` | DSN used by the Postgres integration tests only |

## Server — evidence storage

| Variable | Purpose |
|---|---|
| `STORAGE_DRIVER` | Evidence blob backend, e.g. `local` or `s3` |
| `STORAGE_LOCAL_DIR` | Directory for the `local` driver |
| `AWS_S3_BUCKET` | S3 bucket for evidence (s3 driver) |
| `AWS_REGION` | AWS region (S3 / Secrets Manager / ECS / Lambda) |
| `FIDES_OBJECT_LOCK_MODE` | WORM retention: `GOVERNANCE` or `COMPLIANCE` (bucket must have Object Lock enabled) |
| `FIDES_EVIDENCE_RETENTION_DAYS` | Retain-until window (days) for WORM evidence |

## Server — secrets

| Variable | Purpose |
|---|---|
| `SECRETS_PROVIDER` | Secret backend for `--secret-path` references. `aws` = AWS Secrets Manager (via IRSA); otherwise env-var lookup |
| `FIDES_ENCRYPTION_KEY` | Server-side key to decrypt encrypted attestation payloads |

## Server — approvals / segregation of duties

| Variable | Purpose | Default |
|---|---|---|
| `FIDES_DELEGATED_APPROVAL_ENABLED` | Allow `POST /api/v1/trails/{id}/approvals` to honor an `on_behalf_of` human identity when the caller is a shared service token (the SARC portal case). Default-deny | `false` |

On-behalf-of delegation is honored ONLY when all hold: the flag is `true`, the
authenticated principal is a **service token with the Admin role** (the static
`FIDES_API_TOKEN` principal, or an Admin service-account key), the `on_behalf_of`
value is a syntactically-valid bare email, and it matches a known user in the
caller's org. When honored the approval is recorded with `approver_kind=session`
(so it counts toward four-eyes segregation of duties) and the delegating service
principal is captured in the `delegated_by` column and emitted to the audit log.
Otherwise `on_behalf_of` is ignored and the approval is attributed to the token
principal (`approver_kind=service`) exactly as before — a service token is never
silently upgraded to a human session.

Request contract:

```
POST /api/v1/trails/{id}/approvals
{ "reason": "reviewed by platform lead", "role": "approver", "on_behalf_of": "user@example.com" }

# honored -> 201
{ "status": "approved", "approved_by": "user@example.com", "kind": "session",
  "role": "approver", "delegated_by": "portal-service@fides" }

# invalid/unknown on_behalf_of while honored -> 400
```

## Server — AI / LLM gateway (`Fides-AI`)

Powers `policy generate`, the portal "Check & fix" linter (`POST /api/v1/ai/lint-policy`),
and scored AI audit reports.

| Variable | Purpose |
|---|---|
| `AI_PROVIDER` | LLM provider, e.g. `ollama`, `llamacpp`, `gemini` |
| `AI_MODEL` | Model name |
| `AI_OLLAMA_ENDPOINT` | Ollama endpoint URL |
| `AI_LLAMACPP_ENDPOINT` | llama.cpp endpoint URL |
| `GEMINI_API_KEY` | Google Gemini API key (when `AI_PROVIDER=gemini`) |

## Server — event engine & integrations

| Variable | Purpose |
|---|---|
| `FIDES_EVENTS_ENABLED` | Turn on the outbox/dispatcher that drives sinks: webhooks, GitHub/GitLab commit-status, ServiceNow ITOM+CMDB, Slack |

Integration *connections* (ServiceNow, Git providers, webhooks, Slack) are configured
via the CLI (`fides servicenow|git-provider|webhook|slack config`), storing credentials
as `--secret-path` references resolved by `SECRETS_PROVIDER`.

## Server — Kubernetes admission controller (`pkg/admission`)

| Variable | Purpose |
|---|---|
| `FIDES_ADMISSION_MODE` | Admission behavior, e.g. enforce vs audit |
| `FIDES_ADMISSION_ORG_ID` | Org (tenant) the admission webhook evaluates against |

## MCP

| Variable | Purpose |
|---|---|
| `FIDES_MCP_ALLOWED_COMMANDS` | Allow-list of commands the MCP sensor may run (runtime compliance checks) |
| `MCP_SENSOR_RESPONSE` | Response payload for the in-cluster stdio sensor |

---

## Minimal configs

**CI runner (using the CLI):**
```bash
export FIDES_SERVER_URL="https://fides.example.com"
export FIDES_API_TOKEN="fides_ci_xxx"     # a Writer service-account key
export FIDES_ENCRYPTION_KEY="$CI_SECRET"  # only if you encrypt payloads
```

**Server (local dev):**
```bash
export DB_DSN="postgres://fides:fides@localhost:5432/fides?sslmode=disable"
export FIDES_AUTO_MIGRATE=true
export PORTAL_USERNAME=admin PORTAL_PASSWORD='change-me'
export STORAGE_DRIVER=local STORAGE_LOCAL_DIR=./evidence
export AI_PROVIDER=ollama AI_OLLAMA_ENDPOINT=http://localhost:11434 AI_MODEL=llama3
```

**Server (production hardening):**
```bash
export FIDES_RLS_ENABLED=true
export SECRETS_PROVIDER=aws AWS_REGION=eu-west-2
export STORAGE_DRIVER=s3 AWS_S3_BUCKET=acme-fides-evidence
export FIDES_OBJECT_LOCK_MODE=COMPLIANCE FIDES_EVIDENCE_RETENTION_DAYS=2555
export FIDES_EVENTS_ENABLED=true
export FIDES_PUBLIC_URL=https://fides.acme.com
```

See `docs/setup.md`, `docs/aws-secrets-manager.md`, and the Helm chart `charts/fides`
for full deployment guidance.
