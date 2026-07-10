# Segregation of Duties — supplying the three identities

Fides trails carry a `segregation-of-duties` attestation that proves the
**committer**, the **approver(s)**, and the **deployer(s)** are three distinct
identities — the four-eyes / SoD control required by PCI-DSS 4.0 and SOX ITGC
change management. This guide shows exactly **how each of the three identities
is supplied** and walks a full worked example that ends in a `compliant: true`
verdict.

The computed payload (`pkg/api/sod.go`) is shaped like this and is exposed on
both the change-gate response and the approvals response (see
[fetch the verdict](#4-fetch-the-change-gate)):

```json
{
  "committer": "dev@example.com",
  "approvers": ["approver@example.com"],
  "deployers": ["ci-deployer@example.com"],
  "compliant": true,
  "violations": []
}
```

`compliant` is `true` only when the three roles are **pairwise-distinct**. If
the same identity appears in two roles (e.g. the committer also approves), the
role is listed in `violations` and `compliant` flips to `false`.

## The three roles

| Role | Supplied by | Stored as | Resolved from |
|---|---|---|---|
| **Committer** | `fides trail start --committer <email>` | trail tag `tags.committer` | `identityFromTags` checks tag keys `committer`, `author`, `git_author` (in order) |
| **Approver** | `fides approve --role approver` (default) | `trail_approvals.role = 'approver'` | authenticated principal, or `on_behalf_of` when delegation is enabled |
| **Deployer** | `fides approve --role deployer` | `trail_approvals.role = 'deployer'` | authenticated principal, or `on_behalf_of` when delegation is enabled |

`role='deployer'` rows are routed into the `deployers` set, **not** `approvers`.

## Identity registration — use `/api/v1/tenant/users`

> [!IMPORTANT]
> The identity/user endpoints live under **`/api/v1/tenant/users`**, **not**
> `/api/v1/users` (which is **404**). Probing the wrong path is what previously
> blocked a client. Any email used as `on_behalf_of` in an approval **must
> already be a registered user in the org**, or the approval is rejected with
> `400 "on_behalf_of does not match a known user in the organization"`.

| Endpoint | Purpose |
|---|---|
| `GET  /api/v1/tenant/users` | List the org's users/identities (`handleListUsers`) |
| `POST /api/v1/tenant/users` | Register/upsert an identity — upserts on email conflict (`handleSaveUser`) |
| `POST /api/v1/tenant/users/{id}/password` | Set a local-login password (Admin only) |

All examples below assume:

```bash
export FIDES_SERVER_URL="https://fides.example.com"
export FIDES_API_TOKEN="<admin service-account key>"   # Admin, for on_behalf_of
```

## Worked example — three distinct identities → `compliant: true`

We use `dev@example.com` (committer), `approver@example.com` (approver), and
`ci-deployer@example.com` (deployer).

### 0. Register the three identities

```bash
for u in \
  '{"name":"Dev Committer","email":"dev@example.com","role":"developer"}' \
  '{"name":"Release Approver","email":"approver@example.com","role":"approver"}' \
  '{"name":"CI Deployer","email":"ci-deployer@example.com","role":"deployer"}'; do
  curl -sS -X POST "$FIDES_SERVER_URL/api/v1/tenant/users" \
    -H "Authorization: Bearer $FIDES_API_TOKEN" \
    -H 'Content-Type: application/json' \
    -d "$u"
done

# verify they exist
curl -sS "$FIDES_SERVER_URL/api/v1/tenant/users" \
  -H "Authorization: Bearer $FIDES_API_TOKEN"
```

Only the two identities used with `on_behalf_of` (approver + deployer) strictly
need registering; registering the committer too keeps the directory complete.

### 1. Start the trail with a committer

**CLI** — the `--committer` flag is stored as the trail tag `tags.committer`:

```bash
fides trail start --flow "$FLOW" --trail "release-2026.07.10" \
  --repository "https://github.com/acme/app" --commit "$GIT_SHA" \
  --committer "dev@example.com"
```

**Raw API** — the committer is body field `tags.committer`:

```bash
curl -sS -X POST "$FIDES_SERVER_URL/api/v1/trails" \
  -H "Authorization: Bearer $FIDES_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
        "flow_id": "'"$FLOW"'",
        "name": "release-2026.07.10",
        "tags": { "committer": "dev@example.com" }
      }'
# → capture the returned trail id into $TRAIL
```

### 2. Record the approver approval

**CLI** — `--role approver` is the default; the approval is attributed to the
**authenticated principal**, so run this as the approver's own identity/token:

```bash
fides approve --trail "$TRAIL" --role approver --reason "reviewed by release board"
```

**Raw API** — to attribute the approval to a specific human from a shared Admin
service token, pass `on_behalf_of` (requires delegation enabled — see
[on-behalf-of](#on-behalf-of-delegation)):

```bash
curl -sS -X POST "$FIDES_SERVER_URL/api/v1/trails/$TRAIL/approvals" \
  -H "Authorization: Bearer $FIDES_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{ "role": "approver", "on_behalf_of": "approver@example.com",
        "reason": "reviewed by release board" }'
```

### 3. Record the deployer approval

**CLI:**

```bash
fides approve --trail "$TRAIL" --role deployer --reason "prod deploy"
```

**Raw API** (on-behalf-of the CI deployer identity):

```bash
curl -sS -X POST "$FIDES_SERVER_URL/api/v1/trails/$TRAIL/approvals" \
  -H "Authorization: Bearer $FIDES_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{ "role": "deployer", "on_behalf_of": "ci-deployer@example.com",
        "reason": "prod deploy" }'
```

### 4. Fetch the change gate

**CLI:**

```bash
fides change-gate --trail "$TRAIL"
```

**Raw API** — the SoD payload is the `segregation_of_duties` sub-object:

```bash
curl -sS "$FIDES_SERVER_URL/api/v1/trails/$TRAIL/change-gate" \
  -H "Authorization: Bearer $FIDES_API_TOKEN"
```

```json
{
  "approved": true,
  "segregation_of_duties": {
    "committer": "dev@example.com",
    "approvers": ["approver@example.com"],
    "deployers": ["ci-deployer@example.com"],
    "compliant": true,
    "violations": []
  }
}
```

The same `segregation_of_duties` object is also returned inline on every
`POST /api/v1/trails/{id}/approvals` response, so a pipeline can read the
current SoD state straight after recording an approval.

## On-behalf-of delegation

`on_behalf_of` lets a shared Admin service token record an approval **as a real
human** so it counts toward four-eyes. It is honored only when **all** hold:

- `FIDES_DELEGATED_APPROVAL_ENABLED=true` on the server,
- the caller is an **Admin** service token, and
- `on_behalf_of` is an email matching a **registered org user**
  ([step 0](#0-register-the-three-identities)).

When honored, the approval is recorded with `approver_kind=session` and the
delegating service principal is captured in `delegated_by` (and the audit log).
Otherwise `on_behalf_of` is ignored and the approval is attributed to the token.
An unknown email is rejected with `400 "on_behalf_of does not match a known user
in the organization"`. See `FIDES_DELEGATED_APPROVAL_ENABLED` in the
configuration reference and the `fides approve` row in the
[CLI reference](cli-reference.md).

## Common `compliant: false` causes

- **Committer also approves/deploys** — same email in two roles; the shared
  identity is listed in `violations`.
- **`on_behalf_of` not set (or ignored)** and every approval resolves to the
  same service token — collapses approver and deployer into one identity.
- **Missing a role** — no committer tag, or no deployer approval, so the gate
  cannot prove three distinct parties.
