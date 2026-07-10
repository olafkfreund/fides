# HMAC-signed inbound webhook verification (ServiceNow)

> Closes [#229](https://github.com/olafkfreund/fides/issues/229). Part of epic
> [#216](https://github.com/olafkfreund/fides/issues/216).

Fides delivers every outbound webhook **signed with HMAC-SHA256** so a receiver
can prove the payload really came from Fides and was not tampered with in transit.
ServiceNow's built-in inbound webhook plumbing does **not** verify signatures, so
this guide ships a **Scripted REST API** resource plus a reusable **Script
Include** (`FidesWebhookVerifier`) that recompute the HMAC over the raw body and
compare it, in a length-independent scan, to the signature header.

## 1. How Fides signs (the contract you must match)

Implemented in [`pkg/webhooks/webhook.go`](https://github.com/olafkfreund/fides/blob/main/pkg/webhooks/webhook.go) (`Sign`)
and delivered by the tenant webhook sink:

```
X-Fides-Signature   sha256=<hex>      HMAC_SHA256(secret, timestamp + "." + rawBody)
X-Fides-Timestamp   <unix seconds>    part of the signed payload; also a replay guard
X-Fides-Event-Id    <uuid>            dedupe key — delivery is at-least-once
X-Fides-Event-Type  <event type>      e.g. compliance.evaluated, servicenow.change_gate
```

The body is the JSON envelope `{ "id", "type", "org_id", "payload", "sent_at" }`.

The **signed payload is `timestamp + "." + rawBody`** — the literal timestamp
string, a `.`, then the exact bytes of the body. Two rules follow:

1. Hash the **raw** request body (`request.body.dataString`), never a re-serialized
   object. Re-serialization reorders/whitespaces the JSON and breaks the HMAC.
2. Recompute `sha256=` + lowercase hex and compare in constant time. Fides itself
   compares with `hmac.Equal` (constant time) — mirror that on the receiver.

### Worked example

```
secret     = "s3cr3t"
timestamp  = "1735732800"
rawBody    = {"id":"e1","type":"compliance.evaluated","org_id":"o1","payload":{},"sent_at":"1735732800"}

signed     = "1735732800." + rawBody
X-Fides-Signature = "sha256=" + hex(HMAC_SHA256("s3cr3t", signed))
```

Reproduce it from a shell to sanity-check your ServiceNow implementation:

```bash
TS=1735732800
BODY='{"id":"e1","type":"compliance.evaluated","org_id":"o1","payload":{},"sent_at":"1735732800"}'
printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac 's3cr3t'
# -> the hex after "sha256=" must equal what FidesWebhookVerifier computes
```

## 2. Install the Script Include

Create **System Definition → Script Includes**:

- **Name:** `FidesWebhookVerifier`
- **Client callable:** false
- **Accessible from:** (your app scope)
- **Script:** paste [`scripted-rest/FidesWebhookVerifier.js`](scripted-rest/FidesWebhookVerifier.js)

It uses `GlideCertificateEncryption.generateMac(base64Key, "HmacSHA256", data)`
(base64 in/out) and converts the MAC to hex, because ServiceNow has no native
hex-HMAC primitive. It also enforces a `MAX_SKEW_SECONDS` (default 300s) replay
window on `X-Fides-Timestamp`.

## 3. Create the Scripted REST API

**System Web Services → Scripted REST APIs → New**:

- **Name:** `Fides Inbound`, **API ID:** `fides_inbound`
- Add a **resource**: HTTP method `POST`, relative path `/events`,
  **Requires authentication = true**.
- **Script:** paste [`scripted-rest/fides_inbound_resource.js`](scripted-rest/fides_inbound_resource.js)

Published URL:

```
https://<instance>.service-now.com/api/<scope>/fides_inbound/events
```

The resource verifies the HMAC first and returns **401** on any failure
(malformed/missing header, stale timestamp, or signature mismatch), otherwise it
parses the envelope and fans out on `X-Fides-Event-Type`.

## 4. Store the shared secret

**Never** hard-code the secret in the resource script. Options, best first:

1. **Connection & Credential alias** (`sn_cc`) — a Credentials record; read it in
   the resource with the `sn_cc` API. Rotatable, access-controlled, audited.
2. **Encrypted system property** — `x_fides.webhook.shared_secret` with
   **Type = password2** (encrypted at rest). This is what the sample resource
   reads via `gs.getProperty(...)` for brevity.

On the Fides side the same secret is stored only as a `secret_path` reference and
resolved by the secrets provider (env or AWS Secrets Manager) — Fides never
persists the plaintext. Register the ServiceNow endpoint as a tenant webhook:

```bash
curl -X POST https://<fides>/api/v1/tenant/webhooks \
  -H "Authorization: Bearer $FIDES_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "url": "https://<instance>.service-now.com/api/<scope>/fides_inbound/events",
    "secret_path": "SNOW_WEBHOOK_SECRET",
    "event_types": ["compliance.evaluated", "servicenow.change_gate"]
  }'
```

Set the **same** secret value in ServiceNow (step 4) and in the Fides secrets
provider under `SNOW_WEBHOOK_SECRET`.

## 5. Flow Designer usage note

If you would rather branch in **Flow Designer** than in the resource script, keep
the Scripted REST resource as the thin verify-and-ack front door and hand the
verified envelope to a flow:

1. In the resource script, after `verdict.ok`, call your flow via
   `sn_fd.FlowAPI.getRunner().action(...).inForeground().withInputs({...}).run()`
   passing `event_type`, `event_id`, and the parsed `payload`.
2. Build the flow with a **trigger of "None/Called"** and inputs matching those
   keys, then branch on `event_type` (e.g. update a `change_request`, open an
   incident, post to CAB).
3. Do **not** use the out-of-box "Inbound REST/Webhook" trigger for the Fides feed
   — it bypasses HMAC verification. Always enter through the verifying resource.

Because delivery is at-least-once, make the flow idempotent: dedupe on
`X-Fides-Event-Id` (e.g. a lookup against a small "processed events" table) before
any side effect.

## 6. Testing checklist

- Valid delivery → **200** `{ "status": "accepted" }`.
- Tampered body (flip one byte) → **401** `signature mismatch`.
- Missing/short `X-Fides-Signature` → **401** `missing or malformed`.
- `X-Fides-Timestamp` older than `MAX_SKEW_SECONDS` → **401** `stale timestamp`.
- Cross-check one delivery's hex against the `openssl` one-liner in §1.
