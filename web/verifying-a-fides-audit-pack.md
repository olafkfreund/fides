# Verifying a Fides audit pack

A signed audit pack consists of a ZIP archive and its detached `.sig` file.
Keep them together. The signature covers the exact ZIP bytes, including the
archive metadata. The manifest lists the evidence members with their byte
sizes and SHA-256 digests.

## Set up archive signing

Provision an Ed25519 private key in PKCS #8 PEM format and set
`FIDES_AUDIT_PACK_PRIVATE_KEY_FILE` to its runtime file path on the server.
Restrict file access to the server account. Export and distribute the public
key through a trusted channel independent of the ZIP. For a new key, run
these commands in a private working directory:

```bash
(umask 077 && openssl genpkey -algorithm ED25519 -out audit-pack-key.pem)
openssl pkey -in audit-pack-key.pem -pubout -out audit-pack-public.pem
```

Retain each public key for as long as you need to verify packs it signed.
The detached signature identifies the signing key by the SHA-256 fingerprint
of its raw Ed25519 public key.

Upgrade ledger readers before enabling version 2 evidence writes with
`FIDES_LEDGER_EVIDENCE_V2=true`. Older attestations retain their original
hashes and can still appear in a signed pack.

## Download a pack

```bash
fides audit --signed --trail "$TRAIL_ID" --output trail-audit.zip
```

Keep `trail-audit.zip.sig` beside `trail-audit.zip`. Give the auditor both
files and identify the independently distributed public key. A missing
object with a recorded digest or a failed export read prevents delivery of
a completed pack.

## Verify offline

Use the public key received through your independent trust channel. This
example also supplies local roots and a signer policy for retained proofs:

```bash
fides verify-pack trail-audit.zip --archive-key audit-pack-public.pem \
  --tsa-roots tsa-roots.pem --signer-policy signer-policy.json
```

Repeat `--archive-key` to trust multiple archive keys through a rotation.
Supply `--tsa-roots` when the pack contains timestamp tokens. Supply
`--signer-policy` when it contains signer proofs. The policy is a JSON object
keyed by each expected artifact's lowercase SHA-256 digest without a prefix.
Each entry uses a pinned `key` or a local `trusted_root` with an explicit
`signer` and `issuer`. Relative trust paths resolve beside the policy file.

```json
{
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {
    "key": "team-public.pem"
  },
  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": {
    "trusted_root": "sigstore-root.json",
    "signer": "release@example.com",
    "issuer": "https://issuer.example.com"
  }
}
```

Verification authenticates the exact container before opening the ZIP. It
checks membership, sizes, digests, the attestation chain, and every retained
signer and timestamp proof. Packs are limited to 128 MiB compressed and
256 MiB expanded, with 32 MiB per member.

| Exit | Result |
|------|--------|
| 0 | All required evidence and proofs verified |
| 1 | Command usage, local file, or trust configuration error |
| 2 | Invalid archive, signature, chain, or included proof |
| 3 | Verified available evidence with incomplete coverage |

Incomplete coverage includes older attestations, missing historical signer
proofs, or a current chain head without a timestamp. A failed check on any
included proof returns an invalid result even if historical gaps also exist.
