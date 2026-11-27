---
status: approved
issue: 547
intent: intent/2026-11-27-547-git-attestation-destination.md
---

# Spec: Separate provider requests from signed downloads

## Design

Limit authenticated list and same-origin bundle requests to the configured Git API origin, including redirect hops. Additional provider-issued absolute public HTTPS bundle URLs use the existing public destination policy on a separate client with no provider token or cookies. The direct configured provider can remain private and use its established scheme.

GitHub documents signed bundle URLs on a different origin. GitLab documents same-origin bundle downloads. [GitHub REST API](https://docs.github.com/en/rest/repos/attestations) · [GitLab attestations API](https://docs.gitlab.com/api/attestations/)

## Alternatives rejected

Sending the provider credential to signed storage destinations exceeds its intended scope. Restricting all bundles to the provider origin would break documented cross-origin downloads.

## Risks

Private storage on a different origin needs the provider to return a link from its configured origin. Expired signed links may require a fresh list response.

## Verification

Use synthetic cases for same-origin authenticated downloads, anonymous public HTTPS downloads, and policy refusals. Prove that configured internal provider endpoints still work and run the standard local checks.
