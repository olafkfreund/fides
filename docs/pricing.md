# Fides pricing & open-core — proposal (DRAFT)

> **Status: proposal for review (#238).** Dollar figures below are marked
> `[PLACEHOLDER]` — they are structural suggestions, not committed prices. The
> **open-core boundary** and **tier structure** are the substance to review;
> swap in the numbers you want before this goes public. Not yet linked into the
> published site nav.

## Why publish this at all

Our head-to-head competitor, **Kosli**, runs **opaque, SaaS-only, enterprise
"call us" pricing**. That opacity is a named weakness, and our **self-hostable,
OSS-core** architecture is the wedge. Publishing a transparent price list plus a
genuinely free, self-hostable tier directly attacks two market white-spaces:

1. **"Pricing opacity"** — we post real numbers; buyers can self-qualify.
2. **"The open-source Kosli alternative"** — a free, Apache-2.0 core they can run
   air-gapped today, with a clear paid upgrade path.

Positioning line: **"The open, self-hostable evidence & change-gate layer — Kosli
without the black box."**

## The open-core boundary

The principle: **the evidence engine is open and free; the enterprise assurance,
scale, deep integrations, and hosting are commercial.** A solo developer or an
OSS project gets real value at $0 and can self-host forever. Regulated
enterprises pay for the assurance guarantees, identity, deep ServiceNow, and
support they already budget for.

| Capability | Community (OSS, free) | Commercial (Team / Enterprise) |
|---|---|---|
| Trails, artifacts, attestations, **tamper-evident hash chain** (`verify-chain`) | ✅ | ✅ |
| Evidence parsers (JUnit, Trivy, Snyk, SBOM CycloneDX/SPDX, secret-scan, SAST, IaC) | ✅ | ✅ |
| Supply-chain provenance: `verify-image` (cosign/Sigstore), SLSA ingest/attest | ✅ | ✅ |
| **Change gate** + 0–100 risk + policy engine | ✅ | ✅ |
| Control frameworks (SOC2/ISO27001/NIST/PCI/DORA/PSD2/SOX/SLSA) + coverage | ✅ | ✅ |
| CLI + **`fides-mcp`** (AI-native MCP server) | ✅ | ✅ |
| Single organization, self-hosted | ✅ | ✅ |
| Segregation-of-duties attestation + control timeline | ✅ | ✅ |
| **SSO / SAML / SCIM** provisioning | — | ✅ |
| **Multi-tenant RLS at scale**, org hierarchy | — | ✅ |
| **WORM / retention** on evidence (S3 Object Lock), long-retention model provenance | — | ✅ |
| **Deep ServiceNow spoke** (signed change-gate write-back, change↔control, CMDB anchor, MCP client, CAB enrichment) | Basic write-back | **Full spoke** |
| Slack / webhooks / Git-status enterprise fan-out | Basic | ✅ |
| DORA ↔ compliance correlation, auto-remediation with approval gates | — | ✅ |
| Per-framework **auditor report packs** + OSCAL export | OSCAL export | **Report packs + support** |
| **Hosted SaaS** option | — | ✅ |
| **Air-gapped / on-prem** deployment support | Self-serve | **Supported + hardening** |
| Support | Community (GitHub) | Business hours → 24×7 + SLA |

> The **ServiceNow governed MCP client** and change-gate write-back exist in the
> OSS core (they're part of the engine); the **enterprise SN spoke** — packaged
> IntegrationHub actions, CAB enrichment, Now Assist grounding, and support — is
> the commercial upgrade. Adjust this line if you want SN fully behind the paywall.

## Tiers

### Community — free, forever, self-hosted (Apache-2.0 core)

- The full evidence/provenance/change-gate engine, CLI, and MCP server.
- Self-hosted (Docker / Helm / Nix); single organization.
- Community support (GitHub issues/discussions).
- **Price: $0.**
- **Goal:** be the default "open-source Kosli alternative." Land developers and
  OSS projects; convert the ones that grow into regulated needs.

### Team — for a growing engineering org

- Everything in Community, plus: SSO, hosted SaaS option, enterprise
  integrations (full Slack/webhooks/Git fan-out), DORA↔compliance dashboards,
  email support.
- **Price: `[PLACEHOLDER — e.g. $20–40 / developer / month]`, or
  `[PLACEHOLDER — flat $X / org / month up to N developers]`.**
- **Goal:** transparent, self-serve, land-and-expand. Undercut "call us."

### Enterprise — regulated & at scale

- Everything in Team, plus: multi-tenant RLS at scale + org hierarchy, WORM /
  retention (Object Lock), SCIM, the **full ServiceNow DevGovOps spoke**,
  auto-remediation with approval gates, per-framework auditor report packs,
  air-gapped/on-prem hardening, and 24×7 + SLA. Audit-support add-on available.
- **Price: `[PLACEHOLDER — custom / annual; publish a "starting at $X/yr" anchor
  so we're still less opaque than Kosli]`.**
- **Goal:** the regulated-enterprise buyer who today evaluates Kosli/Chainloop —
  won on tamper-evidence + self-hostable + deep ServiceNow.

## Licensing model (open-core)

Two candidate models — **pick one before publishing:**

| Model | Core license | Enterprise features | Notes |
|---|---|---|---|
| **A. Permissive core** (recommended for adoption) | **Apache-2.0** | Separate commercial license / EE modules | Maximum "truly open" credibility; standard open-core (GitLab/Grafana-style). |
| **B. Source-available core** | **BSL 1.1** (converts to Apache-2.0 after N years) | Commercial license | Protects against a hyperscaler reselling us as SaaS; slightly less "OSS-pure." |

Recommendation: **Model A** — the whole point is to win the "open-source
alternative" white-space, and a permissive core maximizes that credibility. Gate
value on **enterprise features + hosting + support**, not on the license.

## How we compare (the table we put on the website)

| | **Fides Community** | **Fides Enterprise** | **Kosli** |
|---|---|---|---|
| Price transparency | Public | Public anchor + custom | **Opaque ("contact us")** |
| Self-host / air-gapped | ✅ Free | ✅ Supported | ❌ SaaS-only |
| Open-source core | ✅ | ✅ | ❌ |
| Tamper-evident evidence chain | ✅ | ✅ | ✅ |
| AI-native (MCP) control plane | ✅ | ✅ | AI Q&A only |
| Deep ServiceNow spoke | Basic | ✅ Full | Partial |

## Open questions for you

1. **Numbers:** confirm the Team per-developer price and whether Enterprise gets
   a public "starting at" anchor (recommended — it still beats Kosli's opacity).
2. **License:** Model A (Apache-2.0) vs Model B (BSL)?
3. **ServiceNow boundary:** keep the governed MCP client + basic write-back in
   the free core (current draft), or move all of ServiceNow to Enterprise?
4. **Publish surface:** a `/pricing` page on the GitHub Pages site + a Go-served
   `/pricing` in-portal? (Say the word and I'll wire it once the numbers land.)

## Related
- `docs/market-analysis-2026.md` §5 Tier-3 (#8) and §3 (Kosli benchmark).
- Epic #217 (delivery-intelligence moat & new-buyer plays) — this is its last child.
