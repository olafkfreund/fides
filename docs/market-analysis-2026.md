# Fides — Market Position, Competitive Analysis & ServiceNow Opportunities

> Analysis date: 2026-07-02. Competitive/regulatory research is web-sourced (2025–2026);
> market-size and pricing figures are **directional estimates**, not verified. Product
> capability claims are grounded in the Fides CLI/feature surface as of this date.

## 1. What we are, in one line

Fides is a **DevOps change-governance + provenance + continuous-compliance** platform:
it records every state change in the SDLC (flows → trails → artifacts → attestations)
into per-trail **tamper-evident hash chains**, gates deploys on policy/control coverage
with an **approve/hold verdict + 0–100 risk score**, adopts 7 control frameworks, snapshots
runtimes (docker/k8s/ecs/lambda), and is **AI-native** (MCP + WebMCP + in-cluster MCP sensor).

## 2. Market map — five overlapping categories

| Category | Leaders | Where Fides sits |
|---|---|---|
| **DevOps change gate + provenance** (our lane) | **Kosli** (benchmark), JFrog AppTrust | **Direct competitor — near parity + AI-native edge** |
| Supply-chain security / SLSA attestation | Chainguard, Sigstore/cosign, in-toto, GitHub/GitLab attestations, Aqua, Snyk, Anchore | We *consume/verify*, we don't sign images — **gap** |
| Continuous compliance / GRC automation | Vanta, Drata, Secureframe, ServiceNow IRM, AuditBoard, LogicGate | We overlap on evidence+frameworks; they own the auditor UX |
| DORA / delivery intelligence | Jellyfish, Swarmia, Harness, Octopus | We have DORA metrics; they own the analytics UX |
| Policy-as-code / admission | Kyverno, OPA/Gatekeeper, Wiz | We have env policies + admission pkg; they own K8s admission |

**Our true head-to-head is Kosli.** Everything else is adjacent — either a component we
should integrate (Sigstore, Kyverno) or a different buyer (Vanta/Drata for the CISO checklist).

## 3. Kosli vs Fides (the benchmark)

Kosli = "governance infrastructure for AI-assisted delivery in regulated industries."
Backed by Deutsche Bank, embedded in FINOS. Evidence vault, cryptographic artifact
fingerprinting, automated change gates, runtime env monitoring, hybrid/mainframe support,
"Kosli Answers" (AI compliance Q&A). Opaque enterprise SaaS pricing.

**Fides is at or near parity on the core:** hash-chained evidence, SHA256 artifact identity,
evidence-based change gates, runtime snapshots, framework catalogs, Git/Slack/ServiceNow.

**Where Fides is genuinely differentiated:**
1. **AI-native governance** — MCP server (15 tools + docs-as-resources), in-browser WebMCP,
   in-cluster MCP sensor. Agents can *query compliance and record provenance directly*.
   Kosli has AI Q&A; we have an **agent-actionable control plane**. This is our sharpest edge.
2. **Numerical 0–100 risk score** on the change gate (vs binary pass/fail).
3. **Self-hostable / own-your-data** — Postgres + embedded migrations + Helm; viable for
   air-gapped/on-prem. Kosli is SaaS-only. (Maps directly to a named market white-space.)
4. **LLM-drafted policies** (`fides policy generate --framework ... --description`).

**Where Kosli/others are ahead (our gaps):**
- Brand/credibility (DB + FINOS); hybrid/mainframe reach; polished evidence-vault UX.
- **JFrog AppTrust (Sept 2025)** is running the *same* "DevGovOps → ServiceNow" play we are,
  with an evidence-provider ecosystem (GitHub, Sonar, Aqua…). Validates our thesis, but they move fast.

## 4. Table stakes we must confirm/close

These are now baseline expectations across the market:

- **SLSA-aligned provenance + Sigstore/cosign verification.** We hash & chain, but we don't
  *generate SLSA in-toto provenance* or *verify cosign signatures*. **Highest-value gap.**
- **SBOM at build time** (CycloneDX/SPDX ingestion as a first-class attestation type + query).
- **Native SLSA/attestation ingestion** from GitHub Artifact Attestations & GitLab.
- **AI-assisted compliance** — we're ahead here via MCP; keep pressing.

## 5. Gap list — what's missing & how to add it (prioritized)

### Tier 1 — ride the regulatory wave (next 1–2 quarters)
1. **SLSA provenance + Sigstore/cosign verifier.**
   *How:* new `fides attest slsa` / `fides verify-image --sha --signer` that validates cosign
   signatures + in-toto provenance and records the verdict as an attestation. Wire into the
   change gate as a required evidence type. Closes the #1 table-stakes gap and the "SLSA
   compliance validator" positioning.
2. **First-class SBOM support** (CycloneDX/SPDX).
   *How:* `fides attest sbom --file bom.json` normalizer (like junit/trivy), component storage,
   `fides search components --purl ...`, and a "vuln-in-deployed-artifact" query. Directly
   satisfies CRA / PCI-DSS 4.0 / SSDF evidence asks.
3. **OSCAL export** for control reports.
   *How:* `fides report --framework SOC2 --format oscal`. This is the machine-readable format
   FedRAMP 20x mandates (Sept 2026 OSCAL deadline) and NIST is standardizing on. Few competitors
   have it — differentiator + federal door-opener.
4. **Segregation-of-duties as verifiable evidence** (dev ≠ approver ≠ deployer).
   *How:* we already have `fides approve` (four-eyes); add an explicit SoD attestation the change
   gate emits and ServiceNow can read. PCI-DSS 4.0 + SOX ITGC require exactly this.

### Tier 2 — deepen the moat
5. **DORA-metrics ↔ compliance correlation** (named market white-space).
   *How:* extend `fides metrics` to overlay change-failure rate vs control-coverage / risk-score
   trend. "Did velocity cost us compliance?" No competitor bridges delivery intelligence + GRC.
6. **Auto-remediation with approval gates** (white-space): policy violation → proposed fix →
   `fides approve` → apply. Start low-risk (tags, allowlist, drift re-sync).
7. **Evidence-vault UX parity** — the portal (Go-served admin pages) should present a
   Kosli-grade evidence timeline per trail/artifact, not just CLI/JSON.

### Tier 3 — positioning
8. **Publish pricing / open-core story.** Kosli's opacity is a named weakness; our self-hostable
   architecture is a wedge. An OSS/free tier attacks the "open-source Kosli alternative" white-space.
9. **EU AI Act model-provenance play** — reuse trails/attestations to record model version →
   inference → decision with long retention. New buyer, same engine.

## 6. ServiceNow — how Fides makes ServiceNow *better*

ServiceNow is **not a competitor — it's our biggest force-multiplier**. Its DevOps Change
Velocity auto-approves on **pipeline data only**, with **no cryptographic tamper-evidence, no
build-vs-deploy-time distinction, and unsigned webhooks**. IRM/GRC evidence is largely **manual
uploads** (PDFs/screenshots, versioning conflicts). Change ↔ Compliance ↔ Audit are **siloed**.
Every one of these is a Fides strength. "Fides advises; ServiceNow decides."

### Tier 1 ServiceNow integrations (highest value)
1. **Signed evidence feed into DevOps Change Velocity.** Fides posts its change-gate verdict +
   risk score + tamper-evident evidence bundle to the `change_request`; a change-approval policy
   input requires "Fides attests all gates passed." Turns SN auto-approval from *pipeline-metric*
   into *cryptographically-verified*. (We already do change-gate write-back — extend the payload
   and add a policy-input template.)
2. **Change ↔ Control linkage.** Record "CHG0030192 implemented control SOC2-CC7.1 via evidence
   E, attested at T, signature S" so both `change_request` and `sn_grc_control` reference the same
   Fides attestation. Kills the biggest GRC silo; auditors trace change→control in one hop.
3. **Deployment provenance anchored in CMDB.** On change close, attach the signed deployment
   attestation (image digest, commit, build log, runtime snapshot) to the CMDB CI — proving
   "deployment matched change intent." We already push ITOM/CMDB events; add the evidence anchor.

### Tier 2
4. **Automated control-testing feed into IRM/Audit Management.** Fides continuous checks +
   runtime snapshots replace manual evidence uploads: IRM shows live "control tested at T via
   Fides, N% compliant" instead of a screenshot in a spreadsheet.
5. **CAB risk enrichment.** Feed the 0–100 risk score + control-coverage ("8 of 10 required
   controls have current evidence") into the CAB workbench so votes are evidence-driven.
6. **Post-approval drift re-evaluation.** `fides env diff` detects drift → raise the CR risk /
   flag control non-compliance in real time (SN has no post-approval re-scoring today).

### Integration mechanics (leverage what SN already exposes)
- **HMAC-signed webhooks** — SN webhooks are unsigned by default; ours are already HMAC-signed.
  Ship a Scripted REST API + Flow Designer template that verifies the Fides signature. Instant
  security upgrade + audit trail SN lacks natively.
- Deliver as a **ServiceNow IntegrationHub spoke / Flow Designer actions** ("Attach Fides evidence
  to change", "Require Fides gate", "Anchor deployment in CMDB") so SN admins adopt with no code.
- **Ground Now Assist** — expose Fides control-coverage/evidence as context so SN's AI risk
  predictions become *explainable and cryptographically backed* instead of black-box.

## 7. Regulatory tailwinds (why now)

Convergent demand for automated, tamper-evident, continuous build→deploy evidence:
- **PCI-DSS 4.0** — mandatory since Mar 2025; auditors want 12 months of change-control + SoD evidence by end-2026.
- **DORA (EU financial regulation)** — in force Jan 2025; change-approval chains + third-party ICT evidence. *(Note: distinct from DORA delivery metrics — Fides serves both.)*
- **EU CRA** — SBOM + secure-build attestation; reporting obligations Sept 2026, full Dec 2027.
- **NIST SSDF / SLSA / CISA self-attestation** — signed provenance for software sold to US gov.
- **FedRAMP 20x** — OSCAL machine-readable evidence (Sept 2026 direction).
- **SOX ITGC & ISO 27001:2022** — shift from point-in-time to continuous evidence + SoD.
- **EU AI Act** — model provenance / record-keeping (Aug 2026 transparency obligations).

The buying thesis writes itself: *you cannot satisfy six frameworks with manual evidence and
one-tool-per-regulation.* Fides generates audit-ready evidence for all of them from one pipeline.

## 8. Recommended focus (the short list)
1. **SLSA/cosign verify + SBOM ingestion + OSCAL export** — close table-stakes, unlock CRA/SSDF/FedRAMP.
2. **Ship the ServiceNow spoke** (signed evidence → CR, change↔control link, CMDB anchor) — beat JFrog AppTrust to the "DevGovOps" story with tamper-evidence they don't have.
3. **Lean into AI-native (MCP) + self-hostable** as the two things Kosli structurally can't copy quickly.
4. **DORA↔compliance correlation** as the wedge feature no one else has.
