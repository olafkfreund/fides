---
layout: default
title: "Fides × ServiceNow — Why They're Better Together"
description: "How Fides complements ServiceNow: the evidence layer beneath change management."
---

# Fides × ServiceNow — Why They're Better Together

> **ServiceNow runs the process. Fides delivers the proof.**
>
> Fides is the automated system-of-record for software-delivery evidence. It
> feeds ServiceNow the verified, tamper-evident facts it was never designed to
> collect — turning manual, screenshot-driven change management into
> policy-driven, audit-ready change velocity.

*A showcase pitch for the sales team — and for our ServiceNow partners.*

---

## 1. The gap Fides fills

ServiceNow is the enterprise system of **action and process** — Change, CMDB,
ITOM, incident, and workflow. It is unmatched at orchestrating *what* teams
should do.

But ServiceNow has a structural blind spot: **it doesn't watch your software
factory.** On its own it cannot prove:

- *Was this release actually tested, scanned, and approved before it shipped?*
- *Which commit produced this artifact — and is it the exact thing running in
  production right now?*
- *Does this change meet SOC 2 / ISO 27001 / NIST 800-53 / DORA control X —
  provably, not "someone ticked a box"?*

Today those answers arrive as **screenshots pasted into change tickets,
spreadsheets, and "trust me" attestations.** That is slow, manual, and
audit-fragile.

**Fides closes that loop.** It runs inside the CI/CD pipeline and the Kubernetes
runtime, automatically recording cryptographically-verifiable evidence of every
build, test, scan, approval, and deployment — then writes the resulting verdict
and risk score straight back onto the matching **ServiceNow Change Request**.

> **Fides is the evidence layer. ServiceNow remains the system of record.**

---

## 2. What Fides adds to ServiceNow

| ServiceNow does | Fides adds |
|---|---|
| Change requests & CAB workflow | An **evidence-backed approve / hold verdict + a 0–100 risk score written onto the Change Request** (work note + risk field) — so reviewers decide on facts, not attachments |
| CMDB (configuration items) | **Real provenance & runtime truth** — which artifact, from which commit, is actually running where, streamed via the ServiceNow ITOM + CMDB integration |
| ITOM event management | **Deployment & compliance events** as ITOM signals, so incidents correlate to the exact change that caused them |
| Manual attestations | **Tamper-evident attestation chains** (AES-256-GCM in transit, optional WORM retention) instead of pasted screenshots |
| Policy stated in documents | **Policy-as-code gates** — deterministic JQ rules (LLM-assisted) evaluated *before* deploy, mapped to compliance-framework controls |
| Approvals as free-text | **Segregation of duties as first-class evidence** — human sign-off (`fides approve`), with four-eyes requiring two distinct approvers |
| Reactive governance | **Drift & shadow-deployment detection** — continuous reconciliation of running workloads against verified provenance |
| Change reporting | **DORA metrics** (deployment frequency, lead time) as evidence-backed data |

### The headline advantages

1. **Change velocity** — Reviewers act on a verdict and risk score, not a pile of
   attachments. Fully-compliant changes flow through fast; humans focus on the
   genuine exceptions.
2. **Audit-ready by default** — Every change in ServiceNow is backed by an
   immutable evidence trail. A multi-week audit scramble becomes a query, with
   control-by-control reports (SOC 2, ISO 27001, NIST 800-53, PCI-DSS, DORA,
   PSD2, SOX).
3. **A CMDB you can trust** — Drift and shadow deployments are detected
   continuously, so the CMDB reflects what is *proven* to be running.
4. **Shift-left compliance** — Controls are enforced in the pipeline via the
   change gate, so ServiceNow records *prevented* risk, not just *logged* risk.
5. **AI-native** — Fides ships an MCP server (and in-browser WebMCP), so AI
   assistants can query compliance and provenance directly — future-proofing the
   ServiceNow investment.

---

## 3. The demo moment (for the sales team)

The three-minute "wow":

1. A developer merges a PR → the pipeline runs → Fides records the build, tests,
   and security scans as signed attestations (`fides trail`, `fides attest`).
2. `fides change-gate` evaluates policy + control coverage and produces an
   **approve / hold verdict with a 0–100 risk score**.
3. That verdict and risk score **appear on the matching ServiceNow Change
   Request automatically** — as a work note and a populated risk field.
4. Because four-eyes is required, the gate holds until a **distinct human
   approver** signs off (`fides approve`) — segregation of duties, proven.
5. Post-deploy, Fides snapshots the Kubernetes runtime and flags a **shadow /
   drifted container** live on stage to prove continuous reconciliation.
6. Auditor question: *"Prove this passed security."* → one click to the immutable
   evidence trail, or `fides report --framework soc2`.

**The line to close on:** *"That entire change lifecycle — evidence, verdict,
risk, the ServiceNow work-note, the audit trail — happened with zero manual data
entry."*

---

## 4. Why the ServiceNow partner team should champion Fides

- **Expands ServiceNow's footprint into DevOps / platform engineering** — the
  exact teams ServiceNow struggles to reach, where GitLab, Harness, and Kosli
  are circling. Fides makes ServiceNow the destination for DevSecOps evidence.
- **Drives ITOM & CMDB consumption** — Fides pumps high-quality, high-volume,
  verified data into the two modules ServiceNow most wants customers using.
  More data → more value → more expansion.
- **Increases stickiness** — Once change management is evidence-driven through
  Fides → ServiceNow, replacing ServiceNow means rebuilding the entire
  compliance backbone.
- **A joint compliance / DevSecOps story** — ServiceNow + Fides answers
  "govern software delivery end-to-end" in a way neither tells alone.
- **A multiplier, not a competitor** — Fides has no ITSM ambitions, no system of
  record, no workflow engine. It exists to make ServiceNow's data richer and its
  workflows faster.

**Partner one-liner:** *"Fides makes every ServiceNow change request audit-proof
and every CMDB record true — by driving more verified data into the modules
ServiceNow monetizes most."*

---

## 5. Objection handling

- ***"Doesn't ServiceNow DevOps already do this?"*** — ServiceNow DevOps
  orchestrates and correlates pipeline data. Fides **generates cryptographic
  evidence, enforces policy at the change gate, and maps it to compliance
  controls**, then writes the verdict back to ServiceNow. Complementary — Fides
  is the evidence layer beneath the workflow.
- ***"We already have change management."*** — You have the *process*. Fides
  removes the *manual evidence gathering* that makes it slow and audit-fragile.
- ***"Is the evidence trustworthy?"*** — Tamper-evident attestation chains,
  AES-256-GCM in transit, optional WORM retention, and per-tenant Row-Level
  Security — not screenshots. That is the whole point.

---

## 6. The 60-second version (for cold outreach)

> Your team already runs change management in ServiceNow. But every change ticket
> still relies on screenshots and "trust me" attestations to prove the release
> was tested, scanned, and approved — which is slow to assemble and painful at
> audit time.
>
> **Fides fixes that.** It sits in your CI/CD pipeline and Kubernetes runtime,
> automatically captures cryptographically-verifiable evidence of every build,
> test, scan, and approval, and writes an **approve/hold verdict plus a 0–100
> risk score straight back onto the matching ServiceNow Change Request** — with
> the CMDB and ITOM enriched by what's *actually* running.
>
> ServiceNow stays your system of record. Fides becomes the evidence layer
> beneath it: faster change velocity, a CMDB you can trust, and audit-readiness
> by default across SOC 2, ISO 27001, NIST 800-53, and DORA.
>
> **One line:** *ServiceNow runs the process — Fides delivers the proof.*

---

*Ready to go deeper? See the [ServiceNow integration guide](/docs/servicenow-integration.md),
the live admin page at `/servicenow`, or the [full user guide](/guide.html).*
