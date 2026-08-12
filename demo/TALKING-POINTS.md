# Fides — Demo Talking Points

Narration for `just demo`. Each beat maps to a numbered step the script
prints. Run `just demo dry` first to see the whole workflow without
touching a server.

---

## The one-sentence pitch

> **Your CI already produces the evidence. Fides makes it provable, and
> turns it into a gate.**

If you only get one line in, that's the line.

## The problem, framed for the room

Pick the framing that matches your audience.

### Engineering leadership

> "How long did your last SOC2 audit take, in engineer-days? Fides turns
> that from a project into a query."

### Compliance / GRC

> "Today your evidence is screenshots in Confluence, gathered once a year,
> and unverifiable. That's not evidence — it's a claim."

### Platform / DevOps

> "You already run Trivy, cosign, and SBOM generation. That output goes
> into a log and dies. Fides makes it a release gate."

### Regulated (DORA / PSD2 / EU AI Act)

> "The regulation asks you to *demonstrate* control effectiveness
> continuously. Annual sampling doesn't demonstrate anything."

The pain to name out loud: evidence is collected *retrospectively*, by
humans, from systems that weren't designed to prove anything. So it's
expensive, late, and nobody can prove it wasn't edited.

---

## Beat-by-beat

### Preflight + seeding

> "I'm pointing at a live Fides server. It's creating a flow and an
> environment — a *flow* is a service, an *environment* is somewhere it
> runs."

Keep this fast. It's plumbing, not story.

### 1. `trail start` — record

> "A **trail** is one build of one service. It's the spine — every piece
> of evidence from here on hangs off it, and it carries the commit and the
> committer, because who wrote the code matters for segregation of duties
> later."

Point to make: this is one line in your existing pipeline. Not a new
pipeline.

### 2. `artifact report` — fingerprint

> "The build produced an artifact. We record its SHA256. From now on we're
> not talking about 'the auth service' — we're talking about *this exact
> binary*."

Point to make: the fingerprint is what makes the rest non-repudiable.
Vague identity is how compliance theatre happens.

### 3. `attest trivy` — evidence

> "Now we attach evidence from a scanner you already run. Fides has
> parsers for Trivy, Snyk, JUnit, SBOM, SLSA, GitHub and GitLab native
> attestations."

Point to make: *we are not replacing your tools.* This is the most common
objection and it's better to answer it before it's asked.

### 4. `verify-chain` — prove

> "Here's the part that makes it evidence rather than a database. The
> chain is tamper-evident — hash-linked. If anyone edited a past
> attestation, this exits 2. And we can anchor the chain head to an
> RFC3161 timestamp authority, so it's provable against an external clock
> we don't control."

This is the credibility beat. Slow down. An auditor's first question is
always "how do I know you didn't change it afterwards?"

### 5. `change-gate` — gate

> "Now the verdict. Given everything recorded — scans, approvals, who
> committed, who approved — should this go to production? Exit 0 ships.
> **Exit 2 holds.**"

This is the money beat. The whole CI integration is that exit code. No
plugin, no webhook, no agent — the job just fails.

If the gate holds, don't hide it — that's the product working:

> "It's holding, and it's telling us exactly which control isn't
> satisfied."

### 6. `control import` + `coverage` — map

> "Same evidence, now mapped onto SOC2. We ship catalogs for SOC2,
> ISO 27001, NIST 800-53, PCI-DSS, DORA, PSD2, SOX, SLSA and the EU CRA.
> Coverage is computed from evidence that already exists — nobody filled
> in a spreadsheet."

Point to make: one evidence set, many frameworks. Adding ISO after SOC2 is
close to free. That's the multi-framework cost argument.

### 7. `report --format oscal` — auditor-ready

> "And this is what the auditor gets. NIST OSCAL — a machine-readable
> standard, not a PDF someone assembled by hand the week before the
> audit."

### 8. `metrics` — DORA for free

> "Last thing: the same evidence gives you DORA metrics. You're not buying
> a compliance tool and a delivery-metrics tool. Deployment frequency,
> lead time, change failure rate — from the trails you're already
> recording."

---

## The portal

Follow `demo/screencasts/portal-storyboard.md`.

Switch to the browser here. Run the CLI demo *immediately* before this so
the Assurance Console has live activity — dead tiles undercut the "live"
claim.

Highest-value routes if you're short on time: `/` → `/controls` →
`/ai-audits` → the AI assistant.

> "Everything you just watched me type is here, for people who don't live
> in a terminal. Auditors get read access; they stop asking you for
> screenshots."

## ServiceNow

Run `just demo-servicenow`. This is the differentiator — if the prospect
runs ServiceNow, this is the close.

> **"Fides advises; ServiceNow decides."**
>
> "Bidirectional and governed. Fides reads change requests through
> ServiceNow's own MCP server. Evidence gets written back onto the change
> record as a work note and a risk score. And Now Assist gets *grounded*
> on Fides evidence — so when someone asks the assistant whether a change
> is safe, the answer is backed by real attestations instead of being
> invented."

Warning: this creates a real change request. Demo instance only.

---

## Objection handling

### "We already have this in our CI logs."

Logs are mutable, unstructured, and expire. Ask: can you prove a log line
from 8 months ago wasn't edited? That's the gap.

### "Is this replacing Trivy / Snyk / cosign?"

No — it consumes them. Fides is the evidence layer, not another scanner.
Keep every tool you have.

### "How much work to adopt?"

One line in the pipeline to open a trail, one per evidence source. Start
with a single service, read-only, no gate. Turn the gate on when you trust
it.

### "Our auditor won't accept this."

It exports NIST OSCAL, and the underlying chain is externally timestamped.
Auditors usually prefer it to screenshots — it's more verifiable than what
they get today.

### "What if it blocks a release wrongly?"

Gates are opt-in per control and per environment. There's a documented
exception workflow (`fides exception create`) with justification, approver
and expiry — the override is itself evidence.

### "Multi-tenant / data isolation?"

Every query is org-scoped from the auth token; the server never trusts an
org id in a request body. Postgres RLS is available on top.

### "Why not just build this?"

The recording is the easy part. The tamper-evidence chain, external
anchoring, eight framework catalogs, OSCAL export and the gate semantics
are the expensive parts.

## Closing

> "Three things to take away. **One:** the evidence is generated as a side
> effect of building, not gathered afterwards. **Two:** it's
> tamper-evident, so it holds up as evidence. **Three:** it's a gate, so
> compliance is enforced continuously instead of sampled once a year."

Suggested next step: one service, read-only, no gate — a two-week pilot.
Then turn on a single control and watch coverage move.

---

## Logistics

- Rehearse with `just demo dry`, then `just demo readonly` against the
  real server. Only run the full write path once you've seen it work.
- Have `just demo-render` GIFs ready as a fallback for when the network
  dies.
- Sign into the portal **before** sharing your screen.
- `DEMO_PACE=3 just demo` slows the beats down for a live audience;
  `just demo-fast` removes all pauses for recording.
