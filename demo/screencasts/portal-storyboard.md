# Portal Screencast — Storyboard

A ~3-minute guided tour of the Fides portal. Record against a seeded server
(the live env, or a local server with demo data). Capture with the Chrome
browser-automation `gif_creator`, a screen recorder, or by hand.

**Setup:** sign in first (`/login`), pick one theme, window ~1440×900. Run one
CLI quickstart (tape `01`) *just before* recording so the Assurance Console has
live activity to show.

| # | Route | Show this | Say this (narration) |
|---|-------|-----------|----------------------|
| 1 | `/` Assurance Console | Numbers ticking via SSE; the Live Checks stream; Integrations panel; coverage donut by framework. Click a stat tile (Compliant checks → `/attestations?compliant=true`). | "This is the live assurance view — every compliance check, as it happens. Tiles deep-link into the evidence behind them." |
| 2 | `/flows` Flows & Trails | The flow list; open a flow → its trails; open a trail. | "A flow is a service; a trail is one build of it. Everything hangs off a trail." |
| 3 | `/artifacts` Artifacts & SBOM | Search box; the inventory card grid; click a card → its attestations + parsed SBOM. | "Every artifact is fingerprinted by SHA256, with its SBOM and evidence one click away." |
| 4 | `/attestations` | Stat tiles + donut/dist bars; toggle the compliant filter; click through to evidence. | "This is the evidence itself — scans, signatures, approvals — filterable, and each one links to proof." |
| 5 | `/policies` | The policy list; the Monaco YAML rules editor; hit "Check & fix". | "Policies are just rules over evidence. The gate commands you saw in the CLI evaluate exactly these." |
| 6 | `/controls` Controls & Coverage | Coverage donut; drill into a control; one-click **Enforce** and watch coverage rise. | "Map evidence to SOC2, ISO, NIST, DORA… Enforce turns a control into a release gate in one click." |
| 7 | `/environments` | Environment inventory; donut + distribution. | "Runtime environments Fides snapshots and checks for drift." |
| 8 | `/ai-audits` | An AI assessment with its big compliance score and titled sections. | "The LLM reviews scans and SBOMs and scores them — findings, not just raw data." |
| 9 | `/telemetry` | Uptime + throughput tiles; runtime/DORA donut. | "Delivery and runtime metrics, from the same evidence." |
| 10 | `/settings` | Click across the tabs: Infrastructure, Directory & Groups, ServiceNow, Slack, Service Accounts, Git & Webhooks, Users. | "One place to wire in ServiceNow, Slack, your Git provider, and service accounts for CI." |
| 11 | `/help` | The Guides sidebar — Getting Started, Small & Large Teams, User Stories, CI/CD Gate. | "Every guide, in-product — including how to adopt Fides for a 3-person team or a regulated org." |
| 12 | AI Assistant (floating) | Open it, ask "what changed in the last day?"; show voice input. | "And you can just ask — the assistant queries this same data through WebMCP." |

**Close on** `/` so the last frame is the live console.

## Capturing with Chrome automation (optional)

The `mcp__claude-in-chrome__gif_creator` tool can record a scripted click-through.
Drive it route by route following the table above, capturing a few frames before
and after each navigation for smooth playback. Name outputs `portal-<route>.gif`
under `out/`. Warn before any click that could trigger a modal/confirm dialog —
those block the extension.
