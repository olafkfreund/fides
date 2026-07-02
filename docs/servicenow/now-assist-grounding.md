# Ground Now Assist with Fides evidence

> Closes [#233](https://github.com/olafkfreund/fides/issues/233). Part of epic
> [#216](https://github.com/olafkfreund/fides/issues/216).

ServiceNow **Now Assist** predicts change risk and summarizes changes, but its
predictions are only as trustworthy as the context it sees. This guide exposes
**Fides control-coverage and cryptographically-signed evidence** as grounding
context so Now Assist's change-risk output becomes **explainable and
evidence-backed** — "Fides advises; ServiceNow (and its AI) decide."

## What Fides contributes

| Fides signal | Endpoint | Why Now Assist wants it |
|---|---|---|
| Change-gate verdict + 0–100 risk | `GET /api/v1/trails/{id}/change-gate` | A deterministic, evidence-derived risk to reconcile against the ML risk |
| Control coverage per framework | `GET /api/v1/controls/coverage` | Which SOC 2 / ISO / NIST controls are actually enforced, and where |
| Attestations (signed evidence) | `GET /api/v1/search/attestations` | The concrete, tamper-evident proofs behind the verdict |
| Tamper-evidence chain verdict | `GET /api/v1/trails/{id}/verify-chain` | Proof the evidence was not altered after the fact |

All are in [`pkg/api/server.go`](../../pkg/api/server.go). The change-gate response
([`change_gate.go`](../../pkg/api/change_gate.go)) already breaks risk down into
`passed`, `failed`, `missing_evidence`, and `approvals` — ready-made explanation
text.

## Pattern: a grounding Script Include

Fetch the Fides evidence for the change's trail and format it as a compact,
model-friendly context block. Bind a **Connection & Credential alias** `x_fides.api`
(same one the Flow Designer actions use — see
[`flow-designer-actions.md`](flow-designer-actions.md)).

```javascript
// FidesEvidenceContext — Script Include (client_callable = false)
var FidesEvidenceContext = Class.create();
FidesEvidenceContext.prototype = {
    initialize: function () {},

    // Returns a grounding string for a given Fides trail (attach the trail_id to
    // the change_request, e.g. a custom field u_fides_trail).
    forTrail: function (trailId) {
        var gate = this._get('/api/v1/trails/' + trailId + '/change-gate');
        var cov = this._get('/api/v1/controls/coverage');
        if (!gate) { return 'No Fides evidence available for this change.'; }

        var lines = [];
        lines.push('Fides change-gate: ' + gate.recommendation +
            ' (risk ' + gate.risk_score + '/100, ' + gate.risk_level + ').');
        lines.push(gate.summary);
        if (gate.passed && gate.passed.length) {
            lines.push('Controls satisfied by signed evidence: ' + gate.passed.join(', ') + '.');
        }
        if (gate.failed && gate.failed.length) {
            lines.push('FAILING controls: ' + this._names(gate.failed) + '.');
        }
        if (gate.missing_evidence && gate.missing_evidence.length) {
            lines.push('Missing evidence for: ' + this._names(gate.missing_evidence) + '.');
        }
        if (gate.approvals) {
            lines.push('Human approvers: ' + gate.approvals.human_approvers +
                ' (four-eyes: ' + gate.approvals.four_eyes + ').');
        }
        if (cov && cov.controls) {
            var enforced = cov.controls.filter(function (c) { return c.coverage > 0; }).length;
            lines.push('Org control coverage: ' + enforced + '/' + cov.controls.length +
                ' controls enforced in at least one environment.');
        }
        return lines.join('\n');
    },

    _names: function (arr) {
        return arr.map(function (e) { return e.control; }).join(', ');
    },

    _get: function (path) {
        var r = new sn_ws.RESTMessageV2();
        r.setConnectionAlias('x_fides.api'); // Base URL + Bearer token from the alias
        r.setHttpMethod('GET');
        r.setEndpoint('${x_fides.api}' + path);
        var resp = r.execute();
        if (resp.getStatusCode() != 200) { return null; }
        try { return JSON.parse(resp.getBody()); } catch (e) { return null; }
    },

    type: 'FidesEvidenceContext'
};
```

## Wiring it into Now Assist

Choose the surface that fits your Now Assist deployment:

1. **Now Assist skill / prompt (AI Agent Studio or Now Assist Skill Kit).** Add an
   input variable `fides_evidence` and set it from `new
   FidesEvidenceContext().forTrail(current.u_fides_trail)` in the skill's data
   step. Reference `{{fides_evidence}}` in the prompt: *"Use the following
   cryptographically-signed Fides evidence when assessing change risk; if it lists
   failing or missing controls, weight risk up and cite them by control key."*

2. **Change summarization.** Prepend the grounding block to the text handed to the
   "Summarize change" skill so the generated summary states which controls are
   proven and which are not, with the Fides risk score alongside the ML score.

3. **CAB workbench note.** Run the Script Include on CR update and write the block
   into a read-only field / work note the CAB and Now Assist both read (this also
   feeds #226's CAB risk enrichment).

## Why this matters (explainability)

- Every claim in the grounding block traces to a **signed attestation** whose
  chain can be re-verified via `GET /api/v1/trails/{id}/verify-chain` — the model
  is grounded on tamper-evident facts, not free text.
- The Fides `risk_score` is **deterministic** (`failed*25 + missing*15 +
  non_compliant*10 + 20 if no human sign-off`, capped at 100), so a reviewer can
  reconcile the AI's prediction against a rule they can audit.
- When Fides and Now Assist disagree, the difference is itself a signal for the
  CAB — surfaced, not hidden.

## Alternative: the Fides MCP server

For agentic Now Assist / external AI tooling, the same evidence is available as
**MCP tools** from `fides-mcp` (see [`docs/mcp-server.md`](../mcp-server.md)):
`get_controls_coverage`, `check_compliance`, `search_attestations`, and the docs
as `fides://docs/*` resources. Point an MCP-capable agent at `fides-mcp` instead of
hand-rolling REST calls when the platform supports it.
