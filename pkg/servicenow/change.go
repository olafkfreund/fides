package servicenow

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"fides/pkg/ledger"
)

// changeFields are the change_request columns Fides reads for gating.
var changeFields = []string{"sys_id", "number", "state", "approval", "risk", "on_hold", "short_description", "start_date", "end_date", "cmdb_ci"}

// QueryChangeRequest returns the first change_request matching the encoded query
// (e.g. `number=CHG0030192` or `cmdb_ci.name=payments^active=true`).
func QueryChangeRequest(ctx context.Context, client *Client, sysparmQuery string) (map[string]any, bool, error) {
	res, err := client.QueryTable(ctx, "change_request", sysparmQuery, changeFields...)
	if err != nil {
		return nil, false, err
	}
	if len(res.Result) == 0 {
		return nil, false, nil
	}
	return res.Result[0], true, nil
}

// NormalizeChange projects a raw change_request record into a stable,
// jq-evaluable payload for the `servicenow-change` attestation type.
func NormalizeChange(cr map[string]any) map[string]any {
	return map[string]any{
		"number":            str(cr["number"]),
		"state":             stateLabel(str(cr["state"])),
		"approval":          str(cr["approval"]),
		"risk":              str(cr["risk"]),
		"on_hold":           str(cr["on_hold"]) == "true",
		"short_description": str(cr["short_description"]),
	}
}

// stateLabel maps ServiceNow change_request numeric states to readable labels.
// If the value is already a label (display value), it is returned unchanged.
func stateLabel(s string) string {
	switch s {
	case "-5":
		return "new"
	case "-4":
		return "assess"
	case "-3":
		return "authorize"
	case "-2":
		return "scheduled"
	case "-1":
		return "implement"
	case "0":
		return "review"
	case "3":
		return "closed"
	case "4":
		return "canceled"
	default:
		return s
	}
}

func str(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

// BuildChangeGateNote renders a change-gate verdict as the work note written
// to a change_request. When gate["evidence_bundle"] is present (the
// tamper-evident hash-chain verdict, artifact digests, and per-type
// attestation counts backing the verdict), it is rendered as a structured
// section beneath the verdict — "Fides advises with cryptographic evidence;
// ServiceNow still decides." The evidence_bundle key is optional so this
// stays backward compatible with callers that only pass the verdict.
func BuildChangeGateNote(gate map[string]any) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Fides Change Gate — recommendation: %v (risk %v / %v)\n%v\n",
		gate["recommendation"], gate["risk_score"], gate["risk_level"], gate["summary"])
	if passed, ok := gate["passed"].([]string); ok && len(passed) > 0 {
		fmt.Fprintf(&b, "Passed controls: %s\n", strings.Join(passed, ", "))
	}
	if failed, ok := gate["failed"].([]map[string]any); ok && len(failed) > 0 {
		b.WriteString("Failed controls:\n")
		for _, f := range failed {
			fmt.Fprintf(&b, "  - %v (%v): %v\n", f["control"], f["name"], f["reasons"])
		}
	}
	if missing, ok := gate["missing_evidence"].([]map[string]any); ok && len(missing) > 0 {
		b.WriteString("Missing evidence:\n")
		for _, m := range missing {
			fmt.Fprintf(&b, "  - %v (%v): %v\n", m["control"], m["name"], m["reasons"])
		}
	}
	if bundle, ok := gate["evidence_bundle"].(map[string]any); ok {
		writeEvidenceBundleNote(&b, bundle)
	}
	return b.String()
}

// ResolveImageCIsByDigest returns the sys_ids of cmdb_ci_docker_image records
// carrying any of the given sha256 digests (bare hex or "sha256:"-prefixed).
// This is the binary anchor: the CMDB image CI recorded for a digest is the
// same digest the trail attests, so a change's artifacts resolve straight to
// the CIs that run them. Matched via short_description (see the query note
// below). Deduped and best-effort — a query error for one digest is skipped.
func ResolveImageCIsByDigest(ctx context.Context, client *Client, digests []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range digests {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		// Match on short_description, NOT a `digest` field. cmdb_ci_docker_image
		// as populated here (discovery_source=karc-portal) carries the full
		// digest in short_description ("... binary digest sha256:<hex> ...") and
		// has no queryable `digest` column -- a `digest=` query is silently
		// ignored by ServiceNow and returns unrelated rows, which would anchor
		// the change to a random image. LIKE on the sha256 string filters
		// correctly (verified: exact digest -> the one image CI; bogus -> none).
		hex := strings.TrimPrefix(d, "sha256:")
		if hex == "" {
			continue
		}
		res, err := client.QueryTable(ctx, "cmdb_ci_docker_image", "short_descriptionLIKEsha256:"+hex, "sys_id")
		if err != nil || len(res.Result) == 0 {
			continue
		}
		if sysID, _ := res.Result[0]["sys_id"].(string); sysID != "" && !seen[sysID] {
			seen[sysID] = true
			out = append(out, sysID)
		}
	}
	return out
}

// LinkAffectedCIs adds task_ci rows (the change's "Affected CIs" related list)
// linking each ci sys_id to the change, skipping pairs that already exist so
// re-runs of the change gate do not duplicate rows. Returns the number of rows
// created. Best-effort: the first create error is returned but rows already
// written stand.
func LinkAffectedCIs(ctx context.Context, client *Client, changeSysID string, ciSysIDs []string) (int, error) {
	created := 0
	for _, ci := range ciSysIDs {
		if ci == "" {
			continue
		}
		res, err := client.QueryTable(ctx, "task_ci", "task="+changeSysID+"^ci_item="+ci, "sys_id")
		if err == nil && res != nil && len(res.Result) > 0 {
			continue // already linked
		}
		if _, err := client.CreateRecord(ctx, "task_ci", map[string]any{"task": changeSysID, "ci_item": ci}); err != nil {
			return created, err
		}
		created++
	}
	return created, nil
}

// writeEvidenceBundleNote renders the signed evidence bundle as a structured
// section of the work note: the tamper-evidence chain verdict (INTACT vs
// TAMPERED, with the break point when broken), the artifact digests produced
// by the trail, and a per-attestation-type compliance count.
func writeEvidenceBundleNote(b *strings.Builder, bundle map[string]any) {
	b.WriteString("Evidence bundle:\n")
	if verdict, ok := bundle["chain"].(ledger.Verdict); ok {
		status := "INTACT"
		if !verdict.Valid {
			status = "TAMPERED"
		}
		fmt.Fprintf(b, "  Chain: %s (%d attestations verified", status, verdict.Count)
		if !verdict.Valid {
			fmt.Fprintf(b, ", broken at index %d: %s", verdict.BrokenAt, verdict.Reason)
		}
		b.WriteString(")\n")
	}
	if artifacts, ok := bundle["artifacts"].([]map[string]any); ok && len(artifacts) > 0 {
		b.WriteString("  Artifact digests:\n")
		for _, a := range artifacts {
			fmt.Fprintf(b, "    - %v: sha256:%v\n", a["name"], a["sha256"])
		}
	}
	if counts, ok := bundle["attestation_types"].(map[string]map[string]int); ok && len(counts) > 0 {
		types := slices.Sorted(maps.Keys(counts))
		b.WriteString("  Attestation types:\n")
		for _, t := range types {
			c := counts[t]
			fmt.Fprintf(b, "    - %s: %d compliant / %d total\n", t, c["compliant"], c["total"])
		}
	}
}
