package servicenow

import (
	"context"
	"fmt"
)

// changeFields are the change_request columns Fides reads for gating.
var changeFields = []string{"number", "state", "approval", "risk", "on_hold", "short_description", "start_date", "end_date", "cmdb_ci"}

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
