package servicenow

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// ----- CMDB: Identification & Reconciliation Engine (IRE) -----

// IREItem is one CI in an IRE payload.
type IREItem struct {
	ClassName string         `json:"className"`
	Values    map[string]any `json:"values"`
}

// IRERelation links two items by their index in the items slice.
type IRERelation struct {
	Parent int    `json:"parent"`
	Child  int    `json:"child"`
	Type   string `json:"type"`
}

// IREPayload is the body posted to the IRE endpoint.
type IREPayload struct {
	Items     []IREItem     `json:"items"`
	Relations []IRERelation `json:"relations,omitempty"`
}

// IREResult is the subset of the IRE response Fides needs to tell success from
// failure. IRE reports per-item rejections *inside a 200 response*, so a nil
// error from the transport means nothing on its own — see IdentifyReconcile.
type IREResult struct {
	Result struct {
		HasError  bool         `json:"hasError"`
		Items     []IREOutcome `json:"items"`
		Relations []IREOutcome `json:"relations"`
	} `json:"result"`
}

// IREOutcome is one item's or relation's fate within an IRE response.
type IREOutcome struct {
	ClassName string `json:"className"`
	SysID     string `json:"sysId"`
	Errors    []struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	} `json:"errors"`
}

// failures renders the distinct error messages across items and relations.
func (r IREResult) failures() []string {
	seen := map[string]bool{}
	var out []string
	for _, o := range append(append([]IREOutcome{}, r.Result.Items...), r.Result.Relations...) {
		for _, e := range o.Errors {
			// ABANDONED is a cascade of a real error reported elsewhere; the
			// root cause is more useful than N copies of the symptom.
			if e.Error == "ABANDONED" {
				continue
			}
			msg := fmt.Sprintf("%s: %s: %s", o.ClassName, e.Error, e.Message)
			if !seen[msg] {
				seen[msg] = true
				out = append(out, msg)
			}
		}
	}
	return out
}

// IdentifyReconcile upserts CIs via the CMDB Instance API IRE endpoint.
//
// Two things here are easy to get wrong and both fail silently:
//
//  1. IRE requires the discovery source as the sysparm_data_source *query
//     parameter*. Passing it in the body is ignored, and every item is then
//     rejected with INVALID_INPUT_DATA.
//  2. IRE answers HTTP 200 even when it commits nothing, reporting the
//     rejections per-item in the body. Returning the transport error alone
//     therefore reports success for a payload ServiceNow threw away, so we
//     decode the result and turn hasError into a real error.
func (c *Client) IdentifyReconcile(ctx context.Context, payload IREPayload) error {
	path := "/api/now/identifyreconcile?sysparm_data_source=" + url.QueryEscape(c.cfg.DataSource)

	var res IREResult
	if err := c.doJSON(ctx, "POST", path, payload, &res); err != nil {
		return err
	}
	if res.Result.HasError {
		return fmt.Errorf("servicenow: IRE rejected the payload (data source %q): %s",
			c.cfg.DataSource, strings.Join(res.failures(), "; "))
	}
	return nil
}

// ----- ITOM: Event Management -----

// Event maps to the ServiceNow em_event fields. Severity is "0".."5"
// (0=Clear, 1=Critical, 2=Major, 3=Minor, 4=Warning, 5=Info).
type Event struct {
	Source         string `json:"source"`
	EventClass     string `json:"event_class"`
	Node           string `json:"node"`
	Resource       string `json:"resource,omitempty"`
	MetricName     string `json:"metric_name,omitempty"`
	Type           string `json:"type,omitempty"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	MessageKey     string `json:"message_key,omitempty"` // idempotency / de-dupe key
	AdditionalInfo string `json:"additional_info,omitempty"`
}

// SendEvents posts events to the Event Management JSON endpoint.
func (c *Client) SendEvents(ctx context.Context, events ...Event) error {
	body := map[string]any{"records": events}
	return c.doJSON(ctx, "POST", "/api/global/em/jsonv2", body, nil)
}

// ----- ITSM: Table API -----

// TableResult wraps a ServiceNow Table API response ("result" envelope).
type TableResult struct {
	Result []map[string]any `json:"result"`
}

// QueryTable runs an encoded sysparm_query against a table and returns rows.
func (c *Client) QueryTable(ctx context.Context, table, sysparmQuery string, fields ...string) (*TableResult, error) {
	q := url.Values{}
	if sysparmQuery != "" {
		q.Set("sysparm_query", sysparmQuery)
	}
	if len(fields) > 0 {
		q.Set("sysparm_fields", joinComma(fields))
	}
	q.Set("sysparm_limit", "100")

	path := "/api/now/table/" + url.PathEscape(table) + "?" + q.Encode()
	var out TableResult
	if err := c.doJSON(ctx, "GET", path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateRecord inserts a record into a table (e.g. an incident).
func (c *Client) CreateRecord(ctx context.Context, table string, fields map[string]any) (map[string]any, error) {
	var out struct {
		Result map[string]any `json:"result"`
	}
	if err := c.doJSON(ctx, "POST", "/api/now/table/"+url.PathEscape(table), fields, &out); err != nil {
		return nil, err
	}
	return out.Result, nil
}

// UpdateRecord PATCHes a record by sys_id (e.g. to add a work note to a change).
func (c *Client) UpdateRecord(ctx context.Context, table, sysID string, fields map[string]any) (map[string]any, error) {
	var out struct {
		Result map[string]any `json:"result"`
	}
	if err := c.doJSON(ctx, "PATCH", "/api/now/table/"+url.PathEscape(table)+"/"+url.PathEscape(sysID), fields, &out); err != nil {
		return nil, err
	}
	return out.Result, nil
}

// ----- Attachment API -----

// AttachFile uploads a file to any record via the Attachment API. This is the
// ServiceNow-native way to evidence a record (e.g. a CMDB CI) — it works
// regardless of whether the target table has custom fields for the evidence,
// and shows up in the record's Attachments/Activity timeline.
func (c *Client) AttachFile(ctx context.Context, table, sysID, fileName, contentType string, data []byte) (map[string]any, error) {
	if table == "" || sysID == "" || fileName == "" {
		return nil, fmt.Errorf("servicenow: table, sysID and fileName are required")
	}
	q := url.Values{}
	q.Set("table_name", table)
	q.Set("table_sys_id", sysID)
	q.Set("file_name", fileName)
	path := "/api/now/attachment/file?" + q.Encode()

	var out struct {
		Result map[string]any `json:"result"`
	}
	if err := c.doRaw(ctx, "POST", path, contentType, data, &out); err != nil {
		return nil, err
	}
	return out.Result, nil
}

func joinComma(xs []string) string {
	s := ""
	for i, x := range xs {
		if i > 0 {
			s += ","
		}
		s += x
	}
	return s
}
