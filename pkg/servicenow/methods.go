package servicenow

import (
	"context"
	"fmt"
	"net/url"
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

// IdentifyReconcile upserts CIs via the CMDB Instance API IRE endpoint.
func (c *Client) IdentifyReconcile(ctx context.Context, payload IREPayload, out any) error {
	return c.doJSON(ctx, "POST", "/api/now/identifyreconcile", payload, out)
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
