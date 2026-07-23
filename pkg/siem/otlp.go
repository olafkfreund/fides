package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"fides/pkg/events"
)

// OTLPSink delivers events to an OpenTelemetry logs endpoint over OTLP/HTTP
// (JSON-encoded), e.g. an OpenTelemetry Collector's /v1/logs receiver — an
// alternative SIEM backend to the Splunk HEC sink (issue #312).
type OTLPSink struct {
	url    string
	token  string
	client *http.Client
}

// NewOTLPSink builds an OTLP logs sink. url is the full logs endpoint (e.g.
// http://collector:4318/v1/logs); token, if non-empty, is sent as a Bearer token.
func NewOTLPSink(url, token string) *OTLPSink {
	return &OTLPSink{url: url, token: token, client: &http.Client{Timeout: 10 * time.Second}}
}

func (s *OTLPSink) Name() string { return "otlp-logs" }

// otlpAttr builds one OTLP KeyValue (string-valued) attribute.
func otlpAttr(key, val string) map[string]any {
	return map[string]any{"key": key, "value": map[string]any{"stringValue": val}}
}

// Deliver POSTs one event as an OTLP LogsData document. A non-2xx returns an
// error so the dispatcher retries rather than dropping the event.
func (s *OTLPSink) Deliver(ctx context.Context, ev events.Event) error {
	logRecord := map[string]any{
		"timeUnixNano": strconv.FormatInt(ev.CreatedAt.UnixNano(), 10),
		"severityText": "INFO",
		"body":         map[string]any{"stringValue": ev.Type},
		"attributes": []map[string]any{
			otlpAttr("event.id", ev.ID.String()),
			otlpAttr("org.id", ev.OrgID.String()),
			otlpAttr("event.type", ev.Type),
			otlpAttr("event.payload", string(ev.Payload)),
		},
	}
	body, err := json.Marshal(map[string]any{
		"resourceLogs": []map[string]any{{
			"resource":  map[string]any{"attributes": []map[string]any{otlpAttr("service.name", "fides")}},
			"scopeLogs": []map[string]any{{"logRecords": []map[string]any{logRecord}}},
		}},
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("otlp logs: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("otlp logs returned status %d", resp.StatusCode)
	}
	return nil
}
