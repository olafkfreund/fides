package siem

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"fides/pkg/events"
)

func TestOTLPSinkDeliver(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := NewOTLPSink(srv.URL, "tok")
	ev := events.Event{
		ID:        uuid.New(),
		OrgID:     uuid.New(),
		Type:      "compliance.evaluated",
		Payload:   json.RawMessage(`{"trail_id":"t1"}`),
		CreatedAt: time.Unix(1700000000, 0),
	}
	if err := sink.Deliver(context.Background(), ev); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer tok")
	}

	// Verify the OTLP LogsData shape and that the event type reached the log body.
	var out struct {
		ResourceLogs []struct {
			ScopeLogs []struct {
				LogRecords []struct {
					Body struct {
						StringValue string `json:"stringValue"`
					} `json:"body"`
					Attributes []struct {
						Key   string `json:"key"`
						Value struct {
							StringValue string `json:"stringValue"`
						} `json:"value"`
					} `json:"attributes"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if err := json.Unmarshal([]byte(gotBody), &out); err != nil {
		t.Fatalf("decode OTLP body: %v (body=%s)", err, gotBody)
	}
	if len(out.ResourceLogs) != 1 || len(out.ResourceLogs[0].ScopeLogs) != 1 || len(out.ResourceLogs[0].ScopeLogs[0].LogRecords) != 1 {
		t.Fatalf("unexpected OTLP structure: %s", gotBody)
	}
	rec := out.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	if rec.Body.StringValue != "compliance.evaluated" {
		t.Errorf("log body = %q, want event type", rec.Body.StringValue)
	}
	var foundType bool
	for _, a := range rec.Attributes {
		if a.Key == "event.type" && a.Value.StringValue == "compliance.evaluated" {
			foundType = true
		}
	}
	if !foundType {
		t.Errorf("event.type attribute missing in %s", gotBody)
	}
}

func TestOTLPSinkErrorOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	sink := NewOTLPSink(srv.URL, "")
	if err := sink.Deliver(context.Background(), events.Event{CreatedAt: time.Now()}); err == nil {
		t.Fatal("expected an error on non-2xx OTLP response")
	}
}
