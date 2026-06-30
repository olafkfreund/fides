package servicenow

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"fides/pkg/events"
)

type fakeLoader struct {
	cfg     Config
	enabled bool
}

func (f fakeLoader) ServiceNowConfig(context.Context, uuid.UUID) (Config, bool, error) {
	return f.cfg, f.enabled, nil
}

func snapshotEvent(t *testing.T) events.Event {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"environment_id": "env-1",
		"snapshot_id":    "snap-1",
		"shadows":        []string{"service x running unregistered digest sha256:abc"},
		"drifts":         []string{"service y running drifted artifact"},
	})
	return events.Event{ID: uuid.New(), OrgID: uuid.New(), Type: EventType, Payload: payload}
}

func TestITOMSinkSendsEmEvents(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/global/em/jsonv2" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &body)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	sink := NewITOMSink(fakeLoader{
		cfg:     Config{InstanceURL: srv.URL, AuthType: AuthBasic, ClientID: "u", Secret: "p"},
		enabled: true,
	})
	sink.newClient = func(cfg Config) (*Client, error) {
		return testClient(cfg.InstanceURL, cfg.AuthType, srv.Client()), nil
	}

	if err := sink.Deliver(context.Background(), snapshotEvent(t)); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	recs, _ := body["records"].([]any)
	if len(recs) != 2 {
		t.Fatalf("expected 2 em_events (1 shadow + 1 drift), got %d", len(recs))
	}
	// Verify the shadow event mapped to Critical severity.
	var sawShadowCritical bool
	for _, r := range recs {
		m := r.(map[string]any)
		if m["event_class"] == "ShadowDeployment" && m["severity"] == "1" && m["message_key"] != "" {
			sawShadowCritical = true
		}
	}
	if !sawShadowCritical {
		t.Fatalf("shadow deployment should map to a Critical (1) em_event with a message_key: %+v", recs)
	}
}

func TestITOMSinkSkipsWhenDisabled(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer srv.Close()

	sink := NewITOMSink(fakeLoader{enabled: false})
	sink.newClient = func(cfg Config) (*Client, error) {
		return testClient(srv.URL, AuthBasic, srv.Client()), nil
	}
	if err := sink.Deliver(context.Background(), snapshotEvent(t)); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if called {
		t.Fatalf("disabled tenant must not call ServiceNow")
	}
}

func TestITOMSinkIgnoresUnrelatedEvents(t *testing.T) {
	sink := NewITOMSink(fakeLoader{enabled: true})
	if err := sink.Deliver(context.Background(), events.Event{Type: "other", Payload: []byte("{}")}); err != nil {
		t.Fatalf("unrelated event should be a no-op: %v", err)
	}
}
