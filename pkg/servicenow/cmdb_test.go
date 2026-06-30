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

func TestBuildIREPayload(t *testing.T) {
	svcs := []RunningService{
		{Service: "payments", Digest: "abc123", Repository: "reg/payments", Registered: true, Environment: "prod"},
		{Service: "payments", Digest: "abc123", Repository: "reg/payments", Registered: true, Environment: "prod"}, // dup digest+service
		{Service: "frontend", Digest: "def456", Registered: false, Environment: "prod"},
		{Service: "legacy", Digest: "", Registered: true, Environment: "prod"}, // no digest -> no image CI
	}
	p := BuildIREPayload(svcs)

	// Dedup: 2 service CIs (payments, frontend, legacy = 3 services), 2 image CIs
	// (abc123, def456), and one container per input row (4 containers).
	var services, images, containers int
	for _, it := range p.Items {
		switch it.ClassName {
		case "cmdb_ci_service_discovered":
			services++
		case "cmdb_ci_docker_image":
			images++
		case "cmdb_ci_docker_container":
			containers++
		}
	}
	if services != 3 {
		t.Errorf("expected 3 service CIs, got %d", services)
	}
	if images != 2 {
		t.Errorf("expected 2 image CIs (deduped by digest), got %d", images)
	}
	if containers != 4 {
		t.Errorf("expected 4 container CIs (one per row), got %d", containers)
	}

	// Every relation index must be in range, and image digests prefixed.
	for _, rel := range p.Relations {
		if rel.Parent < 0 || rel.Parent >= len(p.Items) || rel.Child < 0 || rel.Child >= len(p.Items) {
			t.Fatalf("relation index out of range: %+v", rel)
		}
	}
	for _, it := range p.Items {
		if it.ClassName == "cmdb_ci_docker_image" {
			if d, _ := it.Values["digest"].(string); d[:7] != "sha256:" {
				t.Errorf("image digest must be sha256-prefixed, got %q", d)
			}
		}
	}
}

func TestCMDBSinkPostsIRE(t *testing.T) {
	var gotPath string
	var body IREPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &body)
		w.Write([]byte(`{"result":{}}`))
	}))
	defer srv.Close()

	sink := NewCMDBSink(fakeLoader{
		cfg:     Config{InstanceURL: srv.URL, AuthType: AuthBasic, ClientID: "u", Secret: "p"},
		enabled: true,
	})
	sink.newClient = func(cfg Config) (*Client, error) {
		return testClient(cfg.InstanceURL, cfg.AuthType, srv.Client()), nil
	}

	payload, _ := json.Marshal(reportedPayload{
		Environment: "prod",
		Services:    []RunningService{{Service: "payments", Digest: "abc", Registered: true}},
	})
	ev := events.Event{ID: uuid.New(), OrgID: uuid.New(), Type: CMDBEventType, Payload: payload}
	if err := sink.Deliver(context.Background(), ev); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if gotPath != "/api/now/identifyreconcile" {
		t.Fatalf("path = %s", gotPath)
	}
	if len(body.Items) == 0 {
		t.Fatalf("expected IRE items in the posted payload")
	}
}

func TestCMDBSinkSkipsDisabledAndUnrelated(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer srv.Close()

	disabled := NewCMDBSink(fakeLoader{enabled: false})
	disabled.newClient = func(Config) (*Client, error) { return testClient(srv.URL, AuthBasic, srv.Client()), nil }
	payload, _ := json.Marshal(reportedPayload{Services: []RunningService{{Service: "x", Digest: "y"}}})
	if err := disabled.Deliver(context.Background(), events.Event{Type: CMDBEventType, Payload: payload}); err != nil {
		t.Fatalf("disabled: %v", err)
	}

	other := NewCMDBSink(fakeLoader{enabled: true})
	if err := other.Deliver(context.Background(), events.Event{Type: "other", Payload: []byte("{}")}); err != nil {
		t.Fatalf("unrelated: %v", err)
	}
	if called {
		t.Fatalf("must not call ServiceNow for disabled/unrelated")
	}
}
