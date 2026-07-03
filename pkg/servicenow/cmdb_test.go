package servicenow

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestAnchorDeploymentAttestationUploadsAttachmentAndUpdatesCI is the core
// proof for issue #228: anchoring a signed deployment attestation onto a CMDB
// CI must (1) upload it as a file attachment carrying the image digest, commit,
// build log ref and runtime snapshot ref, and (2) best-effort summarize it onto
// the CI record itself.
func TestAnchorDeploymentAttestationUploadsAttachmentAndUpdatesCI(t *testing.T) {
	var attachPath, attachQuery string
	var attachBody DeploymentAttestation
	var updatePath string
	var updateBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/now/attachment/file":
			attachPath = r.URL.Path
			attachQuery = r.URL.RawQuery
			if err := json.Unmarshal(b, &attachBody); err != nil {
				t.Errorf("decode attachment body: %v", err)
			}
			w.Write([]byte(`{"result":{"sys_id":"att-1","file_name":"fides-deployment-attestation-attest-1.json"}}`))
		case r.Method == http.MethodPatch:
			updatePath = r.URL.Path
			if err := json.Unmarshal(b, &updateBody); err != nil {
				t.Errorf("decode update body: %v", err)
			}
			w.Write([]byte(`{"result":{"sys_id":"ci-1"}}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	client := testClient(srv.URL, AuthBasic, srv.Client())
	att := DeploymentAttestation{
		CISysID:       "ci-1",
		ChangeNumber:  "CHG0030192",
		TrailID:       "trail-1",
		FlowName:      "payments-api",
		ImageDigest:   "abc123def456abc123def456abc123def456abc123def456abc123def456ab",
		Commit:        "deadbeefcafefeed0123456789abcdef0123456",
		BuildLogRef:   "https://ci.example.com/builds/42",
		SnapshotRef:   "snap-9",
		AttestationID: "attest-1",
		ContentHash:   "hash-1",
		Compliant:     true,
	}

	result, err := AnchorDeploymentAttestation(context.Background(), client, att)
	if err != nil {
		t.Fatalf("AnchorDeploymentAttestation: %v", err)
	}
	if result["sys_id"] != "att-1" {
		t.Fatalf("expected attachment result, got %+v", result)
	}

	if attachPath != "/api/now/attachment/file" {
		t.Fatalf("attachment path = %s", attachPath)
	}
	if !strings.Contains(attachQuery, "table_name=cmdb_ci") || !strings.Contains(attachQuery, "table_sys_id=ci-1") {
		t.Fatalf("attachment query missing table_name/table_sys_id: %s", attachQuery)
	}
	if attachBody.ImageDigest != att.ImageDigest || attachBody.Commit != att.Commit ||
		attachBody.BuildLogRef != att.BuildLogRef || attachBody.SnapshotRef != att.SnapshotRef ||
		attachBody.AttestationID != att.AttestationID || attachBody.ChangeNumber != att.ChangeNumber {
		t.Fatalf("attachment body did not carry the full attestation: %+v", attachBody)
	}

	// The CI update (PATCH) must also carry evidence of the attestation, so it
	// is visible without opening the attachment.
	if updatePath != "/api/now/table/cmdb_ci/ci-1" {
		t.Fatalf("update path = %s", updatePath)
	}
	summary, _ := updateBody["comments"].(string)
	for _, want := range []string{att.ImageDigest[:12], att.Commit[:12], att.ChangeNumber, att.BuildLogRef, att.SnapshotRef} {
		if !strings.Contains(summary, want) {
			t.Errorf("CI update comments missing %q: %s", want, summary)
		}
	}
}

func TestAnchorDeploymentAttestationRequiresCISysID(t *testing.T) {
	client := testClient("https://example.service-now.com", AuthBasic, http.DefaultClient)
	if _, err := AnchorDeploymentAttestation(context.Background(), client, DeploymentAttestation{}); err == nil {
		t.Fatal("expected error when ci_sys_id is missing")
	}
}

func TestCMDBSinkDeliverAnchorResolvesCIByNameAndAnchors(t *testing.T) {
	var sawSearch, sawAttach bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/now/table/cmdb_ci":
			sawSearch = true
			w.Write([]byte(`{"result":[{"sys_id":"ci-42","name":"payments"}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/now/attachment/file":
			sawAttach = true
			if !strings.Contains(r.URL.RawQuery, "table_sys_id=ci-42") {
				t.Errorf("expected resolved sys_id ci-42 in attachment query, got %s", r.URL.RawQuery)
			}
			w.Write([]byte(`{"result":{"sys_id":"att-2"}}`))
		case r.Method == http.MethodPatch:
			w.Write([]byte(`{"result":{}}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	sink := NewCMDBSink(fakeLoader{
		cfg:     Config{InstanceURL: srv.URL, AuthType: AuthBasic, ClientID: "u", Secret: "p"},
		enabled: true,
	})
	sink.newClient = func(cfg Config) (*Client, error) {
		return testClient(cfg.InstanceURL, cfg.AuthType, srv.Client()), nil
	}

	payload, _ := json.Marshal(DeploymentAttestation{
		CI: "payments", TrailID: "trail-1", ImageDigest: "abc", Commit: "def", Compliant: true,
	})
	ev := events.Event{ID: uuid.New(), OrgID: uuid.New(), Type: AnchorEventType, Payload: payload}
	if err := sink.Deliver(context.Background(), ev); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if !sawSearch || !sawAttach {
		t.Fatalf("expected CI search and attachment upload, got search=%v attach=%v", sawSearch, sawAttach)
	}
}

func TestCMDBSinkDeliverAnchorMissingCIErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result":[]}`))
	}))
	defer srv.Close()

	sink := NewCMDBSink(fakeLoader{
		cfg:     Config{InstanceURL: srv.URL, AuthType: AuthBasic, ClientID: "u", Secret: "p"},
		enabled: true,
	})
	sink.newClient = func(cfg Config) (*Client, error) {
		return testClient(cfg.InstanceURL, cfg.AuthType, srv.Client()), nil
	}

	payload, _ := json.Marshal(DeploymentAttestation{CI: "unknown-service", TrailID: "trail-1"})
	ev := events.Event{ID: uuid.New(), OrgID: uuid.New(), Type: AnchorEventType, Payload: payload}
	if err := sink.Deliver(context.Background(), ev); err == nil {
		t.Fatal("expected error when the CI cannot be resolved")
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
	anchorPayload, _ := json.Marshal(DeploymentAttestation{CISysID: "ci-1", TrailID: "trail-1"})
	if err := disabled.Deliver(context.Background(), events.Event{Type: AnchorEventType, Payload: anchorPayload}); err != nil {
		t.Fatalf("disabled anchor: %v", err)
	}

	other := NewCMDBSink(fakeLoader{enabled: true})
	if err := other.Deliver(context.Background(), events.Event{Type: "other", Payload: []byte("{}")}); err != nil {
		t.Fatalf("unrelated: %v", err)
	}
	if called {
		t.Fatalf("must not call ServiceNow for disabled/unrelated")
	}
}
