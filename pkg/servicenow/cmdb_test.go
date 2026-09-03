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
	// The IRE identify rules match cmdb_ci_docker_image on image_id and
	// cmdb_ci_docker_container on container_id. Omit either and ServiceNow
	// rejects the item with MISSING_MATCHING_ATTRIBUTES and creates nothing.
	for _, it := range p.Items {
		switch it.ClassName {
		case "cmdb_ci_docker_image":
			d, _ := it.Values["image_id"].(string)
			if !strings.HasPrefix(d, "sha256:") {
				t.Errorf("image_id must be sha256-prefixed, got %q", d)
			}
		case "cmdb_ci_docker_container":
			if id, _ := it.Values["container_id"].(string); id == "" {
				t.Errorf("container CI must carry container_id, got %+v", it.Values)
			}
		}
	}

	// Relation names must exist in cmdb_rel_type, and "Instantiates::Instance
	// of" reads parent-instantiates-child, so the image is the parent.
	for _, rel := range p.Relations {
		switch rel.Type {
		case "Instantiates::Instance of":
			if p.Items[rel.Parent].ClassName != "cmdb_ci_docker_image" {
				t.Errorf("image must be the parent of the instantiates relation, got %s",
					p.Items[rel.Parent].ClassName)
			}
		case "Depends on::Used by":
		default:
			t.Errorf("unknown cmdb_rel_type name %q", rel.Type)
		}
	}
}

// The two CI-inventory writers are gated independently: the snapshot mirror is
// off by default because it collides with whoever owns the CMDB, while the
// per-binary artifact CI is on because ARC's reconcile depends on it. Anchoring
// is not inventory and must keep working regardless of either.
func TestCMDBSinkInventoryGate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		event    string
		snapshot bool
		artifact bool
		wantCall bool
	}{
		{"snapshot suppressed when its flag is off", CMDBEventType, false, true, false},
		{"snapshot delivered when its flag is on", CMDBEventType, true, true, true},
		{"artifact suppressed when its flag is off", ArtifactEventType, false, false, false},
		{"artifact delivered when its flag is on", ArtifactEventType, false, true, true},
		// The two are independent. Defaults are snapshot=off, artifact=on: ARC's
		// scheduled reconcile reports an artifact and waits for its image CI, so
		// gating them together left that job polling for a record that would
		// never arrive.
		{"artifact survives the snapshot flag being off", ArtifactEventType, false, true, true},
		// Attaching evidence to a CI someone else owns is never gated.
		{"anchoring is never gated", AnchorEventType, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var called bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.Write([]byte(`{"result":{"hasError":false,"items":[]}}`))
			}))
			defer srv.Close()

			sink := NewCMDBSink(fakeLoader{
				cfg:     Config{InstanceURL: srv.URL, AuthType: AuthBasic, ClientID: "u", Secret: "p"},
				enabled: true,
			})
			sink.snapshotInventory = func() bool { return tc.snapshot }
			sink.artifactCI = func() bool { return tc.artifact }
			sink.newClient = func(cfg Config) (*Client, error) {
				return testClient(cfg.InstanceURL, AuthBasic, srv.Client()), nil
			}

			payload := `{"environment":"e","services":[{"service":"s","digest":"abc","registered":true}]}`
			switch tc.event {
			case ArtifactEventType:
				payload = `{"sha256":"abc","name":"img","type":"docker"}`
			case AnchorEventType:
				payload = `{"ci":"x","trail_id":"t","image_digest":"abc"}`
			}

			err := sink.Deliver(context.Background(), events.Event{
				OrgID: uuid.New(), Type: tc.event, Payload: []byte(payload),
			})
			// Anchoring against a stub server may legitimately error; the
			// assertion here is only about whether ServiceNow was contacted.
			if tc.event != AnchorEventType && err != nil {
				t.Fatalf("Deliver: %v", err)
			}
			if called != tc.wantCall {
				t.Fatalf("ServiceNow contacted = %v, want %v", called, tc.wantCall)
			}
		})
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
	// The snapshot mirror is opt-in; this test is about what gets posted once on.
	sink.snapshotInventory = func() bool { return true }

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
		// No attachment exists yet, so the anchor proceeds.
		case r.Method == http.MethodGet && r.URL.Path == "/api/now/table/sys_attachment":
			w.Write([]byte(`{"result":[]}`))
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
		// No attachment exists yet, so the anchor proceeds.
		case r.Method == http.MethodGet && r.URL.Path == "/api/now/table/sys_attachment":
			w.Write([]byte(`{"result":[]}`))
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

// The snapshot path (IRE) writes image_id and no short_description; the artifact
// path wrote short_description and no image_id, and both the resolver and this
// dedupe queried short_description alone. So Fides could not see the CI its own
// snapshot had just created: it inserted a second CI for the same digest, and
// the change gate then resolved only one of them. Both queries are now an OR
// over the two conventions, which is what this asserts.
func TestDeliverArtifactSkipsWhenOnlyIRECIExists(t *testing.T) {
	const sha = "3d0f7584ed7d04e27fa050d6683a74746608faf21f202be78460d679cc56461f"

	var gotQuery string
	var created bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/now/table/cmdb_ci_docker_image":
			gotQuery = r.URL.Query().Get("sysparm_query")
			// Shaped like a CI the IRE path created: image_id set, no short_description.
			w.Write([]byte(`{"result":[{"sys_id":"ire-ci-1","image_id":"sha256:` + sha + `"}]}`))
		case r.Method == http.MethodPost:
			created = true
			w.Write([]byte(`{"result":{"sys_id":"dupe"}}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	if err := artifactSink(srv).deliverArtifact(context.Background(), events.Event{
		OrgID: uuid.New(), Type: ArtifactEventType,
		Payload: []byte(`{"sha256":"` + sha + `","name":"payments","type":"docker"}`),
	}); err != nil {
		t.Fatalf("deliverArtifact: %v", err)
	}

	if created {
		t.Error("created a second CI for a digest the IRE path had already recorded")
	}
	if !strings.Contains(gotQuery, "image_id=sha256:"+sha) {
		t.Errorf("dedupe must match image_id (the IRE identify attribute); query was %q", gotQuery)
	}
	if !strings.Contains(gotQuery, "short_descriptionLIKEsha256:"+sha) {
		t.Errorf("dedupe must still match short_description, or CIs written by another\n"+
			"system stop being seen; query was %q", gotQuery)
	}
}

// image_id as well as short_description: it is the class's IRE identify
// attribute, so writing it is what lets ServiceNow reconcile a later snapshot
// onto this row instead of creating a second one.
func TestDeliverArtifactWritesImageID(t *testing.T) {
	const sha = "aa0f7584ed7d04e27fa050d6683a74746608faf21f202be78460d679cc56461f"

	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Write([]byte(`{"result":[]}`))
		case http.MethodPost:
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &body)
			w.Write([]byte(`{"result":{"sys_id":"new-ci"}}`))
		}
	}))
	defer srv.Close()

	if err := artifactSink(srv).deliverArtifact(context.Background(), events.Event{
		OrgID: uuid.New(), Type: ArtifactEventType,
		Payload: []byte(`{"sha256":"` + sha + `","name":"payments","type":"docker"}`),
	}); err != nil {
		t.Fatalf("deliverArtifact: %v", err)
	}

	if got, _ := body["image_id"].(string); got != "sha256:"+sha {
		t.Errorf("image_id = %q, want %q", got, "sha256:"+sha)
	}
	if got, _ := body["short_description"].(string); !strings.Contains(got, "sha256:"+sha) {
		t.Errorf("short_description must keep carrying the digest for readers that\n"+
			"match on it; got %q", got)
	}
}

// Event delivery is at-least-once, so a redelivery is the normal path on a
// retry, not an edge case. It used to add a second identical attachment and a
// second comments update every time.
func TestAnchorSkipsWhenAttachmentAlreadyExists(t *testing.T) {
	var attached, patched bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/now/table/sys_attachment":
			q := r.URL.Query().Get("sysparm_query")
			if !strings.Contains(q, "table_sys_id=ci-1") ||
				!strings.Contains(q, "fides-deployment-attestation-attest-1.json") {
				t.Errorf("existence check must be scoped to this CI and file name; got %q", q)
			}
			w.Write([]byte(`{"result":[{"sys_id":"att-existing"}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/now/attachment/file":
			attached = true
			w.Write([]byte(`{"result":{"sys_id":"att-dupe"}}`))
		case r.Method == http.MethodPatch:
			patched = true
			w.Write([]byte(`{"result":{}}`))
		}
	}))
	defer srv.Close()

	res, err := AnchorDeploymentAttestation(context.Background(),
		testClient(srv.URL, AuthBasic, srv.Client()),
		DeploymentAttestation{CISysID: "ci-1", AttestationID: "attest-1", TrailID: "t-1"})
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if attached {
		t.Error("attached a second copy of an attestation already on the CI")
	}
	if patched {
		t.Error("re-posted the summary comment on a redelivery")
	}
	if got, _ := res["sys_id"].(string); got != "att-existing" {
		t.Errorf("should return the existing attachment, got %v", res)
	}
}

// If the existence check cannot run (no sys_attachment read ACL, say), attach
// anyway. A duplicate attachment is untidy; a deployment with no evidence
// attached is a hole in the audit trail.
func TestAnchorFailsOpenWhenExistenceCheckErrors(t *testing.T) {
	var attached bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/now/table/sys_attachment":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":{"message":"no read access"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/now/attachment/file":
			attached = true
			w.Write([]byte(`{"result":{"sys_id":"att-1"}}`))
		case r.Method == http.MethodPatch:
			w.Write([]byte(`{"result":{}}`))
		}
	}))
	defer srv.Close()

	if _, err := AnchorDeploymentAttestation(context.Background(),
		testClient(srv.URL, AuthBasic, srv.Client()),
		DeploymentAttestation{CISysID: "ci-1", AttestationID: "attest-1"}); err != nil {
		t.Fatalf("a failed existence check must not fail the anchor: %v", err)
	}
	if !attached {
		t.Error("failed closed: no evidence was attached because the check errored")
	}
}

// artifactSink wires a CMDBSink at the stub server with the artifact-CI writer
// enabled, which is all these two tests need.
func artifactSink(srv *httptest.Server) *CMDBSink {
	sink := NewCMDBSink(fakeLoader{
		cfg:     Config{InstanceURL: srv.URL, AuthType: AuthBasic, ClientID: "u", Secret: "p"},
		enabled: true,
	})
	sink.artifactCI = func() bool { return true }
	sink.newClient = func(cfg Config) (*Client, error) {
		return testClient(cfg.InstanceURL, AuthBasic, srv.Client()), nil
	}
	return sink
}

// A published binary is not a container image and must not be filed as one.
//
// This is the mutation kill-set for the class switch in deliverArtifact. It
// fails if the binary branch is deleted (nothing is created), and it fails if a
// binary is misrouted into the docker case (a cmdb_ci_docker_image request
// appears). Together with TestDeliverArtifactWritesImageID -- which fails if
// the new branch swallows "docker" -- the shared switch is pinned in both
// directions.
//
// Before the branch existed a binary was SILENTLY DROPPED: the switch fell
// through to `return nil` and the event was delivered "successfully" with no CI
// created and nothing logged, so a change anchored to nothing and looked fine.
func TestDeliverArtifactBinaryTakesSoftwarePackageClass(t *testing.T) {
	const sha = "f15266a2bdeb2befc7c2dbb92cc7eaa56111d19bd5df6fc42706ddb8d214b723"

	var createdPaths []string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if strings.Contains(r.URL.Path, "cmdb_ci_docker_image") {
				t.Errorf("a binary must never be looked up as a container image; got GET %s", r.URL.Path)
			}
			w.Write([]byte(`{"result":[]}`))
		case http.MethodPost:
			createdPaths = append(createdPaths, r.URL.Path)
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &body)
			w.Write([]byte(`{"result":{"sys_id":"new-spkg"}}`))
		}
	}))
	defer srv.Close()

	if err := artifactSink(srv).deliverArtifact(context.Background(), events.Event{
		OrgID: uuid.New(), Type: ArtifactEventType,
		Payload: []byte(`{"sha256":"` + sha + `","name":"arc-binary-demo-1.0.0.jar","type":"binary"}`),
	}); err != nil {
		t.Fatalf("deliverArtifact: %v", err)
	}

	if len(createdPaths) == 0 {
		t.Fatal("a binary artifact created no CI at all — the silent-drop regression")
	}
	for _, p := range createdPaths {
		if strings.Contains(p, "cmdb_ci_docker_image") {
			t.Errorf("binary was filed as a container image: POST %s", p)
		}
		if !strings.Contains(p, binaryCIClass) {
			t.Errorf("POST %s is not the binary CI class %q", p, binaryCIClass)
		}
	}

	// The digest must be in short_description in FULL. That is the convention
	// every other digest-bearing CI in this estate uses, and binaryDigestQuery
	// LIKE-matches on it -- a truncated display digest would make the dedupe
	// silently miss and mint a second CI on every redelivery.
	if got, _ := body["short_description"].(string); !strings.Contains(got, "sha256:"+sha) {
		t.Errorf("short_description must carry the full digest; got %q", got)
	}
	if got, _ := body["name"].(string); got == "" {
		t.Error("binary CI has no name")
	}
}

// An artifact reported with no type is still an image: the CLI defaults to
// --type docker, so treating "" as anything else would retroactively
// reclassify every artifact ever reported without one.
func TestDeliverArtifactEmptyTypeStaysAnImage(t *testing.T) {
	const sha = "bb0f7584ed7d04e27fa050d6683a74746608faf21f202be78460d679cc56461f"

	var createdPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Write([]byte(`{"result":[]}`))
		case http.MethodPost:
			createdPaths = append(createdPaths, r.URL.Path)
			w.Write([]byte(`{"result":{"sys_id":"new-ci"}}`))
		}
	}))
	defer srv.Close()

	if err := artifactSink(srv).deliverArtifact(context.Background(), events.Event{
		OrgID: uuid.New(), Type: ArtifactEventType,
		Payload: []byte(`{"sha256":"` + sha + `","name":"payments"}`),
	}); err != nil {
		t.Fatalf("deliverArtifact: %v", err)
	}

	if len(createdPaths) != 1 || !strings.Contains(createdPaths[0], "cmdb_ci_docker_image") {
		t.Errorf("empty type must still create a docker image CI; got %v", createdPaths)
	}
}
