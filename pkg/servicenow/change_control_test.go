package servicenow

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestControlLinkNoteAndFields(t *testing.T) {
	at := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	note := ControlLinkNote("SOC2-CC7.1", "Change Management", "att-123", at)
	if note == "" {
		t.Fatal("expected a non-empty note")
	}
	for _, want := range []string{"SOC2-CC7.1", "Change Management", "att-123", "2026-07-02T12:00:00Z"} {
		if !strings.Contains(note, want) {
			t.Errorf("note %q missing %q", note, want)
		}
	}

	fields := ControlLinkFields("SOC2-CC7.1", "Change Management", "att-123", at)
	if fields["u_fides_control"] != "SOC2-CC7.1" {
		t.Errorf("u_fides_control = %v", fields["u_fides_control"])
	}
	if fields["u_fides_attestation_id"] != "att-123" {
		t.Errorf("u_fides_attestation_id = %v", fields["u_fides_attestation_id"])
	}
	if fields["work_notes"] != note {
		t.Errorf("work_notes should equal ControlLinkNote's output")
	}

	// A control with no name still produces a usable note.
	anon := ControlLinkNote("SOC2-CC7.1", "", "att-123", at)
	if !strings.Contains(anon, "SOC2-CC7.1") || !strings.Contains(anon, "att-123") {
		t.Errorf("anonymous-name note missing key fields: %q", anon)
	}
}

// TestWriteControlLinkPatchesChangeRequest is the mock-HTTP ServiceNow write
// test: it verifies WriteControlLink queries the change_request by number and
// then PATCHes the resolved sys_id with the control/attestation reference.
func TestWriteControlLinkPatchesChangeRequest(t *testing.T) {
	var gotQuery string
	var gotPatchPath string
	var gotPatchBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			gotQuery = r.URL.Query().Get("sysparm_query")
			w.Write([]byte(`{"result":[{"sys_id":"abc123","number":"CHG0030192"}]}`))
		case http.MethodPatch:
			gotPatchPath = r.URL.Path
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &gotPatchBody)
			w.Write([]byte(`{"result":{"sys_id":"abc123"}}`))
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	}))
	defer srv.Close()

	c := testClient(srv.URL, AuthBasic, srv.Client())
	at := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	sysID, found, err := WriteControlLink(context.Background(), c, "CHG0030192", "SOC2-CC7.1", "Change Management", "att-123", at)
	if err != nil {
		t.Fatalf("WriteControlLink: %v", err)
	}
	if !found {
		t.Fatal("expected the change request to be found")
	}
	if sysID != "abc123" {
		t.Fatalf("sysID = %q", sysID)
	}
	if gotQuery != "number=CHG0030192" {
		t.Fatalf("query = %q", gotQuery)
	}
	if gotPatchPath != "/api/now/table/change_request/abc123" {
		t.Fatalf("patch path = %q", gotPatchPath)
	}
	if gotPatchBody["u_fides_control"] != "SOC2-CC7.1" {
		t.Fatalf("patch body missing u_fides_control: %+v", gotPatchBody)
	}
	if gotPatchBody["u_fides_attestation_id"] != "att-123" {
		t.Fatalf("patch body missing u_fides_attestation_id: %+v", gotPatchBody)
	}
	if gotPatchBody["work_notes"] == "" {
		t.Fatalf("expected non-empty work_notes")
	}
}

func TestWriteControlLinkNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result":[]}`))
	}))
	defer srv.Close()

	c := testClient(srv.URL, AuthBasic, srv.Client())
	sysID, found, err := WriteControlLink(context.Background(), c, "CHG9999999", "SOC2-CC7.1", "", "att-123", time.Now())
	if err != nil {
		t.Fatalf("expected no error when the change is simply not found, got %v", err)
	}
	if found || sysID != "" {
		t.Fatalf("expected found=false and empty sysID, got found=%v sysID=%q", found, sysID)
	}
}
