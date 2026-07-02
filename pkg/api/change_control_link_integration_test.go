package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"fides/pkg/auth"
)

// TestChangeControlLinkIntegration exercises the Fides-side linkage record
// (#227): resolving a trail/control/attestation and persisting the link,
// independent of ServiceNow (which is unconfigured for this org, so the
// handler must still succeed and just report servicenow_written=false).
func TestChangeControlLinkIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the change-control-link integration test")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer pool.Close()
	schema, _ := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	if _, err := pool.Exec(string(schema)); err != nil {
		t.Fatalf("schema: %v", err)
	}

	org, flow, trail := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name) VALUES ($1,$2,'t')`, trail, flow)
	mustExec(t, pool, `INSERT INTO controls (org_id,key,name,required_types) VALUES ($1,'SOC2-CC7.1','Change Management','{}')`, org)
	att1, att2 := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO attestations (id,trail_id,name,type_name,payload,is_compliant,created_at)
	                    VALUES ($1,$2,'a1','junit','{}',true, now() - interval '1 hour')`, att1, trail)
	mustExec(t, pool, `INSERT INTO attestations (id,trail_id,name,type_name,payload,is_compliant,created_at)
	                    VALUES ($1,$2,'a2','junit','{}',true, now())`, att2, trail)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: org, Email: "auditor@example.com", Role: auth.RoleAdmin, Kind: "session"})

	// Resolving without an explicit attestation_id picks the trail's most recent.
	link, status, err := s.resolveChangeControlLink(ctx, org, linkControlReq{
		TrailID: trail.String(), ControlKey: "SOC2-CC7.1", ChangeNumber: "CHG0030192",
	})
	if err != nil {
		t.Fatalf("resolveChangeControlLink: status=%d err=%v", status, err)
	}
	if link.AttestationID != att2 {
		t.Fatalf("expected the most recent attestation (%s), got %s", att2, link.AttestationID)
	}

	linkID, err := s.upsertChangeControlLink(ctx, org, link, "CHG0030192", "", "auditor@example.com", false)
	if err != nil {
		t.Fatalf("upsertChangeControlLink: %v", err)
	}

	var gotControlID, gotAttestationID uuid.UUID
	var gotChangeNumber, gotLinkedBy string
	var gotSynced bool
	if err := pool.QueryRow(
		`SELECT control_id, attestation_id, change_number, linked_by, servicenow_synced FROM change_control_links WHERE id = $1`,
		linkID).Scan(&gotControlID, &gotAttestationID, &gotChangeNumber, &gotLinkedBy, &gotSynced); err != nil {
		t.Fatalf("select link: %v", err)
	}
	if gotAttestationID != att2 || gotChangeNumber != "CHG0030192" || gotLinkedBy != "auditor@example.com" || gotSynced {
		t.Fatalf("link row wrong: attestation=%s change=%s by=%s synced=%v", gotAttestationID, gotChangeNumber, gotLinkedBy, gotSynced)
	}

	// Re-linking the same trail/control/change (e.g. after a later attestation)
	// upserts in place rather than creating a duplicate row.
	link2, _, err := s.resolveChangeControlLink(ctx, org, linkControlReq{
		TrailID: trail.String(), ControlKey: "SOC2-CC7.1", ChangeNumber: "CHG0030192", AttestationID: att1.String(),
	})
	if err != nil {
		t.Fatalf("resolveChangeControlLink (explicit attestation): %v", err)
	}
	linkID2, err := s.upsertChangeControlLink(ctx, org, link2, "CHG0030192", "sys123", "auditor@example.com", true)
	if err != nil {
		t.Fatalf("upsertChangeControlLink (update): %v", err)
	}
	if linkID2 != linkID {
		t.Fatalf("expected an upsert onto the same row, got a new id %s vs %s", linkID2, linkID)
	}
	var n int
	if err := pool.QueryRow(`SELECT count(*) FROM change_control_links WHERE trail_id = $1`, trail).Scan(&n); err != nil || n != 1 {
		t.Fatalf("expected exactly 1 link row, got %d (err=%v)", n, err)
	}

	// Unknown control -> 404, trail not found -> 404.
	if _, status, err := s.resolveChangeControlLink(ctx, org, linkControlReq{
		TrailID: trail.String(), ControlKey: "NOPE", ChangeNumber: "CHG1",
	}); err == nil || status != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown control, got status=%d err=%v", status, err)
	}
	if _, status, err := s.resolveChangeControlLink(ctx, org, linkControlReq{
		TrailID: uuid.New().String(), ControlKey: "SOC2-CC7.1", ChangeNumber: "CHG1",
	}); err == nil || status != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown trail, got status=%d err=%v", status, err)
	}

	// Full handler: ServiceNow isn't configured for this org, so it must still
	// succeed and report servicenow_written=false rather than fail the request.
	body, _ := json.Marshal(linkControlReq{TrailID: trail.String(), ControlKey: "SOC2-CC7.1", ChangeNumber: "CHG0030192"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/servicenow/link-control", bytes.NewReader(body)).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleServiceNowLinkControl(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("handleServiceNowLinkControl: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Status            string `json:"status"`
		ServiceNowWritten bool   `json:"servicenow_written"`
		ServiceNowMessage string `json:"servicenow_message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "linked" {
		t.Fatalf("status = %q", resp.Status)
	}
	if resp.ServiceNowWritten {
		t.Fatalf("expected servicenow_written=false when ServiceNow isn't configured")
	}
	if resp.ServiceNowMessage == "" {
		t.Fatalf("expected an explanatory servicenow_message")
	}
}
