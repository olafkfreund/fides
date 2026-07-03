package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"fides/pkg/auth"
)

// TestResolveApprovalDelegation covers the DB-free authorization decision for
// on-behalf-of approval delegation: secure by default, honored only when the
// flag is on AND the caller is an Admin service token.
func TestResolveApprovalDelegation(t *testing.T) {
	adminSvc := &auth.Principal{OrgID: uuid.New(), Role: auth.RoleAdmin, Kind: "service"}
	writerSvc := &auth.Principal{OrgID: uuid.New(), Role: auth.RoleWriter, Kind: "service"}
	adminSession := &auth.Principal{OrgID: uuid.New(), Role: auth.RoleAdmin, Kind: "session", Email: "human@example.com"}

	tests := []struct {
		name          string
		enabled       bool
		principal     *auth.Principal
		onBehalfOf    string
		wantRequested bool
		wantHonored   bool
		wantIdentity  string
	}{
		{
			name:          "flag off, authorized principal -> not honored (ignored)",
			enabled:       false,
			principal:     adminSvc,
			onBehalfOf:    "user@example.com",
			wantRequested: true,
			wantHonored:   false,
			wantIdentity:  "user@example.com",
		},
		{
			name:          "flag on, admin service token, valid target -> honored",
			enabled:       true,
			principal:     adminSvc,
			onBehalfOf:    "  user@example.com  ",
			wantRequested: true,
			wantHonored:   true,
			wantIdentity:  "user@example.com",
		},
		{
			name:          "flag on, non-admin service token -> not honored",
			enabled:       true,
			principal:     writerSvc,
			onBehalfOf:    "user@example.com",
			wantRequested: true,
			wantHonored:   false,
		},
		{
			name:          "flag on, human session principal -> not honored (never upgrade)",
			enabled:       true,
			principal:     adminSession,
			onBehalfOf:    "user@example.com",
			wantRequested: true,
			wantHonored:   false,
		},
		{
			name:          "flag on, authorized, empty on_behalf_of -> no delegation requested",
			enabled:       true,
			principal:     adminSvc,
			onBehalfOf:    "   ",
			wantRequested: false,
			wantHonored:   false,
		},
		{
			name:          "flag on, nil principal -> not honored",
			enabled:       true,
			principal:     nil,
			onBehalfOf:    "user@example.com",
			wantRequested: true,
			wantHonored:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveApprovalDelegation(tc.enabled, tc.principal, tc.onBehalfOf)
			if got.requested != tc.wantRequested {
				t.Fatalf("requested = %v, want %v", got.requested, tc.wantRequested)
			}
			if got.honored != tc.wantHonored {
				t.Fatalf("honored = %v, want %v", got.honored, tc.wantHonored)
			}
			if tc.wantHonored && got.onBehalfOf != tc.wantIdentity {
				t.Fatalf("onBehalfOf = %q, want %q", got.onBehalfOf, tc.wantIdentity)
			}
		})
	}
}

// TestValidApproverIdentity covers the on_behalf_of syntactic validation that
// gates the 400 response.
func TestValidApproverIdentity(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"user@example.com", true},
		{"  user@example.com  ", true},
		{"first.last+tag@sub.example.co.uk", true},
		{"", false},
		{"   ", false},
		{"not-an-email", false},
		{"user@", false},
		{"@example.com", false},
		{"Display Name <user@example.com>", false}, // bare address only
		{"user@example.com, other@example.com", false},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := validApproverIdentity(tc.in); got != tc.want {
				t.Fatalf("validApproverIdentity(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// invokeRecordApproval drives handleRecordApproval directly with a principal on
// the context and a JSON body, returning the recorder.
func invokeRecordApproval(t *testing.T, s *Server, p *auth.Principal, trailID uuid.UUID, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	buf, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/trails/"+trailID.String()+"/approvals", strings.NewReader(string(buf)))
	req.SetPathValue("id", trailID.String())
	req = req.WithContext(auth.WithPrincipal(context.Background(), p))
	rec := httptest.NewRecorder()
	s.handleRecordApproval(rec, req)
	return rec
}

// TestRecordApprovalDelegationIntegration exercises the full on-behalf-of flow
// against Postgres: flag off ignores on_behalf_of; flag on + authorized token +
// known user records a human (kind=session) approval with delegated_by set;
// invalid email and unknown user both 400.
func TestRecordApprovalDelegationIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the approval-delegation integration test")
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

	org := uuid.New()
	flow := uuid.New()
	trail := uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name,git_commit) VALUES ($1,$2,'t','abc123')`, trail, flow)
	mustExec(t, pool, `INSERT INTO users (org_id,name,email,role) VALUES ($1,'Alice','alice@example.com','Writer')`, org)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, org) })

	s := &Server{DB: pool}
	svcAdmin := &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "service"}

	approvalRow := func() (by, kind, delegatedBy string) {
		_ = pool.QueryRow(
			`SELECT approved_by, approver_kind, COALESCE(delegated_by,'') FROM trail_approvals WHERE trail_id=$1`, trail).
			Scan(&by, &kind, &delegatedBy)
		return
	}
	reset := func() { mustExec(t, pool, `DELETE FROM trail_approvals WHERE trail_id=$1`, trail) }

	t.Run("flag off -> on_behalf_of ignored, attributed to token", func(t *testing.T) {
		reset()
		t.Setenv("FIDES_DELEGATED_APPROVAL_ENABLED", "false")
		rec := invokeRecordApproval(t, s, svcAdmin, trail, map[string]any{"reason": "r", "role": "approver", "on_behalf_of": "alice@example.com"})
		if rec.Code != http.StatusCreated {
			t.Fatalf("code = %d, want 201; body=%s", rec.Code, rec.Body.String())
		}
		by, kind, delegatedBy := approvalRow()
		if kind != "service" || by == "alice@example.com" || delegatedBy != "" {
			t.Fatalf("flag off must ignore delegation: by=%q kind=%q delegated_by=%q", by, kind, delegatedBy)
		}
	})

	t.Run("flag on + authorized + known user -> recorded as session with delegated_by", func(t *testing.T) {
		reset()
		t.Setenv("FIDES_DELEGATED_APPROVAL_ENABLED", "true")
		rec := invokeRecordApproval(t, s, svcAdmin, trail, map[string]any{"reason": "r", "role": "approver", "on_behalf_of": "alice@example.com"})
		if rec.Code != http.StatusCreated {
			t.Fatalf("code = %d, want 201; body=%s", rec.Code, rec.Body.String())
		}
		by, kind, delegatedBy := approvalRow()
		if by != "alice@example.com" || kind != "session" || delegatedBy == "" {
			t.Fatalf("delegation not honored: by=%q kind=%q delegated_by=%q", by, kind, delegatedBy)
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp["kind"] != "session" || resp["approved_by"] != "alice@example.com" || resp["delegated_by"] == nil {
			t.Fatalf("response contract mismatch: %v", resp)
		}
	})

	t.Run("flag on + invalid email -> 400", func(t *testing.T) {
		reset()
		t.Setenv("FIDES_DELEGATED_APPROVAL_ENABLED", "true")
		rec := invokeRecordApproval(t, s, svcAdmin, trail, map[string]any{"reason": "r", "role": "approver", "on_behalf_of": "not-an-email"})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("code = %d, want 400; body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("flag on + unknown user -> 400", func(t *testing.T) {
		reset()
		t.Setenv("FIDES_DELEGATED_APPROVAL_ENABLED", "true")
		rec := invokeRecordApproval(t, s, svcAdmin, trail, map[string]any{"reason": "r", "role": "approver", "on_behalf_of": "stranger@example.com"})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("code = %d, want 400; body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("flag on + non-admin service token -> ignored, attributed to token", func(t *testing.T) {
		reset()
		t.Setenv("FIDES_DELEGATED_APPROVAL_ENABLED", "true")
		writer := &auth.Principal{OrgID: org, Role: auth.RoleWriter, Kind: "service"}
		rec := invokeRecordApproval(t, s, writer, trail, map[string]any{"reason": "r", "role": "approver", "on_behalf_of": "alice@example.com"})
		if rec.Code != http.StatusCreated {
			t.Fatalf("code = %d, want 201; body=%s", rec.Code, rec.Body.String())
		}
		by, kind, delegatedBy := approvalRow()
		if kind != "service" || by == "alice@example.com" || delegatedBy != "" {
			t.Fatalf("unauthorized caller must not delegate: by=%q kind=%q delegated_by=%q", by, kind, delegatedBy)
		}
	})
}
