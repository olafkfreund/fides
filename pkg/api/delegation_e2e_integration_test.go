package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
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

// A Writer-scoped key holding may_delegate_approvals lifts a change-gate hold.
//
// The table test beside this one covers resolveApprovalDelegation in isolation,
// which is not the same claim. The capability is read off a database row, put on
// a Principal by the bearer-key auth path, and only then consulted — so a column
// that is never selected, or a Principal field that is never populated, would
// leave every one of those unit cases passing while nothing worked. This drives
// the whole chain over HTTP with a real key and asserts the verdict actually
// changes.
//
// It also pins the thing the capability exists for. Before it, the only way to
// get a counted sign-off was an Admin token, so a deploy tool had to be able to
// create service accounts and rewrite controls in order to record who approved
// a release. Here the credential that lifts the gate can do neither, and that is
// asserted rather than assumed.
func TestWriterWithDelegationCapabilityLiftsTheChangeGate(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the delegation end-to-end test")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	schema, _ := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	if _, err := pool.Exec(string(schema)); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const (
		committer = "dev@example.com"
		approver  = "approver@example.com"
		deployer  = "ci-deployer@example.com"
	)

	// A fresh organisation with no controls adopted, so the change gate reduces
	// to its approval condition. That is the point of the test rather than a
	// convenience: with controls in play the verdict is held by missing SBOMs
	// and scans no matter who signs, and the transition under test would be
	// invisible underneath them.
	org, flow, trail := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, org, "o-"+org.String()[:8])
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name,description) VALUES ($1,$2,'f','')`, flow, org)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name,git_commit,tags) VALUES ($1,$2,'t','abc123',$3::jsonb)`,
		trail, flow, `{"committer":"`+committer+`"}`)
	t.Cleanup(func() {
		if _, err := pool.Exec(`DELETE FROM organizations WHERE id=$1`, org); err != nil {
			t.Errorf("cleanup left organisation %s behind: %v", org, err)
		}
	})

	t.Setenv("FIDES_DELEGATED_APPROVAL_ENABLED", "true")
	t.Setenv("FIDES_API_TOKEN", "unused-but-required")
	t.Setenv("FIDES_API_ORG_ID", uuid.NewString())

	srv := NewServer(pool, nil, nil)
	admin := &auth.Principal{OrgID: org, Role: auth.RoleAdmin, Kind: "service"}

	// The identities have to exist before anything can approve on their behalf.
	for _, u := range []string{approver, deployer} {
		if rec := invokeSaveUser(t, srv, admin, map[string]any{"name": u, "email": u, "role": "Writer"}); rec.Code != http.StatusOK {
			t.Fatalf("register %s: code=%d body=%s", u, rec.Code, rec.Body.String())
		}
	}

	// The credential under test: Writer, so it can write evidence and
	// administer nothing, plus the one narrow permission.
	sa := uuid.New()
	mustExec(t, pool,
		`INSERT INTO service_accounts (id,org_id,name,role,may_delegate_approvals) VALUES ($1,$2,'deployer-bot','Writer',TRUE)`,
		sa, org)
	key := issueKeyForTest(t, srv, admin, sa)

	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)

	call := func(method, path, body string) (int, string) {
		t.Helper()
		var r *http.Request
		var err error
		if body == "" {
			r, err = http.NewRequest(method, ts.URL+path, nil)
		} else {
			r, err = http.NewRequest(method, ts.URL+path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
		}
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+key)
		resp, err := ts.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body2, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body2)
	}

	verdict := func() map[string]any {
		t.Helper()
		code, body := call(http.MethodGet, "/api/v1/trails/"+trail.String()+"/change-gate", "")
		if code != http.StatusOK {
			t.Fatalf("change-gate: code=%d body=%s", code, body)
		}
		var out map[string]any
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatalf("decode verdict: %v", err)
		}
		return out
	}

	// Before: nobody has signed, so it holds.
	before := verdict()
	if before["recommendation"] != "hold" {
		t.Fatalf("recommendation = %v before any approval, want hold: %v", before["recommendation"], before)
	}
	if humans(t, before) != 0 {
		t.Fatalf("human_approvers = %d before any approval", humans(t, before))
	}

	// The transition. Recorded with the Writer key over HTTP, so the capability
	// has to survive the round trip from the database through the bearer-key
	// auth path to be consulted at all.
	for _, a := range []struct{ role, who string }{
		{"approver", approver},
		{"deployer", deployer},
	} {
		code, body := call(http.MethodPost, "/api/v1/trails/"+trail.String()+"/approvals",
			`{"role":"`+a.role+`","on_behalf_of":"`+a.who+`"}`)
		if code != http.StatusCreated {
			t.Fatalf("%s approval: code=%d body=%s", a.role, code, body)
		}
		// The response says which kind was stored, and "service" is the silent
		// failure this whole change exists to remove.
		var out struct {
			Kind        string `json:"kind"`
			ApprovedBy  string `json:"approved_by"`
			DelegatedBy string `json:"delegated_by"`
		}
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatalf("decode approval: %v", err)
		}
		if out.Kind != "session" {
			t.Fatalf("%s approval stored as kind %q, want session — the capability did not reach "+
				"the delegation check (body: %s)", a.role, out.Kind, body)
		}
		if out.ApprovedBy != a.who {
			t.Errorf("approved_by = %q, want %q — a collapsed identity means four-eyes can never "+
				"be satisfied", out.ApprovedBy, a.who)
		}
	}

	// After: the hold is lifted, by a credential that cannot administer anything.
	after := verdict()
	if after["recommendation"] != "approve" {
		t.Fatalf("recommendation = %v after two delegated approvals, want approve: %v",
			after["recommendation"], after)
	}
	if got := humans(t, after); got < 2 {
		t.Errorf("human_approvers = %d, want 2", got)
	}

	// And it really is least privilege: the same key cannot administer. If this
	// ever starts passing as 2xx, the capability has been re-coupled to Admin
	// and the point of the change is gone.
	for _, probe := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/tenant/service-accounts", `{"name":"escalated","role":"Admin"}`},
		{http.MethodPost, "/api/v1/controls", `{"key":"X","name":"x","required_types":["sbom"]}`},
		{http.MethodPost, "/api/v1/tenant/users", `{"name":"n","email":"n@example.com","role":"Admin"}`},
	} {
		code, body := call(probe.method, probe.path, probe.body)
		if code < 400 {
			t.Errorf("the delegating key was allowed to %s %s (code=%d) — it is supposed to "+
				"record approvals and administer nothing: %s", probe.method, probe.path, code, body)
		}
	}
}

// humans reads approvals.human_approvers out of a change-gate verdict.
func humans(t *testing.T, verdict map[string]any) int {
	t.Helper()
	approvals, ok := verdict["approvals"].(map[string]any)
	if !ok {
		t.Fatalf("verdict has no approvals object: %v", verdict)
	}
	n, ok := approvals["human_approvers"].(float64)
	if !ok {
		t.Fatalf("approvals has no human_approvers: %v", approvals)
	}
	return int(n)
}

// issueKeyForTest mints a key for a service account through the real handler,
// so the stored hash is produced the way production produces it.
func issueKeyForTest(t *testing.T, s *Server, admin *auth.Principal, sa uuid.UUID) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenant/service-accounts/"+sa.String()+"/keys", strings.NewReader(`{"label":"e2e"}`))
	req.SetPathValue("id", sa.String())
	req = req.WithContext(auth.WithPrincipal(context.Background(), admin))
	rec := httptest.NewRecorder()
	s.handleIssueServiceAccountKey(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue key: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode key: %v", err)
	}
	if out.APIKey == "" {
		t.Fatal("issued key is empty")
	}
	return out.APIKey
}
