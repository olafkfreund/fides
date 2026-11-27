package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"fides/pkg/auth"
	"fides/pkg/db"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

func TestCRAMonthAfter(t *testing.T) {
	for _, tc := range []struct{ from, until string }{
		{"2024-01-31T18:20:00Z", "2024-02-29T18:20:00Z"},
		{"2026-01-31T18:20:00Z", "2026-02-28T18:20:00Z"},
		{"2026-12-31T00:00:00Z", "2027-01-31T00:00:00Z"},
		{"2026-01-31T01:00:00+02:00", "2026-02-28T23:00:00Z"},
	} {
		start, err := time.Parse(time.RFC3339, tc.from)
		if err != nil {
			t.Fatal(err)
		}
		if got := craMonthAfter(start).Format(time.RFC3339); got != tc.until {
			t.Errorf("%s plus one month = %s, want %s", tc.from, got, tc.until)
		}
	}
}

type inspectedCRADeadline struct {
	Stage        string     `json:"stage"`
	Revision     int64      `json:"revision"`
	DueAt        *time.Time `json:"due_at"`
	SupersededAt *time.Time `json:"superseded_at"`
	SatisfiedAt  *time.Time `json:"satisfied_at"`
}

func TestCRACasesIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to test the CRA lifecycle")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	if err := db.Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	if err := db.ApplyRLS(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	role := "fides_cra_api_" + uuid.NewString()
	quoted := pq.QuoteIdentifier(role)
	mustExec(t, pool, "CREATE ROLE "+quoted+" LOGIN PASSWORD 'test'")
	t.Cleanup(func() {
		mustExec(t, pool, "DROP OWNED BY "+quoted)
		mustExec(t, pool, "DROP ROLE "+quoted)
	})
	mustExec(t, pool, "GRANT USAGE ON SCHEMA public TO "+quoted)
	mustExec(t, pool, "GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO "+quoted)
	app, err := sql.Open("postgres", withUserPassword(dsn, role, "test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })

	org, other := uuid.New(), uuid.New()
	flow, foreignFlow := uuid.New(), uuid.New()
	trail, secondTrail, foreignTrail := uuid.New(), uuid.New(), uuid.New()
	sha, suppressedSHA := uuid.NewString(), uuid.NewString()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$1::uuid::text), ($2,$2::uuid::text)`, org, other)
	t.Cleanup(func() { _, _ = pool.Exec(`DELETE FROM organizations WHERE id IN ($1,$2)`, org, other) })
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name) VALUES ($1,$2,'flow'), ($3,$4,'flow')`, flow, org, foreignFlow, other)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name) VALUES ($1,$2,'first'), ($3,$2,'second'), ($4,$5,'foreign')`,
		trail, flow, secondTrail, foreignTrail, foreignFlow)
	mustExec(t, pool, `INSERT INTO artifacts (sha256,org_id,trail_id,name,type)
		VALUES ($1,$2,$3,'affected','docker'),($4,$2,$5,'suppressed','docker')`, sha, org, trail, suppressedSHA, secondTrail)
	mustExec(t, pool, `INSERT INTO artifact_vulnerabilities (id,org_id,artifact_sha256,cve_id,source)
		VALUES (gen_random_uuid(),$1,$2,'CVE-2026-1234','test'),(gen_random_uuid(),$1,$3,'CVE-2026-1234','test')`, org, sha, suppressedSHA)
	mustExec(t, pool, `INSERT INTO vex_statements (id,org_id,cve_id,product,status)
		VALUES (gen_random_uuid(),$1,'CVE-2026-1234',$2,'not_affected')`, org, suppressedSHA)

	t.Setenv("FIDES_RLS_ENABLED", "true")
	t.Setenv("FIDES_API_TOKEN", "unused")
	s := NewServer(app, nil, nil)
	s.craNow = func() time.Time { return time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC) }
	router := s.Routes()
	tokens := map[string]string{}
	operator := uuid.New()
	for _, p := range []auth.Principal{
		{OrgID: org, Role: auth.RoleWriter, UserID: operator, Email: "operator@example.test", Kind: "session"},
		{OrgID: org, Role: auth.RoleAdmin, UserID: operator, Kind: "session"},
		{OrgID: org, Role: auth.RoleViewer, Kind: "session"},
		{OrgID: other, Role: "foreign", Kind: "session"},
	} {
		tokens[p.Role], err = s.Sessions.Create(p, time.Hour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}
	const base = "/api/v1/cra/cases"
	do := func(role, method, path string, body any) *httptest.ResponseRecorder {
		data, err := json.Marshal(body)
		if err != nil {
			panic(err)
		}
		r := httptest.NewRequest(method, base+path, bytes.NewReader(data))
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tokens[role]})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	call := func(role, method, path string, code int, body any, out any) {
		t.Helper()
		w := do(role, method, path, body)
		if w.Code != code {
			t.Fatalf("%s %s as %s = %d, want %d: %s", method, path, role, w.Code, code, w.Body.String())
		}
		if out != nil {
			if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
				t.Fatal(err)
			}
		}
	}
	assertDeadline := func(detail craCaseDetail, stage string, revision int64, due string, satisfied bool) {
		t.Helper()
		var deadlines []inspectedCRADeadline
		if err := json.Unmarshal(detail.Deadlines, &deadlines); err != nil {
			t.Fatal(err)
		}
		for _, d := range deadlines {
			if d.Stage == stage && d.SupersededAt == nil {
				got := ""
				if d.DueAt != nil {
					got = d.DueAt.UTC().Format(time.RFC3339)
				}
				if d.Revision != revision || got != due || (d.SatisfiedAt != nil) != satisfied {
					t.Fatalf("%s deadline = %+v (due %q)", stage, d, got)
				}
				return
			}
		}
		t.Fatalf("missing current %s deadline in %s", stage, detail.Deadlines)
	}

	writer, admin, viewer := auth.RoleWriter, auth.RoleAdmin, auth.RoleViewer
	request := map[string]any{"kind": "vulnerability", "title": "Sensitive case", "awareness_at": "2026-01-29T12:00:00Z", "cve": "CVE-2026-1234"}
	call(viewer, "POST", "", 403, request, nil)
	var vuln, severe craCaseDetail
	call(writer, "POST", "", 201, request, &vuln)
	vulnPath := "/" + vuln.ID.String()
	assertDeadline(vuln, craEarlyWarning, 1, "2026-01-30T12:00:00Z", false)
	assertDeadline(vuln, craNotification, 1, "2026-02-01T12:00:00Z", false)
	assertDeadline(vuln, craFinal, 1, "", false)
	call("foreign", "GET", vulnPath, 404, nil, nil)
	var foreignList []craCase
	call("foreign", "GET", "", 200, nil, &foreignList)
	if len(foreignList) != 0 {
		t.Fatalf("foreign tenant sees %d cases", len(foreignList))
	}
	var unscoped int
	if err := app.QueryRow(`SELECT count(*) FROM cra_case_deadlines WHERE case_id = $1`, vuln.ID).Scan(&unscoped); err != nil || unscoped != 0 {
		t.Fatalf("unscoped deadline rows = %d, %v", unscoped, err)
	}
	err = db.WithOrgScope(context.Background(), app, other.String(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO cra_case_deadlines (org_id,case_id,stage,revision)
			VALUES ($1,$2,'intermediate',99)`, other, vuln.ID)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "foreign key constraint") {
		t.Fatalf("cross-tenant deadline insert = %v", err)
	}
	call(writer, "PATCH", vulnPath, 404, map[string]any{"links": []craLink{{TrailID: foreignTrail}}}, nil)
	call(writer, "PATCH", vulnPath, 200, map[string]any{"link_impact": true}, &vuln)
	if len(vuln.Links) != 1 || vuln.Links[0].ArtifactSHA256 != sha {
		t.Fatalf("impact links = %+v", vuln.Links)
	}
	call(writer, "PATCH", vulnPath, 200, map[string]any{
		"measure_available_at": "2026-02-01T12:00:00Z",
		"links":                []craLink{{TrailID: trail}, {TrailID: secondTrail}},
	}, &vuln)
	assertDeadline(vuln, craFinal, 2, "2026-02-15T12:00:00Z", false)
	correction := map[string]any{"measure_available_at": "2026-02-02T12:00:00Z", "correction_reason": "verified publication timestamp"}
	call(writer, "PATCH", vulnPath, 403, correction, nil)
	call(admin, "PATCH", vulnPath, 200, correction, &vuln)
	assertDeadline(vuln, craFinal, 3, "2026-02-16T12:00:00Z", false)
	if !bytes.Contains(vuln.Corrections, []byte("verified publication timestamp")) || !bytes.Contains(vuln.Deadlines, []byte("2026-02-15T12:00:00")) {
		t.Fatalf("correction history missing: %s %s", vuln.Corrections, vuln.Deadlines)
	}

	export := func(path, stage string) craExport {
		t.Helper()
		var out craExport
		call(writer, "POST", path+"/exports", 201, map[string]any{"stage": stage, "fields": map[string]any{"summary": "sensitive worksheet"}}, &out)
		digest := sha256.Sum256([]byte(out.Payload))
		if out.Version != 1 || out.PayloadSHA256 != hex.EncodeToString(digest[:]) || !strings.Contains(out.Payload, "fides-cra-manual-filing-worksheet") {
			t.Fatalf("invalid export %+v", out)
		}
		return out
	}
	submitBody := func(draft craExport, when, reference string) map[string]any {
		return map[string]any{"export_id": draft.ID, "worksheet_sha256": draft.PayloadSHA256, "payload_sha256": strings.Repeat("a", 64), "submitted_at": when, "external_reference": reference}
	}
	early := export(vulnPath, craEarlyWarning)
	call(viewer, "GET", vulnPath, 200, nil, &vuln)
	assertDeadline(vuln, craEarlyWarning, 1, "2026-01-30T12:00:00Z", false)
	submit := submitBody(early, "2026-01-30T11:00:00Z", "SRP early receipt")
	mismatch := submitBody(early, "2026-01-30T11:00:00Z", "SRP early receipt")
	mismatch["worksheet_sha256"] = strings.Repeat("0", 64)
	call(writer, "POST", vulnPath+"/submissions", 409, mismatch, nil)
	call(viewer, "POST", vulnPath+"/submissions", 403, submit, nil)

	// Failure after the filing insert must roll back the entire confirmation.
	mustExec(t, pool, "REVOKE INSERT ON attestations FROM "+quoted)
	call(writer, "POST", vulnPath+"/submissions", 500, submit, nil)
	mustExec(t, pool, "GRANT INSERT ON attestations TO "+quoted)
	call(writer, "GET", vulnPath, 200, nil, &vuln)
	assertDeadline(vuln, craEarlyWarning, 1, "2026-01-30T12:00:00Z", false)
	if string(vuln.Submissions) != "[]" {
		t.Fatalf("submission escaped rollback: %s", vuln.Submissions)
	}

	results := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() { results <- do(writer, "POST", vulnPath+"/submissions", submit) }()
	}
	var filing craSubmission
	codes := map[int]int{}
	for range 2 {
		result := <-results
		codes[result.Code]++
		var current craSubmission
		if err := json.Unmarshal(result.Body.Bytes(), &current); err != nil || current.ID == uuid.Nil {
			t.Fatalf("confirmation failed: %d %s", result.Code, result.Body.String())
		}
		if filing.ID != uuid.Nil && filing.ID != current.ID {
			t.Fatalf("concurrent responses have different submission IDs: %s and %s", filing.ID, current.ID)
		}
		filing = current
	}
	if codes[201] != 1 || codes[200] != 1 || !bytes.Contains(filing.RecordedBy, []byte(operator.String())) {
		t.Fatalf("confirmation statuses or operator wrong: %v %+v", codes, filing)
	}
	if filing.PayloadSHA256 != strings.Repeat("a", 64) || filing.WorksheetSHA256 != early.PayloadSHA256 {
		t.Fatalf("incorrect filing or worksheet digest: %+v", filing)
	}
	changedFiling := submitBody(early, "2026-01-30T11:00:00Z", "SRP early receipt")
	changedFiling["payload_sha256"] = strings.Repeat("b", 64)
	call(writer, "POST", vulnPath+"/submissions", 409, changedFiling, nil)

	var attests, valid int
	if err := pool.QueryRow(`SELECT count(*), count(DISTINCT trail_id) FILTER (
		WHERE payload->>'id' = $1 AND content_hash IS NOT NULL AND NOT (payload ? 'title'))
		FROM attestations WHERE type_name = 'cra.submission' AND trail_id IN ($2,$3)`,
		filing.ID.String(), trail, secondTrail).Scan(&attests, &valid); err != nil || attests != 2 || valid != 2 {
		t.Fatalf("evidence total=%d valid linked trails=%d: %v", attests, valid, err)
	}
	call(writer, "PATCH", vulnPath, 404, map[string]any{
		"previously_supplied": craEarlierInformation{Stage: craNotification, SubmissionID: early.ID},
	}, nil)
	call(writer, "PATCH", vulnPath, 200, map[string]any{
		"previously_supplied": craEarlierInformation{Stage: craNotification, SubmissionID: filing.ID},
	}, &vuln)
	assertDeadline(vuln, craNotification, 1, "2026-02-01T12:00:00Z", true)

	call(writer, "POST", "", 201, map[string]any{"kind": "severe-incident", "title": "Incident", "awareness_at": "2026-01-30T00:00:00Z"}, &severe)
	severePath := "/" + severe.ID.String()
	assertDeadline(severe, craFinal, 1, "", false)
	call(writer, "POST", severePath+"/exports", 409, map[string]string{"stage": craIntermediate}, nil)
	call(writer, "PATCH", severePath, 404, map[string]any{
		"previously_supplied": craEarlierInformation{Stage: craNotification, SubmissionID: filing.ID},
	}, nil)
	n := export(severePath, craNotification)
	call(writer, "POST", severePath+"/submissions", 201, submitBody(n, "2026-01-31T10:00:00Z", "SRP notification"), nil)
	call(writer, "GET", severePath, 200, nil, &severe)
	assertDeadline(severe, craFinal, 2, "2026-02-28T10:00:00Z", false)
	call(writer, "PATCH", severePath, 200, map[string]any{
		"intermediate_request": map[string]any{"requested_at": "2026-02-01T10:00:00Z", "reference": "CSIRT request"},
	}, &severe)
	assertDeadline(severe, craIntermediate, 1, "", false)
	intermediate := export(severePath, craIntermediate)
	if !strings.Contains(intermediate.Payload, "14(6)") || !strings.Contains(intermediate.Payload, "CSIRT request") {
		t.Fatalf("intermediate worksheet lacks request: %s", intermediate.Payload)
	}
	call(writer, "POST", severePath+"/submissions", 201, submitBody(intermediate, "2026-02-02T10:00:00Z", "SRP intermediate receipt"), nil)
	call(writer, "GET", severePath, 200, nil, &severe)
	assertDeadline(severe, craIntermediate, 1, "", true)
	assertDeadline(severe, craFinal, 2, "2026-02-28T10:00:00Z", false)
	var supplied craCaseDetail
	call(writer, "POST", "", 201, map[string]any{
		"kind": "severe-incident", "title": "Early information", "awareness_at": "2026-01-30T00:00:00Z",
	}, &supplied)
	suppliedPath := "/" + supplied.ID.String()
	draft := export(suppliedPath, craEarlyWarning)
	var earlyReceipt craSubmission
	call(writer, "POST", suppliedPath+"/submissions", 201,
		submitBody(draft, "2026-01-31T11:00:00Z", "SRP complete early filing"), &earlyReceipt)
	call(writer, "PATCH", suppliedPath, 200, map[string]any{
		"previously_supplied": craEarlierInformation{Stage: craNotification, SubmissionID: earlyReceipt.ID},
	}, &supplied)
	assertDeadline(supplied, craFinal, 2, "2026-02-28T11:00:00Z", false)

	list := do(viewer, "GET", "?limit=1", nil)
	if list.Code != 200 || !strings.Contains(list.Header().Get("Link"), "cursor=") {
		t.Fatalf("list did not paginate: %d %s", list.Code, list.Body.String())
	}
}
