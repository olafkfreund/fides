package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fides/pkg/events"
	"os"
	"testing"
	"time"

	"fides/pkg/db"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

func TestCRARemindersIntegration(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run the CRA reminder worker against PostgreSQL")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.Migrate(ctx, admin); err != nil {
		t.Fatal(err)
	}
	if err := db.ApplyRLS(ctx, admin); err != nil {
		t.Fatal(err)
	}

	user := "fides_cra_reminder_" + uuid.New().String()
	role := pq.QuoteIdentifier(user)
	exec := func(q string, args ...any) { mustExec(t, admin, q, args...) }
	exec("CREATE ROLE " + role + " LOGIN PASSWORD 'test'")
	t.Cleanup(func() {
		exec("DROP OWNED BY " + role)
		exec("DROP ROLE " + role)
	})
	exec("GRANT USAGE ON SCHEMA public TO " + role)
	exec("GRANT SELECT ON organizations TO " + role)
	exec("GRANT SELECT, INSERT ON cra_reminder_orgs TO " + role)
	exec("GRANT SELECT, INSERT, UPDATE ON cra_case_deadlines TO " + role)
	app, err := sql.Open("postgres", withUserPassword(dsn, user, "test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })

	orgA, orgB := uuid.New(), uuid.New()
	caseA, caseB := uuid.New(), uuid.New()
	now := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	dueA := now.Add(time.Hour)
	dueB := now.Add(-time.Hour)
	exec(`INSERT INTO organizations (id, name) VALUES ($1, $1::uuid::text), ($2, $2::uuid::text)`, orgA, orgB)
	t.Cleanup(func() { exec(`DELETE FROM organizations WHERE id IN ($1, $2)`, orgA, orgB) })
	exec(`INSERT INTO cra_cases (id, org_id, kind, title, awareness_at, created_at, created_by)
	      VALUES ($1, $2, 'vulnerability', 'internal case A', $5, $5, '{}'),
	             ($3, $4, 'severe-incident', 'internal case B', $5, $5, '{}')`,
		caseA, orgA, caseB, orgB, now)

	withinOrg := func(org uuid.UUID, fn func(*sql.Tx) error) {
		t.Helper()
		if err := db.WithOrgScope(ctx, app, org.String(), fn); err != nil {
			t.Fatal(err)
		}
	}
	const insertDeadline = `INSERT INTO cra_case_deadlines
	    (org_id, case_id, stage, revision, due_at, superseded_at, satisfied_at)
	    VALUES ($1, $2, $3, $4, $5, $6, $7)`
	withinOrg(orgA, func(tx *sql.Tx) error {
		for _, d := range [][]any{
			{"early-warning", 1, dueA, nil, nil},
			{"notification", 1, dueB, now, nil},
			{"notification", 2, dueB, nil, now},
			{"final", 1, nil, nil, nil},
			{"intermediate", 1, now.Add(24 * time.Hour), nil, nil},
		} {
			if _, err := tx.ExecContext(ctx, insertDeadline, append([]any{orgA, caseA}, d...)...); err != nil {
				return err
			}
		}
		return nil
	})
	withinOrg(orgB, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, insertDeadline, orgB, caseB, "notification", 1, dueB, nil, nil)
		return err
	})

	var visible int
	if err := app.QueryRowContext(ctx, `SELECT count(*) FROM organizations WHERE id IN ($1, $2)`, orgA, orgB).Scan(&visible); err != nil || visible != 0 {
		t.Fatalf("unscoped organizations: %d, %v", visible, err)
	}
	withinOrg(orgA, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM cra_case_deadlines WHERE org_id = $1`, orgB).Scan(&visible); err != nil {
			return err
		}
		if visible != 0 {
			t.Fatalf("tenant A sees %d tenant B deadlines", visible)
		}
		return nil
	})

	type eventKey struct {
		orgID, caseID uuid.UUID
		kind, stage   string
		revision      int64
	}
	assertEvents := func(want map[eventKey]time.Time) {
		t.Helper()
		rows, err := admin.QueryContext(ctx, `SELECT org_id, event_type, payload
		    FROM integration_events WHERE org_id IN ($1, $2)`, orgA, orgB)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		seen := map[eventKey]bool{}
		for rows.Next() {
			var k eventKey
			var raw []byte
			if err := rows.Scan(&k.orgID, &k.kind, &raw); err != nil {
				t.Fatal(err)
			}
			var p events.CRADeadline
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&p); err != nil {
				t.Fatalf("invalid event payload %s: %v", raw, err)
			}
			k.caseID, k.stage, k.revision = p.CaseID, p.Stage, p.Revision
			if seen[k] || !p.DueAt.Equal(want[k]) {
				t.Fatalf("unexpected or duplicate event %v, payload %s", k, raw)
			}
			seen[k] = true
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if len(seen) != len(want) {
			t.Fatalf("got %v, want %v", seen, want)
		}
	}
	sweep := func(at time.Time) {
		t.Helper()
		if err := sweepCRAReminders(ctx, app, at); err != nil {
			t.Fatal(err)
		}
	}

	// A failed outbox write rolls back both phase markers and can be retried.
	if err := sweepCRAReminders(ctx, app, now); err == nil {
		t.Fatal("expected outbox enqueue to fail without INSERT privilege")
	}
	assertEvents(nil)
	if err := admin.QueryRowContext(ctx, `SELECT count(*) FROM cra_case_deadlines
	    WHERE org_id IN ($1, $2) AND (due_soon_enqueued_at IS NOT NULL OR overdue_enqueued_at IS NOT NULL)`,
		orgA, orgB).Scan(&visible); err != nil || visible != 0 {
		t.Fatalf("phase markers after a failed enqueue: %d, %v", visible, err)
	}
	exec("GRANT INSERT ON integration_events TO " + role)

	const dueSoon = "cra.deadline.due_soon"
	const overdue = "cra.deadline.overdue"
	want := map[eventKey]time.Time{{orgB, caseB, overdue, "notification", 1}: dueB}
	sweep(now.Add(-time.Second))
	assertEvents(want)

	start := make(chan struct{})
	results := make(chan error, 4)
	for range cap(results) {
		go func() {
			<-start
			results <- sweepCRAReminders(ctx, app, now)
		}()
	}
	close(start)
	for range cap(results) {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	want[eventKey{orgA, caseA, dueSoon, "early-warning", 1}] = dueA
	assertEvents(want)

	sweep(dueA)
	sweep(dueA)
	want[eventKey{orgA, caseA, overdue, "early-warning", 1}] = dueA
	assertEvents(want)

	corrected := dueA.Add(30 * time.Minute)
	withinOrg(orgA, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE cra_case_deadlines SET superseded_at = $1
		    WHERE org_id = $2 AND case_id = $3 AND stage = 'early-warning' AND revision = 1`, dueA, orgA, caseA); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, insertDeadline, orgA, caseA, "early-warning", 2, corrected, nil, nil)
		return err
	})
	sweep(dueA)
	sweep(corrected)
	want[eventKey{orgA, caseA, dueSoon, "early-warning", 2}] = corrected
	want[eventKey{orgA, caseA, overdue, "early-warning", 2}] = corrected
	assertEvents(want)
}
