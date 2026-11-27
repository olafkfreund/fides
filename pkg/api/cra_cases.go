package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"fides/pkg/auth"
	"fides/pkg/db"

	"github.com/google/uuid"
)

const (
	craEarlyWarning = "early-warning"
	craNotification = "notification"
	craFinal        = "final"
	craIntermediate = "intermediate"
)

type craError struct {
	status  int
	message string
}

func (e craError) Error() string { return e.message }

type craCase struct {
	ID                 uuid.UUID       `json:"id"`
	Kind               string          `json:"kind"`
	Title              string          `json:"title"`
	CVE                string          `json:"cve,omitempty"`
	AwarenessAt        time.Time       `json:"awareness_at"`
	MeasureAvailableAt *time.Time      `json:"measure_available_at"`
	CreatedAt          time.Time       `json:"created_at"`
	CreatedBy          json.RawMessage `json:"created_by"`
}

type craLink struct {
	TrailID        uuid.UUID `json:"trail_id"`
	ArtifactSHA256 string    `json:"artifact_sha256,omitempty"`
}

type craCaseDetail struct {
	craCase
	Links                []craLink       `json:"links"`
	Deadlines            json.RawMessage `json:"deadlines"`
	IntermediateRequests json.RawMessage `json:"intermediate_requests"`
	Exports              json.RawMessage `json:"exports"`
	Submissions          json.RawMessage `json:"submissions"`
	PreviouslySupplied   json.RawMessage `json:"previously_supplied"`
	Corrections          json.RawMessage `json:"corrections"`
}

const craCaseColumns = `id, kind, title, cve, awareness_at, measure_available_at, created_at, created_by`

func (c *craCase) scan(row interface{ Scan(...any) error }) error {
	return row.Scan(&c.ID, &c.Kind, &c.Title, &c.CVE, &c.AwarenessAt, &c.MeasureAvailableAt, &c.CreatedAt, &c.CreatedBy)
}

type craTx struct {
	ctx context.Context
	tx  *sql.Tx
	p   *auth.Principal
	now time.Time

	craCase
	actor  string
	status int
	page   *listPage
}

func (s *Server) craRoute(role string, hasID bool, handle func(*craTx, *http.Request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := auth.FromContext(r.Context())
		if !ok || p.OrgID == uuid.Nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if role != "" && !requireMutationRole(w, r, role) {
			return
		}
		c := craTx{p: p, status: http.StatusOK}
		if hasID {
			var err error
			c.ID, err = uuid.Parse(r.PathValue("id"))
			if err != nil || c.ID == uuid.Nil {
				http.Error(w, "invalid case id", http.StatusBadRequest)
				return
			}
		}
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && !hasID {
			c.page, ok = newListPage(w, r, p.OrgID, timeKey("created_at"), uuidKey("id"), true)
			if !ok {
				return
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
		result, err := s.runCRATx(r, &c, hasID, handle)
		if err != nil {
			var problem craError
			if errors.As(err, &problem) {
				http.Error(w, problem.message, problem.status)
			} else {
				internalError(w, err)
			}
			return
		}
		if c.page != nil {
			c.page.write(w, result)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(c.status)
		writeJSON(w, result)
	}
}

func (s *Server) runCRATx(r *http.Request, c *craTx, hasID bool, handle func(*craTx, *http.Request) (any, error)) (any, error) {
	ctx := r.Context()
	opts := sql.TxOptions{Isolation: sql.LevelReadCommitted}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		opts = sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}
	}
	tx, err := db.BeginTx(ctx, s.DB, &opts)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// CRA policies are installed with the migration and are always active.
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_org', $1, true)`, c.p.OrgID.String()); err != nil {
		return nil, err
	}
	c.ctx, c.tx = db.WithQuerier(ctx, tx), tx
	now := s.craNow
	if now == nil {
		now = time.Now
	}
	c.now = now().UTC().Truncate(time.Microsecond)
	actor, err := json.Marshal(map[string]any{"user_id": c.p.UserID, "email": c.p.Email, "kind": c.p.Kind})
	if err != nil {
		return nil, err
	}
	c.actor = string(actor)
	if hasID {
		q := `SELECT ` + craCaseColumns + ` FROM cra_cases WHERE org_id = $1 AND id = $2`
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			q += ` FOR UPDATE`
		}
		if err := c.scan(tx.QueryRowContext(ctx, q, c.p.OrgID, c.ID)); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, craError{http.StatusNotFound, "case not found"}
			}
			return nil, err
		}
	}
	result, err := handle(c, r.WithContext(c.ctx))
	if err != nil {
		return nil, err
	}
	return result, tx.Commit()
}

func readCRARequest(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if dec.Decode(dst) != nil || dec.Decode(new(json.RawMessage)) != io.EOF {
		return craError{http.StatusBadRequest, "invalid request JSON"}
	}
	return nil
}

func (s *Server) listCRACases(c *craTx, r *http.Request) (any, error) {
	rows, err := s.queryPage(r, c.page, `SELECT `+craCaseColumns+` /* page keys */ FROM cra_cases WHERE org_id = $1`, c.p.OrgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []craCase{}
	for rows.Next() {
		var item craCase
		if err := item.scan(rows); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (c *craTx) links() ([]craLink, error) {
	rows, err := c.tx.QueryContext(c.ctx, `SELECT trail_id, COALESCE(artifact_sha256, '')
		FROM cra_case_links WHERE org_id = $1 AND case_id = $2 ORDER BY trail_id, artifact_sha256`, c.p.OrgID, c.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	links := []craLink{}
	for rows.Next() {
		var link craLink
		if err := rows.Scan(&link.TrailID, &link.ArtifactSHA256); err != nil {
			return nil, err
		}
		links = append(links, link)
	}
	return links, rows.Err()
}

func (c *craTx) detail() (craCaseDetail, error) {
	out := craCaseDetail{craCase: c.craCase}
	var err error
	out.Links, err = c.links()
	if err != nil {
		return out, err
	}
	// Filing and worksheet identities are recorded independently.
	err = c.tx.QueryRowContext(c.ctx, `SELECT
		COALESCE((SELECT jsonb_agg(jsonb_build_object('stage', stage, 'revision', revision, 'due_at', due_at,
		  'superseded_at', superseded_at, 'satisfied_at', satisfied_at) ORDER BY stage, revision)
		  FROM cra_case_deadlines d WHERE org_id = $1 AND case_id = $2), '[]'),
		COALESCE((SELECT jsonb_agg(to_jsonb(i) - 'org_id' - 'case_id' ORDER BY revision)
		  FROM cra_case_intermediate_requests i WHERE org_id = $1 AND case_id = $2), '[]'),
		COALESCE((SELECT jsonb_agg(to_jsonb(e) - 'org_id' - 'case_id' ORDER BY created_at, id)
		  FROM cra_case_exports e WHERE org_id = $1 AND case_id = $2), '[]'),
		COALESCE((SELECT jsonb_agg((to_jsonb(s) - 'org_id') || jsonb_build_object(
		  'stage', e.stage, 'deadline_revision', e.revision, 'worksheet_sha256', e.payload_sha256) ORDER BY s.recorded_at, s.id)
		  FROM cra_case_submissions s JOIN cra_case_exports e ON e.id = s.export_id
		  WHERE s.org_id = $1 AND s.case_id = $2), '[]'),
		COALESCE((SELECT jsonb_agg(to_jsonb(p) - 'org_id' - 'case_id' ORDER BY stage)
		  FROM cra_case_previously_supplied p WHERE org_id = $1 AND case_id = $2), '[]'),
		COALESCE((SELECT jsonb_agg(to_jsonb(h) - 'org_id' - 'case_id' ORDER BY recorded_at, id)
		  FROM cra_case_corrections h WHERE org_id = $1 AND case_id = $2), '[]')`, c.p.OrgID, c.ID).
		Scan(&out.Deadlines, &out.IntermediateRequests, &out.Exports, &out.Submissions, &out.PreviouslySupplied, &out.Corrections)
	return out, err
}

func getCRACase(c *craTx, _ *http.Request) (any, error) {
	return c.detail()
}

func createCRACase(c *craTx, r *http.Request) (any, error) {
	var req struct {
		Kind               string     `json:"kind"`
		Title              string     `json:"title"`
		CVE                string     `json:"cve"`
		AwarenessAt        time.Time  `json:"awareness_at"`
		MeasureAvailableAt *time.Time `json:"measure_available_at"`
		Links              []craLink  `json:"links"`
	}
	if err := readCRARequest(r, &req); err != nil {
		return nil, err
	}
	req.Title = strings.TrimSpace(req.Title)
	req.CVE = strings.ToUpper(strings.TrimSpace(req.CVE))
	if (req.Kind != "vulnerability" && req.Kind != "severe-incident") ||
		req.Title == "" || len([]rune(req.Title)) > 255 ||
		(req.CVE != "" && cveRe.FindString(req.CVE) != req.CVE) ||
		(req.Kind != "vulnerability" && (req.MeasureAvailableAt != nil || req.CVE != "")) ||
		!c.validPast(req.AwarenessAt) || (req.MeasureAvailableAt != nil && !c.validPast(*req.MeasureAvailableAt)) {
		return nil, craError{http.StatusBadRequest, "invalid case kind, title, CVE or milestone timestamp"}
	}
	c.craCase = craCase{
		ID: uuid.New(), Kind: req.Kind, Title: req.Title, CVE: req.CVE,
		AwarenessAt: craTimestamp(req.AwarenessAt), MeasureAvailableAt: craOptionalTimestamp(req.MeasureAvailableAt),
		CreatedAt: c.now, CreatedBy: json.RawMessage(c.actor),
	}
	if _, err := c.tx.ExecContext(c.ctx, `INSERT INTO cra_cases (`+craCaseColumns+`, org_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, c.ID, c.Kind, c.Title, c.CVE,
		c.AwarenessAt, c.MeasureAvailableAt, c.CreatedAt, c.actor, c.p.OrgID); err != nil {
		return nil, err
	}
	if err := c.addLinks(req.Links, false); err != nil {
		return nil, err
	}
	if err := c.refreshDeadlines(); err != nil {
		return nil, err
	}
	c.status = http.StatusCreated
	return c.detail()
}

func (c *craTx) addLinks(links []craLink, impact bool) error {
	for _, link := range links {
		if link.TrailID == uuid.Nil && link.ArtifactSHA256 == "" {
			return craError{http.StatusBadRequest, "each link requires a trail_id or artifact_sha256"}
		}
		var trailID uuid.UUID
		var err error
		if link.ArtifactSHA256 == "" {
			err = c.tx.QueryRowContext(c.ctx, `SELECT t.id FROM trails t JOIN flows f ON f.id = t.flow_id
				WHERE f.org_id = $1 AND t.id = $2`, c.p.OrgID, link.TrailID).Scan(&trailID)
		} else {
			err = c.tx.QueryRowContext(c.ctx, `SELECT t.id FROM artifacts a JOIN trails t ON t.id = a.trail_id
				JOIN flows f ON f.id = t.flow_id WHERE a.org_id = $1 AND f.org_id = $1 AND a.sha256 = $2`,
				c.p.OrgID, link.ArtifactSHA256).Scan(&trailID)
		}
		if errors.Is(err, sql.ErrNoRows) || (err == nil && link.TrailID != uuid.Nil && link.TrailID != trailID) {
			return craError{http.StatusNotFound, "tenant artifact or trail not found"}
		}
		if err != nil {
			return err
		}
		if _, err := c.tx.ExecContext(c.ctx, `INSERT INTO cra_case_links (org_id, case_id, trail_id, artifact_sha256)
			VALUES ($1, $2, $3, NULLIF($4, '')) ON CONFLICT DO NOTHING`, c.p.OrgID, c.ID, trailID, link.ArtifactSHA256); err != nil {
			return err
		}
	}
	if !impact {
		return nil
	}
	if c.CVE == "" {
		return craError{http.StatusBadRequest, "case CVE is required for impact links"}
	}
	_, err := c.tx.ExecContext(c.ctx, `INSERT INTO cra_case_links (org_id, case_id, trail_id, artifact_sha256)
		SELECT $1, $2, t.id, a.sha256 FROM artifact_vulnerabilities av
		JOIN artifacts a ON a.sha256 = av.artifact_sha256 AND a.org_id = av.org_id
		JOIN trails t ON t.id = a.trail_id JOIN flows f ON f.id = t.flow_id AND f.org_id = av.org_id
		WHERE av.org_id = $1 AND av.cve_id = $3 AND NOT EXISTS (`+vexSuppressesArtifact+`)
		ON CONFLICT DO NOTHING`, c.p.OrgID, c.ID, c.CVE)
	return err
}
