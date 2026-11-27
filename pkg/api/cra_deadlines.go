package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"fides/pkg/auth"

	"github.com/google/uuid"
)

func craTimestamp(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }

func craOptionalTimestamp(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := craTimestamp(*t)
	return &v
}

func (c *craTx) validPast(t time.Time) bool {
	return !t.IsZero() && t.UTC().Year() >= 1 && !craTimestamp(t).After(c.now)
}

func craMonthAfter(t time.Time) time.Time {
	t = t.UTC()
	y, m, d := t.Date()
	last := time.Date(y, m+2, 0, 0, 0, 0, 0, time.UTC).Day()
	return time.Date(y, m+1, min(d, last), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
}

type craDeadline struct {
	revision    int64
	dueAt       *time.Time
	satisfiedAt *time.Time
}

func (c *craTx) deadline(stage string) (craDeadline, error) {
	var d craDeadline
	err := c.tx.QueryRowContext(c.ctx, `SELECT revision, due_at, satisfied_at FROM cra_case_deadlines
		WHERE org_id = $1 AND case_id = $2 AND stage = $3 AND superseded_at IS NULL`,
		c.p.OrgID, c.ID, stage).Scan(&d.revision, &d.dueAt, &d.satisfiedAt)
	return d, err
}

func (c *craTx) reviseDeadline(stage string, prev craDeadline, due, satisfied *time.Time) error {
	if prev.revision != 0 {
		if _, err := c.tx.ExecContext(c.ctx, `UPDATE cra_case_deadlines SET superseded_at = $4
			WHERE org_id = $1 AND case_id = $2 AND stage = $3 AND superseded_at IS NULL`,
			c.p.OrgID, c.ID, stage, c.now); err != nil {
			return err
		}
	}
	_, err := c.tx.ExecContext(c.ctx, `INSERT INTO cra_case_deadlines
		(org_id, case_id, stage, revision, due_at, satisfied_at) VALUES ($1,$2,$3,$4,$5,$6)`,
		c.p.OrgID, c.ID, stage, prev.revision+1, due, satisfied)
	return err
}

func sameCRATime(a, b *time.Time) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && a.Equal(*b))
}

func (c *craTx) refreshDeadlines() error {
	early := c.AwarenessAt.Add(24 * time.Hour)
	notification := c.AwarenessAt.Add(72 * time.Hour)
	var final *time.Time
	if c.Kind == "vulnerability" {
		if c.MeasureAvailableAt != nil {
			t := c.MeasureAvailableAt.AddDate(0, 0, 14)
			final = &t
		}
	} else {
		filed, err := c.deadline(craNotification)
		if err == nil && filed.satisfiedAt != nil {
			t := craMonthAfter(*filed.satisfiedAt)
			final = &t
		} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	for _, stage := range []struct {
		name string
		due  *time.Time
	}{{craEarlyWarning, &early}, {craNotification, &notification}, {craFinal, final}} {
		prior, err := c.deadline(stage.name)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if prior.revision == 0 || !sameCRATime(prior.dueAt, stage.due) {
			if err := c.reviseDeadline(stage.name, prior, stage.due, prior.satisfiedAt); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *craTx) satisfyDeadline(stage string, submitted time.Time) error {
	_, err := c.tx.ExecContext(c.ctx, `UPDATE cra_case_deadlines SET satisfied_at = $4
		WHERE org_id = $1 AND case_id = $2 AND stage = $3 AND superseded_at IS NULL`,
		c.p.OrgID, c.ID, stage, submitted)
	return err
}

type craIntermediateRequest struct {
	RequestedAt time.Time  `json:"requested_at"`
	DueAt       *time.Time `json:"due_at"`
	Reference   string     `json:"reference"`
}

type craEarlierInformation struct {
	Stage        string    `json:"stage"`
	SubmissionID uuid.UUID `json:"submission_id"`
}

func patchCRACase(c *craTx, r *http.Request) (any, error) {
	var req struct {
		Links               []craLink               `json:"links"`
		LinkImpact          bool                    `json:"link_impact"`
		AwarenessAt         json.RawMessage         `json:"awareness_at"`
		MeasureAvailableAt  json.RawMessage         `json:"measure_available_at"`
		CorrectionReason    string                  `json:"correction_reason"`
		IntermediateRequest *craIntermediateRequest `json:"intermediate_request"`
		PreviouslySupplied  *craEarlierInformation  `json:"previously_supplied"`
	}
	if err := readCRARequest(r, &req); err != nil {
		return nil, err
	}
	if len(req.AwarenessAt) != 0 || len(req.MeasureAvailableAt) != 0 {
		if err := c.updateMilestones(req.AwarenessAt, req.MeasureAvailableAt, strings.TrimSpace(req.CorrectionReason)); err != nil {
			return nil, err
		}
	} else if req.CorrectionReason != "" {
		return nil, craError{http.StatusBadRequest, "correction_reason requires a milestone update"}
	}
	if err := c.addLinks(req.Links, req.LinkImpact); err != nil {
		return nil, err
	}
	if req.IntermediateRequest != nil {
		if err := c.requestIntermediate(*req.IntermediateRequest); err != nil {
			return nil, err
		}
	}
	if req.PreviouslySupplied != nil {
		if err := c.recordEarlierInformation(*req.PreviouslySupplied); err != nil {
			return nil, err
		}
	}
	return c.detail()
}

func (c *craTx) updateMilestones(awareness, measure json.RawMessage, reason string) error {
	oldAwareness, oldMeasure := c.AwarenessAt, c.MeasureAvailableAt
	if len(awareness) != 0 {
		var t time.Time
		if json.Unmarshal(awareness, &t) != nil || !c.validPast(t) {
			return craError{http.StatusBadRequest, "invalid awareness_at"}
		}
		c.AwarenessAt = craTimestamp(t)
	}
	if len(measure) != 0 {
		var t *time.Time
		if c.Kind != "vulnerability" || json.Unmarshal(measure, &t) != nil || (t != nil && !c.validPast(*t)) {
			return craError{http.StatusBadRequest, "invalid measure_available_at"}
		}
		c.MeasureAvailableAt = craOptionalTimestamp(t)
	}
	awarenessChanged := !oldAwareness.Equal(c.AwarenessAt)
	measureChanged := !sameCRATime(oldMeasure, c.MeasureAvailableAt)
	if !awarenessChanged && !measureChanged {
		return nil
	}
	correction := awarenessChanged || oldMeasure != nil
	if correction {
		if c.p.Role != auth.RoleAdmin {
			return craError{http.StatusForbidden, "only Admins can correct case milestones"}
		}
		if reason == "" {
			return craError{http.StatusBadRequest, "correction_reason is required"}
		}
		var invalid bool
		if err := c.tx.QueryRowContext(c.ctx, `SELECT EXISTS(SELECT 1 FROM cra_case_submissions
			WHERE org_id = $1 AND case_id = $2 AND submitted_at < $3)`,
			c.p.OrgID, c.ID, c.AwarenessAt).Scan(&invalid); err != nil {
			return err
		}
		if invalid {
			return craError{http.StatusConflict, "awareness cannot follow a confirmed submission"}
		}
		if _, err := c.tx.ExecContext(c.ctx, `INSERT INTO cra_case_corrections
			(id, org_id, case_id, previous, corrected, reason, recorded_at, recorded_by)
			VALUES ($1,$2,$3,
			jsonb_build_object('awareness_at', $4::timestamptz, 'measure_available_at', $5::timestamptz),
			jsonb_build_object('awareness_at', $6::timestamptz, 'measure_available_at', $7::timestamptz),$8,$9,$10)`,
			uuid.New(), c.p.OrgID, c.ID, oldAwareness, oldMeasure, c.AwarenessAt, c.MeasureAvailableAt,
			reason, c.now, c.actor); err != nil {
			return err
		}
	}
	if _, err := c.tx.ExecContext(c.ctx, `UPDATE cra_cases SET awareness_at = $3, measure_available_at = $4
		WHERE org_id = $1 AND id = $2`, c.p.OrgID, c.ID, c.AwarenessAt, c.MeasureAvailableAt); err != nil {
		return err
	}
	return c.refreshDeadlines()
}

func (c *craTx) requestIntermediate(req craIntermediateRequest) error {
	req.Reference = strings.TrimSpace(req.Reference)
	req.RequestedAt = craTimestamp(req.RequestedAt)
	req.DueAt = craOptionalTimestamp(req.DueAt)
	if req.Reference == "" || !c.validPast(req.RequestedAt) ||
		(req.DueAt != nil && req.DueAt.Before(req.RequestedAt)) {
		return craError{http.StatusBadRequest, "invalid intermediate request timestamp, due date or reference"}
	}
	var received bool
	if err := c.tx.QueryRowContext(c.ctx, `SELECT EXISTS(SELECT 1 FROM cra_case_submissions s
		JOIN cra_case_exports e ON e.id = s.export_id
		WHERE s.org_id = $1 AND s.case_id = $2 AND e.stage IN ('early-warning','notification')
		AND s.submitted_at <= $3)`, c.p.OrgID, c.ID, req.RequestedAt).Scan(&received); err != nil {
		return err
	}
	if !received {
		return craError{http.StatusConflict, "intermediate request requires a previously filed early warning or notification"}
	}
	var existingAt time.Time
	var existingDue *time.Time
	err := c.tx.QueryRowContext(c.ctx, `SELECT i.requested_at, d.due_at FROM cra_case_intermediate_requests i
		JOIN cra_case_deadlines d USING (case_id, stage, revision)
		WHERE i.org_id = $1 AND i.case_id = $2 AND i.reference = $3`, c.p.OrgID, c.ID, req.Reference).
		Scan(&existingAt, &existingDue)
	if err == nil {
		if existingAt.Equal(req.RequestedAt) && sameCRATime(existingDue, req.DueAt) {
			return nil
		}
		return craError{http.StatusConflict, "intermediate request reference already recorded"}
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	prior, err := c.deadline(craIntermediate)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	// shortcut: one open CSIRT request per case, extend deadline identity if requests overlap.
	if prior.revision != 0 && prior.satisfiedAt == nil {
		return craError{http.StatusConflict, "an intermediate request is already open"}
	}
	if err := c.reviseDeadline(craIntermediate, prior, req.DueAt, nil); err != nil {
		return err
	}
	_, err = c.tx.ExecContext(c.ctx, `INSERT INTO cra_case_intermediate_requests
		(org_id, case_id, revision, requested_at, reference, recorded_by) VALUES ($1,$2,$3,$4,$5,$6)`,
		c.p.OrgID, c.ID, prior.revision+1, req.RequestedAt, req.Reference, c.actor)
	return err
}

func (c *craTx) recordEarlierInformation(req craEarlierInformation) error {
	if (req.Stage != craNotification && req.Stage != craFinal) || req.SubmissionID == uuid.Nil {
		return craError{http.StatusBadRequest, "previously supplied information requires notification or final stage and a submission_id"}
	}
	var submitted time.Time
	var stage string
	err := c.tx.QueryRowContext(c.ctx, `SELECT s.submitted_at, e.stage FROM cra_case_submissions s
		JOIN cra_case_exports e ON e.id = s.export_id WHERE s.org_id = $1 AND s.case_id = $2 AND s.id = $3`,
		c.p.OrgID, c.ID, req.SubmissionID).Scan(&submitted, &stage)
	if errors.Is(err, sql.ErrNoRows) {
		return craError{http.StatusNotFound, "earlier submission not found in this case"}
	}
	if err != nil {
		return err
	}
	if stage != craEarlyWarning && stage != craIntermediate && (stage != craNotification || req.Stage != craFinal) {
		return craError{http.StatusBadRequest, "source submission must be from an earlier reporting stage"}
	}
	d, err := c.deadline(req.Stage)
	if err != nil {
		return err
	}
	if d.satisfiedAt != nil {
		var same bool
		if err := c.tx.QueryRowContext(c.ctx, `SELECT EXISTS(SELECT 1 FROM cra_case_previously_supplied
			WHERE org_id = $1 AND case_id = $2 AND stage = $3 AND submission_id = $4)`,
			c.p.OrgID, c.ID, req.Stage, req.SubmissionID).Scan(&same); err != nil {
			return err
		}
		if same {
			return nil
		}
		return craError{http.StatusConflict, "stage already satisfied"}
	}
	if _, err := c.tx.ExecContext(c.ctx, `INSERT INTO cra_case_previously_supplied
		(org_id, case_id, stage, submission_id, recorded_at, recorded_by) VALUES ($1,$2,$3,$4,$5,$6)`,
		c.p.OrgID, c.ID, req.Stage, req.SubmissionID, c.now, c.actor); err != nil {
		return err
	}
	if err := c.satisfyDeadline(req.Stage, submitted); err != nil {
		return err
	}
	return c.refreshDeadlines()
}
