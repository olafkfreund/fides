package admission

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"

	"fides/pkg/db"
)

// DBChecker resolves image status from the Fides database: an artifact is
// "registered" if a row exists for the sha256, and "compliant" if its trail has
// no failing attestations. Queries run within the tenant's org scope (RLS-safe).
type DBChecker struct {
	db *sql.DB
}

func NewDBChecker(database *sql.DB) *DBChecker {
	return &DBChecker{db: database}
}

func (c *DBChecker) CheckImage(ctx context.Context, orgID uuid.UUID, sha256 string) (ImageStatus, error) {
	var status ImageStatus
	err := db.WithOrgScope(ctx, c.db, orgID.String(), func(tx *sql.Tx) error {
		var trailID sql.NullString
		// Scoped by org in-query, not just by the RLS session GUC that
		// WithOrgScope sets: RLS is opt-in behind FIDES_RLS_ENABLED, so with it
		// unset this admission gate would admit an image on ANOTHER tenant's
		// provenance. A digest is globally unique (artifacts PK), so that is a
		// reachable state, not a theoretical one.
		err := tx.QueryRowContext(ctx,
			`SELECT trail_id FROM artifacts WHERE sha256 = $1 AND org_id = $2 LIMIT 1`,
			sha256, orgID).Scan(&trailID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil // not registered -> shadow
		}
		if err != nil {
			return err
		}
		status.Registered = true

		// Compliant if the artifact's trail has no failing attestations.
		if trailID.Valid && trailID.String != "" {
			var total, compliant int
			if err := tx.QueryRowContext(ctx,
				`SELECT COUNT(*), COUNT(*) FILTER (WHERE is_compliant) FROM attestations WHERE trail_id = $1`,
				trailID.String).Scan(&total, &compliant); err != nil {
				return err
			}
			status.Compliant = total == 0 || compliant == total
		} else {
			// Registered with no trail/attestations -> treat as compliant.
			status.Compliant = true
		}
		return nil
	})
	return status, err
}
