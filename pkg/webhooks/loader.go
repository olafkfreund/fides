package webhooks

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"fides/pkg/db"
	"fides/pkg/vault"
)

// DBLoader resolves a tenant's webhook targets from tenant_webhooks, retrieving
// each signing secret from the secrets provider. The query runs within the
// tenant's org scope (db.WithOrgScope) so it is correct whether or not RLS is
// enabled.
type DBLoader struct {
	db      *sql.DB
	secrets vault.SecretsProvider
}

func NewDBLoader(database *sql.DB, secrets vault.SecretsProvider) *DBLoader {
	return &DBLoader{db: database, secrets: secrets}
}

func (l *DBLoader) Targets(ctx context.Context, orgID uuid.UUID, eventType string) ([]Target, error) {
	var targets []Target
	err := db.WithOrgScope(ctx, l.db, orgID.String(), func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT url, secret_path, event_types FROM tenant_webhooks WHERE org_id = $1 AND enabled = true`, orgID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var url, secretPath string
			var eventTypes pq.StringArray
			if err := rows.Scan(&url, &secretPath, &eventTypes); err != nil {
				return err
			}
			// An empty event_types list subscribes to all event types.
			if len(eventTypes) > 0 && !contains(eventTypes, eventType) {
				continue
			}
			secret, err := l.secrets.GetSecret(ctx, "", secretPath)
			if err != nil {
				return err
			}
			targets = append(targets, Target{URL: url, Secret: secret})
		}
		return rows.Err()
	})
	return targets, err
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
