package slack

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"

	"fides/pkg/db"
	"fides/pkg/vault"
)

// DBLoader resolves the tenant's Slack webhook URL from tenant_slack_settings
// (org-scoped) via the secrets provider.
type DBLoader struct {
	db      *sql.DB
	secrets vault.SecretsProvider
}

func NewDBLoader(database *sql.DB, secrets vault.SecretsProvider) *DBLoader {
	return &DBLoader{db: database, secrets: secrets}
}

func (l *DBLoader) SlackWebhook(ctx context.Context, orgID uuid.UUID) (string, bool, error) {
	var secretPath string
	var enabled bool
	err := db.WithOrgScope(ctx, l.db, orgID.String(), func(tx *sql.Tx) error {
		e := tx.QueryRowContext(ctx,
			`SELECT webhook_secret_path, enabled FROM tenant_slack_settings WHERE org_id = $1`, orgID).
			Scan(&secretPath, &enabled)
		if errors.Is(e, sql.ErrNoRows) {
			enabled = false
			return nil
		}
		return e
	})
	if err != nil || !enabled {
		return "", false, err
	}
	url, err := l.secrets.GetSecret(ctx, "", secretPath)
	if err != nil {
		return "", false, err
	}
	return url, true, nil
}
