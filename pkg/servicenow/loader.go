package servicenow

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"

	"fides/pkg/db"
	"fides/pkg/vault"
)

// DBLoader resolves a tenant's ServiceNow settings from tenant_servicenow_settings
// (org-scoped, RLS-safe) and fetches the credential via the secrets provider.
type DBLoader struct {
	db      *sql.DB
	secrets vault.SecretsProvider
}

func NewDBLoader(database *sql.DB, secrets vault.SecretsProvider) *DBLoader {
	return &DBLoader{db: database, secrets: secrets}
}

func (l *DBLoader) ServiceNowConfig(ctx context.Context, orgID uuid.UUID) (Config, bool, error) {
	var cfg Config
	var authType, secretPath string
	var enabled bool

	err := db.WithOrgScope(ctx, l.db, orgID.String(), func(tx *sql.Tx) error {
		e := tx.QueryRowContext(ctx,
			`SELECT instance_url, auth_type, client_id, secret_path, enabled
			 FROM tenant_servicenow_settings WHERE org_id = $1`, orgID).
			Scan(&cfg.InstanceURL, &authType, &cfg.ClientID, &secretPath, &enabled)
		if errors.Is(e, sql.ErrNoRows) {
			enabled = false
			return nil
		}
		return e
	})
	if err != nil {
		return Config{}, false, err
	}
	if !enabled {
		return Config{}, false, nil
	}

	secret, err := l.secrets.GetSecret(ctx, "", secretPath)
	if err != nil {
		return Config{}, false, err
	}
	cfg.AuthType = AuthType(authType)
	cfg.Secret = secret
	return cfg, true, nil
}
