package servicenow

import (
	"context"
	"database/sql"
	"errors"
	"os"

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
	// The IRE discovery source has to be a valid cmdb_ci.discovery_source
	// choice on the target instance, so it is deployment-level rather than
	// per-tenant. Empty falls back to DefaultDataSource in New().
	cfg.DataSource = os.Getenv("FIDES_SNOW_DISCOVERY_SOURCE")
	return cfg, true, nil
}

// ControlsForAttestation returns the org's active controls that this
// attestation type is evidence for, so a verdict can be filed against each.
//
// Explicitly org-scoped: RLS is opt-in on this deployment, so the org_id
// predicate here is the actual tenant boundary, not a backstop.
func (l *DBLoader) ControlsForAttestation(ctx context.Context, orgID uuid.UUID, attestationType string) ([]ControlRef, error) {
	var out []ControlRef
	err := db.WithOrgScope(ctx, l.db, orgID.String(), func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx,
			`SELECT key, name FROM controls
			 WHERE org_id = $1 AND NOT archived AND $2 = ANY(required_types)`,
			orgID, attestationType)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var c ControlRef
			if e := rows.Scan(&c.Key, &c.Name); e != nil {
				return e
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}
