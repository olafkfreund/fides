package gitstatus

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"

	"fides/pkg/db"
	"fides/pkg/vault"
)

// DBLoader resolves provider configs from tenant_git_providers and a trail's git
// coordinates from trails, both within the tenant's org scope (RLS-safe).
type DBLoader struct {
	db      *sql.DB
	secrets vault.SecretsProvider
}

func NewDBLoader(database *sql.DB, secrets vault.SecretsProvider) *DBLoader {
	return &DBLoader{db: database, secrets: secrets}
}

func (l *DBLoader) Providers(ctx context.Context, orgID uuid.UUID) ([]ProviderConfig, error) {
	var out []ProviderConfig
	err := db.WithOrgScope(ctx, l.db, orgID.String(), func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT provider, host, api_base, token_path FROM tenant_git_providers WHERE org_id = $1 AND enabled = true`, orgID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var cfg ProviderConfig
			var tokenPath string
			if err := rows.Scan(&cfg.Provider, &cfg.Host, &cfg.APIBase, &tokenPath); err != nil {
				return err
			}
			token, err := l.secrets.GetSecret(ctx, "", tokenPath)
			if err != nil {
				return err
			}
			cfg.Token = token
			out = append(out, cfg)
		}
		return rows.Err()
	})
	return out, err
}

func (l *DBLoader) TrailGit(ctx context.Context, orgID, trailID uuid.UUID) (TrailGit, error) {
	var tg TrailGit
	err := db.WithOrgScope(ctx, l.db, orgID.String(), func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT COALESCE(git_repository, ''), COALESCE(git_commit, '') FROM trails WHERE id = $1`, trailID,
		).Scan(&tg.Repository, &tg.Commit)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return TrailGit{}, nil
	}
	return tg, err
}
