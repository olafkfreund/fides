package vault

import (
	"context"
	"fmt"
	"os"
)

type SecretsProvider interface {
	GetSecret(ctx context.Context, path string, key string) (string, error)
}

// EnvSecretsProvider falls back to system environment variables.
// The "path" represents a prefix or is ignored, and "key" represents the variable name.
type EnvSecretsProvider struct{}

func NewEnvSecretsProvider() *EnvSecretsProvider {
	return &EnvSecretsProvider{}
}

func (p *EnvSecretsProvider) GetSecret(ctx context.Context, path string, key string) (string, error) {
	val := os.Getenv(key)
	if val == "" {
		// Try with prefix if path is provided
		if path != "" {
			val = os.Getenv(fmt.Sprintf("%s_%s", path, key))
		}
	}
	if val == "" {
		return "", fmt.Errorf("secret not found for key: %s (path: %s)", key, path)
	}
	return val, nil
}
