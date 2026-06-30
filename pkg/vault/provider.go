package vault

import (
	"context"
	"log"
	"os"
)

// NewProvider selects a SecretsProvider from the SECRETS_PROVIDER env var:
//   - "aws": AWS Secrets Manager (region from AWS_REGION)
//   - anything else (default): environment variables
//
// If the AWS provider fails to initialize it logs and falls back to env, so the
// server never fails to start over secrets configuration.
func NewProvider(ctx context.Context) SecretsProvider {
	switch os.Getenv("SECRETS_PROVIDER") {
	case "aws":
		p, err := NewAWSSecretsProvider(ctx, os.Getenv("AWS_REGION"))
		if err != nil {
			log.Printf("vault: AWS secrets provider unavailable (%v); falling back to env", err)
			return NewEnvSecretsProvider()
		}
		log.Printf("vault: using AWS Secrets Manager")
		return p
	default:
		return NewEnvSecretsProvider()
	}
}
