package vault

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// smGetter is the subset of the Secrets Manager client used here, so the
// provider can be unit-tested with a fake.
type smGetter interface {
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// AWSSecretsProvider resolves secrets from AWS Secrets Manager. The secret id is
// `key`, optionally prefixed by `path` ("path/key"), matching the env provider's
// path/key convention.
type AWSSecretsProvider struct {
	client smGetter
}

// NewAWSSecretsProvider builds a provider using the default AWS credential chain.
func NewAWSSecretsProvider(ctx context.Context, region string) (*AWSSecretsProvider, error) {
	var cfg aws.Config
	var err error
	if region != "" {
		cfg, err = config.LoadDefaultConfig(ctx, config.WithRegion(region))
	} else {
		cfg, err = config.LoadDefaultConfig(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("vault: load AWS config: %w", err)
	}
	return &AWSSecretsProvider{client: secretsmanager.NewFromConfig(cfg)}, nil
}

func (p *AWSSecretsProvider) GetSecret(ctx context.Context, path, key string) (string, error) {
	if key == "" {
		return "", errors.New("vault: secret id (key) is required")
	}
	id := key
	if path != "" {
		id = path + "/" + key
	}
	out, err := p.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(id)})
	if err != nil {
		return "", fmt.Errorf("vault: get secret %q: %w", id, err)
	}
	if out.SecretString != nil {
		return *out.SecretString, nil
	}
	if len(out.SecretBinary) > 0 {
		return string(out.SecretBinary), nil
	}
	return "", fmt.Errorf("vault: secret %q is empty", id)
}
