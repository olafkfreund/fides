package vault

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type fakeSM struct {
	gotID string
	value string
	err   error
}

func (f *fakeSM) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.gotID = *in.SecretId
	if f.err != nil {
		return nil, f.err
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(f.value)}, nil
}

func TestAWSGetSecret(t *testing.T) {
	f := &fakeSM{value: "topsecret"}
	p := &AWSSecretsProvider{client: f}

	got, err := p.GetSecret(context.Background(), "", "fides/servicenow")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got != "topsecret" {
		t.Fatalf("value = %q", got)
	}
	if f.gotID != "fides/servicenow" {
		t.Fatalf("secret id = %q", f.gotID)
	}
}

func TestAWSGetSecretWithPathPrefix(t *testing.T) {
	f := &fakeSM{value: "x"}
	p := &AWSSecretsProvider{client: f}
	if _, err := p.GetSecret(context.Background(), "fides", "snow"); err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if f.gotID != "fides/snow" {
		t.Fatalf("expected path-prefixed id 'fides/snow', got %q", f.gotID)
	}
}

func TestAWSGetSecretErrors(t *testing.T) {
	p := &AWSSecretsProvider{client: &fakeSM{err: errors.New("denied")}}
	if _, err := p.GetSecret(context.Background(), "", "k"); err == nil {
		t.Fatalf("expected an error to propagate")
	}

	p2 := &AWSSecretsProvider{client: &fakeSM{value: "x"}}
	if _, err := p2.GetSecret(context.Background(), "", ""); err == nil {
		t.Fatalf("empty key should error")
	}
}

func TestNewProviderDefaultsToEnv(t *testing.T) {
	t.Setenv("SECRETS_PROVIDER", "")
	if _, ok := NewProvider(context.Background()).(*EnvSecretsProvider); !ok {
		t.Fatalf("default provider should be EnvSecretsProvider")
	}
}
