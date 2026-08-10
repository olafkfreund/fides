package models

import (
	"time"

	"github.com/google/uuid"
)

type Organization struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

type Flow struct {
	ID          uuid.UUID         `json:"id" db:"id"`
	OrgID       uuid.UUID         `json:"org_id" db:"org_id"`
	Name        string            `json:"name" db:"name"`
	Description string            `json:"description" db:"description"`
	Tags        map[string]string `json:"tags" db:"tags"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
}

type Trail struct {
	ID            uuid.UUID         `json:"id" db:"id"`
	FlowID        uuid.UUID         `json:"flow_id" db:"flow_id"`
	Name          string            `json:"name" db:"name"` // Git SHA / PR / Build ID
	GitRepository string            `json:"git_repository" db:"git_repository"`
	GitCommit     string            `json:"git_commit" db:"git_commit"`
	GitBranch     string            `json:"git_branch" db:"git_branch"`
	GitMessage    string            `json:"git_message" db:"git_message"`
	Tags          map[string]string `json:"tags" db:"tags"`
	CreatedAt     time.Time         `json:"created_at" db:"created_at"`
}

type Artifact struct {
	SHA256    string            `json:"sha256" db:"sha256"` // Primary Key (fingerprint)
	OrgID     uuid.UUID         `json:"org_id" db:"org_id"`
	TrailID   *uuid.UUID        `json:"trail_id" db:"trail_id"`
	Name      string            `json:"name" db:"name"`
	Type      string            `json:"type" db:"type"` // docker, binary, etc.
	Tags      map[string]string `json:"tags" db:"tags"`
	CreatedAt time.Time         `json:"created_at" db:"created_at"`
}

type AttestationType struct {
	ID          uuid.UUID `json:"id" db:"id"`
	OrgID       uuid.UUID `json:"org_id" db:"org_id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	Schema      string    `json:"schema" db:"schema"` // JSON schema
	JQRules     []string  `json:"jq_rules" db:"jq_rules"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

type Attestation struct {
	ID                  uuid.UUID `json:"id" db:"id"`
	TrailID             uuid.UUID `json:"trail_id" db:"trail_id"`
	ArtifactSHA256      *string   `json:"artifact_sha256" db:"artifact_sha256"`
	Name                string    `json:"name" db:"name"` // unit-tests, sbom, snyk-scan
	TypeName            string    `json:"type_name" db:"type_name"`
	Payload             string    `json:"payload" db:"payload"` // raw JSON payload
	IsCompliant         bool      `json:"is_compliant" db:"is_compliant"`
	SignedBy            string    `json:"signed_by" db:"signed_by"`
	Signature           string    `json:"signature" db:"signature"`
	SignatureAlgorithm  string    `json:"signature_algorithm" db:"signature_algorithm"`
	ManifestationReason string    `json:"manifestation_reason" db:"manifestation_reason"`
	CreatedAt           time.Time `json:"created_at" db:"created_at"`
}

type TenantAuthConfig struct {
	ID               uuid.UUID `json:"id" db:"id"`
	OrgID            uuid.UUID `json:"org_id" db:"org_id"`
	ProviderName     string    `json:"provider_name" db:"provider_name"`
	ClientID         string    `json:"client_id" db:"client_id"`
	ClientSecretPath string    `json:"client_secret_path" db:"client_secret_path"`
	AuthURL          string    `json:"auth_url" db:"auth_url"`
	TokenURL         string    `json:"token_url" db:"token_url"`
	UserInfoURL      string    `json:"userinfo_url" db:"userinfo_url"`
	RedirectURI      string    `json:"redirect_uri" db:"redirect_uri"`
	Enabled          bool      `json:"enabled" db:"enabled"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" db:"updated_at"`
}

type TenantStorageSettings struct {
	ID                        uuid.UUID `json:"id" db:"id"`
	OrgID                     uuid.UUID `json:"org_id" db:"org_id"`
	StorageDriver             string    `json:"storage_driver" db:"storage_driver"`
	S3Endpoint                string    `json:"s3_endpoint" db:"s3_endpoint"`
	S3Bucket                  string    `json:"s3_bucket" db:"s3_bucket"`
	S3AccessKeyPath           string    `json:"s3_access_key_path" db:"s3_access_key_path"`
	S3SecretKeyPath           string    `json:"s3_secret_key_path" db:"s3_secret_key_path"`
	S3Region                  string    `json:"s3_region" db:"s3_region"`
	GCSBucket                 string    `json:"gcs_bucket" db:"gcs_bucket"`
	GCSCredentialsPath        string    `json:"gcs_credentials_path" db:"gcs_credentials_path"`
	AzureContainer            string    `json:"azure_container" db:"azure_container"`
	AzureConnectionStringPath string    `json:"azure_connection_string_path" db:"azure_connection_string_path"`
	CreatedAt                 time.Time `json:"created_at" db:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at" db:"updated_at"`
}

type TenantVaultSettings struct {
	ID             uuid.UUID `json:"id" db:"id"`
	OrgID          uuid.UUID `json:"org_id" db:"org_id"`
	VaultProvider  string    `json:"vault_provider" db:"vault_provider"`
	VaultAddress   string    `json:"vault_address" db:"vault_address"`
	VaultTokenPath string    `json:"vault_token_path" db:"vault_token_path"`
	VaultRole      string    `json:"vault_role" db:"vault_role"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}

type TenantLLMSettings struct {
	ID              uuid.UUID `json:"id" db:"id"`
	OrgID           uuid.UUID `json:"org_id" db:"org_id"`
	ProviderName    string    `json:"provider_name" db:"provider_name"`
	ModelName       string    `json:"model_name" db:"model_name"`
	EndpointURL     string    `json:"endpoint_url" db:"endpoint_url"`
	APIKeyPath      string    `json:"api_key_path" db:"api_key_path"`
	AWSRegion       string    `json:"aws_region" db:"aws_region"`
	AzureDeployment string    `json:"azure_deployment" db:"azure_deployment"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time `json:"updated_at" db:"updated_at"`
}

type User struct {
	ID           uuid.UUID `json:"id" db:"id"`
	OrgID        uuid.UUID `json:"org_id" db:"org_id"`
	Name         string    `json:"name" db:"name"`
	Email        string    `json:"email" db:"email"`
	Role         string    `json:"role" db:"role"`
	Groups       []string  `json:"groups" db:"groups"`
	PasswordHash string    `json:"-" db:"password_hash"` // never serialized to clients
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

type SSOGroupMapping struct {
	ID            uuid.UUID `json:"id" db:"id"`
	OrgID         uuid.UUID `json:"org_id" db:"org_id"`
	ExternalGroup string    `json:"external_group" db:"external_group"`
	Role          string    `json:"role" db:"role"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

type EnvironmentMCPServer struct {
	ID            uuid.UUID         `json:"id" db:"id"`
	EnvironmentID uuid.UUID         `json:"environment_id" db:"environment_id"`
	Name          string            `json:"name" db:"name"`
	Transport     string            `json:"transport" db:"transport"`
	Command       string            `json:"command" db:"command"`
	Args          []string          `json:"args" db:"args"`
	EnvVars       map[string]string `json:"env_vars" db:"env_vars"`
	URL           string            `json:"url" db:"url"`
	AuthHeader    string            `json:"auth_header" db:"auth_header"`
	CreatedAt     time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at" db:"updated_at"`
}

type TenantWebhook struct {
	ID         uuid.UUID `json:"id" db:"id"`
	OrgID      uuid.UUID `json:"org_id" db:"org_id"`
	Name       string    `json:"name" db:"name"`
	URL        string    `json:"url" db:"url"`
	SecretPath string    `json:"secret_path" db:"secret_path"` // reference, not the secret itself
	EventTypes []string  `json:"event_types" db:"event_types"` // empty = all
	Enabled    bool      `json:"enabled" db:"enabled"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time `json:"updated_at" db:"updated_at"`
}

type TenantGitProvider struct {
	ID                uuid.UUID `json:"id" db:"id"`
	OrgID             uuid.UUID `json:"org_id" db:"org_id"`
	Provider          string    `json:"provider" db:"provider"` // github / gitlab
	Host              string    `json:"host" db:"host"`
	APIBase           string    `json:"api_base" db:"api_base"`
	TokenPath         string    `json:"token_path" db:"token_path"`                   // reference, not the token
	InboundSecretPath string    `json:"inbound_secret_path" db:"inbound_secret_path"` // inbound webhook secret reference
	Enabled           bool      `json:"enabled" db:"enabled"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time `json:"updated_at" db:"updated_at"`
}

type TenantServiceNowSettings struct {
	ID          uuid.UUID `json:"id" db:"id"`
	OrgID       uuid.UUID `json:"org_id" db:"org_id"`
	InstanceURL string    `json:"instance_url" db:"instance_url"`
	AuthType    string    `json:"auth_type" db:"auth_type"` // basic | oauth2
	ClientID    string    `json:"client_id" db:"client_id"`
	SecretPath  string    `json:"secret_path" db:"secret_path"` // reference, not the secret
	Enabled     bool      `json:"enabled" db:"enabled"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}
