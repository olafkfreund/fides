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

type EvidenceAttachment struct {
	ID            uuid.UUID `json:"id" db:"id"`
	AttestationID uuid.UUID `json:"attestation_id" db:"attestation_id"`
	FileName      string    `json:"file_name" db:"file_name"`
	FileSize      int64     `json:"file_size" db:"file_size"`
	FileHash      string    `json:"file_hash" db:"file_hash"`
	StoragePath   string    `json:"storage_path" db:"storage_path"`
	ContentType   string    `json:"content_type" db:"content_type"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

type LLMAssessment struct {
	ID                    uuid.UUID `json:"id" db:"id"`
	AttestationID         uuid.UUID `json:"attestation_id" db:"attestation_id"`
	ModelProvider         string    `json:"model_provider" db:"model_provider"`
	ModelName             string    `json:"model_name" db:"model_name"`
	PromptTemplateVersion string    `json:"prompt_template_version" db:"prompt_template_version"`
	AssessmentRaw         string    `json:"assessment_raw" db:"assessment_raw"`
	ComplianceScore       int       `json:"compliance_score" db:"compliance_score"`
	Findings              string    `json:"findings" db:"findings"` // JSON string list of issues
	CreatedAt             time.Time `json:"created_at" db:"created_at"`
}

type Environment struct {
	ID          uuid.UUID `json:"id" db:"id"`
	OrgID       uuid.UUID `json:"org_id" db:"org_id"`
	Name        string    `json:"name" db:"name"`
	Type        string    `json:"type" db:"type"` // docker, k8s, etc
	Description string    `json:"description" db:"description"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

type EnvironmentSnapshot struct {
	ID            uuid.UUID `json:"id" db:"id"`
	EnvironmentID uuid.UUID `json:"environment_id" db:"environment_id"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

type SnapshotArtifact struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	SnapshotID     uuid.UUID  `json:"snapshot_id" db:"snapshot_id"`
	ArtifactSHA256 *string    `json:"artifact_sha256" db:"artifact_sha256"`
	ServiceName    string     `json:"service_name" db:"service_name"`
	RuntimeDigest  string     `json:"runtime_digest" db:"runtime_digest"`
	StartedAt      *time.Time `json:"started_at" db:"started_at"`
	StoppedAt      *time.Time `json:"stopped_at" db:"stopped_at"`
}

type Policy struct {
	ID          uuid.UUID `json:"id" db:"id"`
	OrgID       uuid.UUID `json:"org_id" db:"org_id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	Rules       string    `json:"rules" db:"rules"` // YAML/JSON config rules string
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

type SystemAuditLog struct {
	ID         int64     `json:"id" db:"id"`
	OrgID      uuid.UUID `json:"org_id" db:"org_id"`
	Actor      string    `json:"actor" db:"actor"`
	ActionType string    `json:"action_type" db:"action_type"`
	TargetType string    `json:"target_type" db:"target_type"`
	TargetID   uuid.UUID `json:"target_id" db:"target_id"`
	OldState   string    `json:"old_state" db:"old_state"` // JSON string
	NewState   string    `json:"new_state" db:"new_state"` // JSON string
	RequestIP  string    `json:"request_ip" db:"request_ip"`
	UserAgent  string    `json:"user_agent" db:"user_agent"`
	Timestamp  time.Time `json:"timestamp" db:"timestamp"`
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

type User struct {
	ID        uuid.UUID `json:"id" db:"id"`
	OrgID     uuid.UUID `json:"org_id" db:"org_id"`
	Name      string    `json:"name" db:"name"`
	Email     string    `json:"email" db:"email"`
	Role      string    `json:"role" db:"role"`
	Groups    []string  `json:"groups" db:"groups"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type SSOGroupMapping struct {
	ID            uuid.UUID `json:"id" db:"id"`
	OrgID         uuid.UUID `json:"org_id" db:"org_id"`
	ExternalGroup string    `json:"external_group" db:"external_group"`
	Role          string    `json:"role" db:"role"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

