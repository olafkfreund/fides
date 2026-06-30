package gitstatus

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"fides/pkg/events"
)

// EventType is the integration event this sink reacts to.
const EventType = "compliance.evaluated"

// ProviderConfig is a tenant's SCM provider connection (secret already resolved).
type ProviderConfig struct {
	Provider string // github / gitlab
	Host     string // git host to match against the trail's remote, e.g. github.com
	APIBase  string // API root, e.g. https://api.github.com or https://gitlab.com/api/v4
	Token    string
}

// TrailGit is the git coordinate of a trail.
type TrailGit struct {
	Repository string
	Commit     string
}

// Loader resolves per-tenant provider configs and a trail's git coordinates.
type Loader interface {
	Providers(ctx context.Context, orgID uuid.UUID) ([]ProviderConfig, error)
	TrailGit(ctx context.Context, orgID, trailID uuid.UUID) (TrailGit, error)
}

// Sink posts commit statuses for compliance.evaluated events.
type Sink struct {
	loader  Loader
	client  *http.Client
	baseURL string // Fides base URL, for the status target link
}

// NewSink builds the commit-status sink. baseURL links the status back to Fides.
func NewSink(loader Loader, baseURL string) *Sink {
	return &Sink{
		loader:  loader,
		client:  &http.Client{Timeout: 10 * time.Second},
		baseURL: baseURL,
	}
}

func (s *Sink) Name() string { return "git-commit-status" }

type compliancePayload struct {
	TrailID   string `json:"trail_id"`
	Compliant bool   `json:"compliant"`
}

// Deliver posts a commit status when the event names a trail whose remote host
// matches a configured provider. Unrelated events and untracked hosts are no-ops.
func (s *Sink) Deliver(ctx context.Context, ev events.Event) error {
	if ev.Type != EventType {
		return nil
	}
	var p compliancePayload
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return err
	}
	if p.TrailID == "" {
		return nil
	}
	trailID, err := uuid.Parse(p.TrailID)
	if err != nil {
		return err
	}

	tg, err := s.loader.TrailGit(ctx, ev.OrgID, trailID)
	if err != nil {
		return err
	}
	if tg.Repository == "" || tg.Commit == "" {
		return nil // no git coordinate to gate
	}

	repo, err := ParseRepo(tg.Repository)
	if err != nil {
		return err
	}

	providers, err := s.loader.Providers(ctx, ev.OrgID)
	if err != nil {
		return err
	}
	cfg, ok := matchProvider(providers, repo.Host)
	if !ok {
		return nil // no provider configured for this host
	}

	v := Verdict{
		Compliant:   p.Compliant,
		Context:     "fides/compliance",
		Description: descriptionFor(p.Compliant),
		TargetURL:   s.baseURL + "/?trail=" + p.TrailID,
	}
	return PostStatus(ctx, s.client, cfg.Provider, cfg.APIBase, cfg.Token, repo, tg.Commit, v)
}

func matchProvider(providers []ProviderConfig, host string) (ProviderConfig, bool) {
	for _, p := range providers {
		if p.Host == host {
			return p, true
		}
	}
	return ProviderConfig{}, false
}

func descriptionFor(compliant bool) string {
	if compliant {
		return "Fides: all compliance gates passed"
	}
	return "Fides: compliance gate failed"
}
