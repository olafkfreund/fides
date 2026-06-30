package servicenow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"fides/pkg/events"
)

// EventType is the integration event the ITOM sink reacts to.
const EventType = "snapshot.noncompliant"

// Loader resolves a tenant's ServiceNow connection (with the credential already
// fetched from the secrets provider) and whether the integration is enabled.
type Loader interface {
	ServiceNowConfig(ctx context.Context, orgID uuid.UUID) (cfg Config, enabled bool, err error)
}

// ITOMSink forwards Fides shadow/drift findings to ServiceNow Event Management
// (em_event). It is an events.Sink consumed by the dispatcher.
type ITOMSink struct {
	loader    Loader
	newClient func(Config) (*Client, error) // overridable in tests
}

// NewITOMSink builds the ITOM sink.
func NewITOMSink(loader Loader) *ITOMSink {
	return &ITOMSink{loader: loader, newClient: New}
}

func (s *ITOMSink) Name() string { return "servicenow-itom" }

type snapshotPayload struct {
	EnvironmentID string   `json:"environment_id"`
	SnapshotID    string   `json:"snapshot_id"`
	Shadows       []string `json:"shadows"`
	Drifts        []string `json:"drifts"`
}

// Deliver emits one em_event per shadow/drift finding for the event's tenant.
func (s *ITOMSink) Deliver(ctx context.Context, ev events.Event) error {
	if ev.Type != EventType {
		return nil
	}
	cfg, enabled, err := s.loader.ServiceNowConfig(ctx, ev.OrgID)
	if err != nil {
		return err
	}
	if !enabled {
		return nil // ServiceNow not configured for this tenant
	}

	var p snapshotPayload
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return err
	}

	node := p.EnvironmentID
	addInfo := fmt.Sprintf(`{"environment_id":%q,"snapshot_id":%q}`, p.EnvironmentID, p.SnapshotID)

	var em []Event
	for _, sh := range p.Shadows {
		em = append(em, Event{
			Source: "Fides-Compliance", EventClass: "ShadowDeployment", Node: node,
			MetricName: "UnregisteredImage", Severity: "1", // Critical
			Description: "CRITICAL: " + sh, AdditionalInfo: addInfo,
			MessageKey: messageKey("ShadowDeployment", p.EnvironmentID, sh),
		})
	}
	for _, dr := range p.Drifts {
		em = append(em, Event{
			Source: "Fides-Compliance", EventClass: "RuntimeDrift", Node: node,
			MetricName: "ComplianceDrift", Severity: "3", // Minor
			Description: dr, AdditionalInfo: addInfo,
			MessageKey: messageKey("RuntimeDrift", p.EnvironmentID, dr),
		})
	}
	if len(em) == 0 {
		return nil
	}

	client, err := s.newClient(cfg)
	if err != nil {
		return err
	}
	return client.SendEvents(ctx, em...)
}

// messageKey is a stable de-dup key so repeated snapshots update the same alert
// instead of creating new ones.
func messageKey(class, env, desc string) string {
	sum := sha256.Sum256([]byte(class + "|" + env + "|" + desc))
	return "fides-" + hex.EncodeToString(sum[:])[:16]
}
