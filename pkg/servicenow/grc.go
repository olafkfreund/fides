package servicenow

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"

	"fides/pkg/events"
)

// GRCEventType is the integration event the GRC sink reacts to: a trail
// verdict. Same event the commit-status sink consumes, read for a different
// audience — a green check on a commit is for the engineer, a control test is
// for the auditor.
const GRCEventType = "compliance.evaluated"

// GRC control-evidence tables. sn_audit_control_test rather than sn_grc_item,
// which the CSDM plan originally named: sn_grc_item is a base class whose rows
// are Risks and Controls, and writing to a base class directly is wrong.
//
// sn_grc_indicator_result would be the natural continuous-monitoring target and
// is not an option: it returns 403 to a REST insert even for an account holding
// admin, because ServiceNow reserves it for its own indicator collection engine.
// That is a design constraint, not a permission to request, so there is no
// better table waiting behind a role grant. sn_audit_control_test is writable
// today and its own columns are already a control-evidence model. See the probe
// report in the ARC repo, docs/clouds/SERVICENOW-GRC-COMPLIANCE-PROBE-REPORT.md.
const (
	grcControlTable = "sn_compliance_control"
	grcTestTable    = "sn_audit_control_test"
)

// GRCEnabled reports whether Fides may write control-test evidence into
// ServiceNow's Policy & Compliance module.
//
// Off by default, and for the same reason the CMDB snapshot mirror is: on a
// shared instance the GRC control catalogue belongs to whoever runs the
// compliance programme, and one control test per control per attestation per
// deploy is a volume they have to agree to carry before it starts arriving.
// Fides produces the verdicts either way; this only decides whether it also
// files them.
func GRCEnabled() bool { return os.Getenv("FIDES_SNOW_GRC_ENABLED") == "true" }

// ControlRef is a Fides control that a given attestation type satisfies.
type ControlRef struct {
	Key  string // e.g. "SOC2-CC7.1" — matched against the ServiceNow control name
	Name string
}

// ControlLoader resolves which controls an attestation type is evidence for.
type ControlLoader interface {
	ControlsForAttestation(ctx context.Context, orgID uuid.UUID, attestationType string) ([]ControlRef, error)
}

// GRCSink files each Fides trail verdict as a ServiceNow control test against
// the compliance control the attestation is evidence for.
//
// What this replaces is worth stating plainly. A sampled live control on the
// probed instance reads "Detective / Quarterly / SOX Control Attestation" — a
// human ticking a box every three months. The same control fed from here is
// continuous and machine-evidenced, without changing its framework mapping or
// its auditor-facing identity.
type GRCSink struct {
	loader    Loader
	controls  ControlLoader
	newClient func(Config) (*Client, error)

	// Overridable in tests.
	enabled func() bool
}

// NewGRCSink builds the GRC sink. controls resolves attestation type ->
// controls; nil disables the sink entirely.
func NewGRCSink(loader Loader, controls ControlLoader) *GRCSink {
	return &GRCSink{loader: loader, controls: controls, newClient: New, enabled: GRCEnabled}
}

func (s *GRCSink) Name() string { return "servicenow-grc" }

type grcPayload struct {
	TrailID     string `json:"trail_id"`
	Attestation string `json:"attestation"`
	Compliant   bool   `json:"compliant"`
}

// Deliver writes one sn_audit_control_test per control the attestation
// satisfies. A control with no counterpart in ServiceNow is skipped rather than
// created: seeding the catalogue is a governance decision, not something a
// verdict should do as a side effect.
func (s *GRCSink) Deliver(ctx context.Context, ev events.Event) error {
	if ev.Type != GRCEventType || !s.enabled() || s.controls == nil {
		return nil
	}
	cfg, cfgEnabled, err := s.loader.ServiceNowConfig(ctx, ev.OrgID)
	if err != nil || !cfgEnabled {
		return err
	}

	var p grcPayload
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return err
	}
	if p.TrailID == "" || p.Attestation == "" {
		return nil
	}

	controls, err := s.controls.ControlsForAttestation(ctx, ev.OrgID, p.Attestation)
	if err != nil || len(controls) == 0 {
		return err
	}

	client, err := s.newClient(cfg)
	if err != nil {
		return err
	}

	// Both effectiveness dimensions carry the same verdict: Fides observes that
	// the control's evidence was produced and that it passed, which speaks to
	// design and operation alike. control_effectiveness is deliberately NOT set
	// — it is derived from these two, and setting it directly is accepted and
	// silently ignored, which reads as success and is not.
	effectiveness := "ineffective"
	opinion := "Fides: control evidence present but non-compliant."
	if p.Compliant {
		effectiveness = "effective"
		opinion = "Fides: control evidence present and compliant."
	}

	var failed []string
	for _, ctl := range controls {
		if err := s.fileControlTest(ctx, client, ctl, p, effectiveness, opinion); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", ctl.Key, err))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("servicenow: control test write failed for %s", strings.Join(failed, "; "))
	}
	return nil
}

// grcMarker is the idempotency key embedded in actual_results. sn_audit_control_test
// has no natural unique column Fides controls, so the marker it writes is the
// marker it queries for — one test per (trail, attestation, control), no matter
// how often the verdict is re-emitted or the event is redelivered.
func grcMarker(trailID, attestation string) string {
	return fmt.Sprintf("[fides:%s:%s]", trailID, attestation)
}

func (s *GRCSink) fileControlTest(ctx context.Context, client *Client, ctl ControlRef, p grcPayload, effectiveness, opinion string) error {
	// Resolve the ServiceNow control by the Fides control key. STARTSWITH
	// because a seeded control is named "<key> <description>", and the key is
	// the stable half.
	found, err := client.QueryTable(ctx, grcControlTable,
		"nameSTARTSWITH"+ctl.Key, "sys_id")
	if err != nil {
		return err
	}
	if len(found.Result) == 0 {
		return nil // not in the catalogue on this instance — nothing to evidence
	}
	sysID, _ := found.Result[0]["sys_id"].(string)
	if sysID == "" {
		return nil
	}

	marker := grcMarker(p.TrailID, p.Attestation)
	dup, err := client.QueryTable(ctx, grcTestTable,
		"control="+sysID+"^actual_resultsLIKE"+marker, "sys_id")
	if err != nil {
		return err
	}
	if len(dup.Result) > 0 {
		return nil // already filed
	}

	_, err = client.CreateRecord(ctx, grcTestTable, map[string]any{
		"control":                 sysID,
		"design_effectiveness":    effectiveness,
		"operation_effectiveness": effectiveness,
		"opinion":                 opinion,
		"actual_results": fmt.Sprintf(
			"%s attestation %q on trail %s: %s. Control %s (%s). Evidence: %s/trails/%s",
			marker, p.Attestation, p.TrailID, verdictWord(p.Compliant), ctl.Key, ctl.Name,
			strings.TrimSuffix(os.Getenv("FIDES_SERVER_URL"), "/"), p.TrailID),
	})
	return err
}

func verdictWord(compliant bool) string {
	if compliant {
		return "compliant"
	}
	return "non-compliant"
}
