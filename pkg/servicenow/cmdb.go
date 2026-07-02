package servicenow

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"fides/pkg/events"
)

// RunningService is one service observed running in an environment, with its
// image digest and whether Fides recognises it. It is the decoupled input to
// the IRE payload builder.
type RunningService struct {
	Service     string `json:"service"`
	Digest      string `json:"digest"` // image content digest (sha256 hex); "" if unknown
	Repository  string `json:"repository"`
	Registered  bool   `json:"registered"` // known in Fides (not a shadow)
	Environment string `json:"environment"`
}

// BuildIREPayload maps running services to a ServiceNow IRE payload:
//   - cmdb_ci_service_discovered  (the logical service)
//   - cmdb_ci_docker_image        (per unique image digest)
//   - cmdb_ci_docker_container    (the running instance)
//
// with relations container->image ("Instantiated From") and
// container->service ("Depends on::Used by").
func BuildIREPayload(services []RunningService) IREPayload {
	var p IREPayload
	serviceIdx := map[string]int{} // service name -> items index
	imageIdx := map[string]int{}   // digest -> items index

	add := func(item IREItem) int {
		p.Items = append(p.Items, item)
		return len(p.Items) - 1
	}

	for _, svc := range services {
		// Logical service CI (deduped by name).
		sIdx, ok := serviceIdx[svc.Service]
		if !ok {
			sIdx = add(IREItem{ClassName: "cmdb_ci_service_discovered", Values: map[string]any{
				"name":              svc.Service,
				"short_description": "Fides-discovered service in " + svc.Environment,
			}})
			serviceIdx[svc.Service] = sIdx
		}

		// Image CI (deduped by digest), only when we have a digest.
		imgIdx := -1
		if svc.Digest != "" {
			if i, ok := imageIdx[svc.Digest]; ok {
				imgIdx = i
			} else {
				vals := map[string]any{
					"name":   nameFor(svc.Repository, svc.Service),
					"digest": "sha256:" + svc.Digest,
				}
				if svc.Repository != "" {
					vals["repository"] = svc.Repository
				}
				imgIdx = add(IREItem{ClassName: "cmdb_ci_docker_image", Values: vals})
				imageIdx[svc.Digest] = imgIdx
			}
		}

		// Container CI (the running instance).
		cIdx := add(IREItem{ClassName: "cmdb_ci_docker_container", Values: map[string]any{
			"name":  containerName(svc),
			"state": "running",
		}})

		if imgIdx >= 0 {
			p.Relations = append(p.Relations, IRERelation{Parent: cIdx, Child: imgIdx, Type: "Instantiated From"})
		}
		p.Relations = append(p.Relations, IRERelation{Parent: cIdx, Child: sIdx, Type: "Depends on::Used by"})
	}
	return p
}

func nameFor(repo, service string) string {
	if repo != "" {
		return repo
	}
	return service
}

func containerName(svc RunningService) string {
	if svc.Digest != "" {
		n := len(svc.Digest)
		if n > 12 {
			n = 12
		}
		return fmt.Sprintf("%s-%s", svc.Service, svc.Digest[:n])
	}
	return svc.Service
}

// ---- CMDB reconciliation sink ----

// CMDBEventType is the event the CMDB sink consumes (emitted on every snapshot).
const CMDBEventType = "snapshot.reported"

// CMDBSink reconciles running services into ServiceNow CMDB via IRE.
type CMDBSink struct {
	loader    Loader
	newClient func(Config) (*Client, error)
}

func NewCMDBSink(loader Loader) *CMDBSink {
	return &CMDBSink{loader: loader, newClient: New}
}

func (s *CMDBSink) Name() string { return "servicenow-cmdb" }

type reportedPayload struct {
	Environment string           `json:"environment"`
	Services    []RunningService `json:"services"`
}

// Deliver builds and posts an IRE payload for the snapshot's running services,
// or anchors a signed deployment attestation onto a CI, depending on the event
// type.
func (s *CMDBSink) Deliver(ctx context.Context, ev events.Event) error {
	switch ev.Type {
	case CMDBEventType:
		return s.deliverSnapshot(ctx, ev)
	case AnchorEventType:
		return s.deliverAnchor(ctx, ev)
	default:
		return nil
	}
}

func (s *CMDBSink) deliverSnapshot(ctx context.Context, ev events.Event) error {
	cfg, enabled, err := s.loader.ServiceNowConfig(ctx, ev.OrgID)
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}

	var p reportedPayload
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return err
	}
	if len(p.Services) == 0 {
		return nil
	}
	for i := range p.Services {
		if p.Services[i].Environment == "" {
			p.Services[i].Environment = p.Environment
		}
	}

	client, err := s.newClient(cfg)
	if err != nil {
		return err
	}
	return client.IdentifyReconcile(ctx, BuildIREPayload(p.Services), nil)
}

// ---- Deployment attestation anchoring ----

// AnchorEventType is emitted on change close / deploy to anchor a signed
// deployment attestation onto the relevant CMDB CI, proving that what was
// deployed (image digest, commit) matches the evidence produced by the
// pipeline (build log, runtime snapshot) and, when present, the change that
// authorized it.
const AnchorEventType = "deployment.attested"

// DeploymentAttestation is the decoupled input for CMDB anchoring: it captures
// what was deployed and where the supporting evidence lives, so it can be
// attached to the CI independent of how Fides resolved it.
type DeploymentAttestation struct {
	CI            string    `json:"ci,omitempty"`            // CMDB CI name; used to resolve CISysID when it is empty
	CISysID       string    `json:"ci_sys_id,omitempty"`     // resolved CI sys_id (preferred; e.g. from change_request.cmdb_ci)
	ChangeNumber  string    `json:"change_number,omitempty"` // ServiceNow change request number, if any
	TrailID       string    `json:"trail_id"`
	FlowName      string    `json:"flow_name,omitempty"`
	Environment   string    `json:"environment,omitempty"`
	ImageDigest   string    `json:"image_digest,omitempty"`         // sha256 hex artifact fingerprint
	Commit        string    `json:"commit,omitempty"`               // git commit SHA that produced the artifact
	BuildLogRef   string    `json:"build_log_ref,omitempty"`        // pointer to the build log (CI run URL, etc.)
	SnapshotRef   string    `json:"runtime_snapshot_ref,omitempty"` // Fides environment_snapshots.id proving it's actually running
	AttestationID string    `json:"attestation_id,omitempty"`
	ContentHash   string    `json:"content_hash,omitempty"` // tamper-evidence chain hash (see pkg/ledger)
	Compliant     bool      `json:"compliant"`
	AnchoredAt    time.Time `json:"anchored_at"`
}

// fileName is the deterministic attachment name for an attestation, so
// repeated anchors of the same attestation are recognisable as re-deliveries
// rather than piling up as unrelated files.
func (d DeploymentAttestation) fileName() string {
	id := d.AttestationID
	if id == "" {
		id = d.TrailID
	}
	if id == "" {
		id = "unknown"
	}
	return "fides-deployment-attestation-" + id + ".json"
}

// AnchorDeploymentAttestation uploads a signed deployment attestation as a CI
// attachment via the ServiceNow Attachment API — evidence visible in the CI's
// timeline regardless of custom fields on its table — and best-effort posts a
// short human-readable summary onto the CI record itself.
func AnchorDeploymentAttestation(ctx context.Context, client *Client, att DeploymentAttestation) (map[string]any, error) {
	if att.CISysID == "" {
		return nil, fmt.Errorf("servicenow: ci_sys_id is required to anchor a deployment attestation")
	}
	if att.AnchoredAt.IsZero() {
		att.AnchoredAt = time.Now().UTC()
	}
	body, err := json.MarshalIndent(att, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("servicenow: marshal deployment attestation: %w", err)
	}
	result, err := client.AttachFile(ctx, "cmdb_ci", att.CISysID, att.fileName(), "application/json", body)
	if err != nil {
		return nil, err
	}
	// Best-effort: not every cmdb_ci-derived table has a free-text field, so a
	// failure here must not fail the anchor — the attachment above is the
	// evidence of record.
	_, _ = client.UpdateRecord(ctx, "cmdb_ci", att.CISysID, map[string]any{
		"comments": deploymentSummary(att),
	})
	return result, nil
}

func deploymentSummary(att DeploymentAttestation) string {
	status := "COMPLIANT"
	if !att.Compliant {
		status = "NON-COMPLIANT"
	}
	s := fmt.Sprintf("Fides deployment attestation anchored [%s] — digest=%s commit=%s",
		status, shortRef(att.ImageDigest), shortRef(att.Commit))
	if att.ChangeNumber != "" {
		s += " change=" + att.ChangeNumber
	}
	if att.BuildLogRef != "" {
		s += " build_log=" + att.BuildLogRef
	}
	if att.SnapshotRef != "" {
		s += " runtime_snapshot=" + att.SnapshotRef
	}
	return s
}

func shortRef(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// deliverAnchor resolves the target CI (if only a name was given) and anchors
// the deployment attestation onto it.
func (s *CMDBSink) deliverAnchor(ctx context.Context, ev events.Event) error {
	cfg, enabled, err := s.loader.ServiceNowConfig(ctx, ev.OrgID)
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}

	var att DeploymentAttestation
	if err := json.Unmarshal(ev.Payload, &att); err != nil {
		return err
	}

	client, err := s.newClient(cfg)
	if err != nil {
		return err
	}

	if att.CISysID == "" && att.CI != "" {
		res, err := client.QueryTable(ctx, "cmdb_ci", "nameLIKE"+att.CI+"^active=true", "sys_id", "name")
		if err != nil {
			return err
		}
		if len(res.Result) > 0 {
			if sysID, _ := res.Result[0]["sys_id"].(string); sysID != "" {
				att.CISysID = sysID
			}
		}
	}
	if att.CISysID == "" {
		return fmt.Errorf("servicenow: cannot resolve CMDB CI for deployment attestation (ci=%q)", att.CI)
	}

	_, err = AnchorDeploymentAttestation(ctx, client, att)
	return err
}
