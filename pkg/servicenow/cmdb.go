package servicenow

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
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
// with relations image->container ("Instantiates::Instance of") and
// container->service ("Depends on::Used by"). Both names must exist in
// cmdb_rel_type or IRE rejects the relation.
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
				// image_id, not digest: the IRE identify rule for
				// cmdb_ci_docker_image matches on image_id, so a payload
				// carrying only name+digest is rejected as
				// MISSING_MATCHING_ATTRIBUTES and no CI is created.
				vals := map[string]any{
					"name":     nameFor(svc.Repository, svc.Service),
					"image_id": "sha256:" + svc.Digest,
				}
				if svc.Repository != "" {
					vals["repository"] = svc.Repository
				}
				imgIdx = add(IREItem{ClassName: "cmdb_ci_docker_image", Values: vals})
				imageIdx[svc.Digest] = imgIdx
			}
		}

		// Container CI (the running instance). container_id is the identify
		// rule's matching attribute, so it has to be present and stable — the
		// name already encodes service+digest, which is exactly that.
		cIdx := add(IREItem{ClassName: "cmdb_ci_docker_container", Values: map[string]any{
			"name":         containerName(svc),
			"container_id": containerName(svc),
			"state":        "running",
		}})

		if imgIdx >= 0 {
			// "Instantiates::Instance of" reads parent-instantiates-child, so
			// the image is the parent and the container the child. The former
			// "Instantiated From" is not a cmdb_rel_type name at all and every
			// relation carrying it was rejected.
			p.Relations = append(p.Relations, IRERelation{Parent: imgIdx, Child: cIdx, Type: "Instantiates::Instance of"})
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

// CMDBInventoryEnabled reports whether Fides may create CMDB configuration
// items — the running services, images and containers it observes.
//
// This is off by default, and deliberately so. On a shared instance the CMDB
// usually already has an owner: ARC, for example, syncs 274 Kubernetes
// workloads and 315 build artifacts into the same instance Fides points at,
// keyed by a name-encoded digest. Fides keys images by image_id through IRE,
// which cannot reconcile against that, so both writing produces two
// disconnected records for one binary — the classic duplicate-CI failure.
//
// Evidence anchoring is NOT gated by this. Attaching a signed attestation to a
// CI somebody else owns is exactly the division of labour a shared CMDB wants,
// and it is the integration ARC's own CSDM model asks Fides for.
func CMDBInventoryEnabled() bool {
	return os.Getenv("FIDES_SNOW_CMDB_ENABLED") == "true"
}

// CMDBSink reconciles running services into ServiceNow CMDB via IRE.
type CMDBSink struct {
	loader    Loader
	newClient func(Config) (*Client, error)
	inventory func() bool // overridable in tests
}

func NewCMDBSink(loader Loader) *CMDBSink {
	return &CMDBSink{loader: loader, newClient: New, inventory: CMDBInventoryEnabled}
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
		// Both of these create configuration items, so both are gated. They
		// also disagree with each other: this one keys images by image_id via
		// IRE while deliverArtifact creates them by name via the Table API, so
		// leaving one on and one off would have Fides duplicating its own CIs.
		if !s.inventory() {
			return nil
		}
		return s.deliverSnapshot(ctx, ev)
	case ArtifactEventType:
		if !s.inventory() {
			return nil
		}
		return s.deliverArtifact(ctx, ev)
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
	return client.IdentifyReconcile(ctx, BuildIREPayload(p.Services))
}

// ---- Deployment attestation anchoring ----

// AnchorEventType is emitted on change close / deploy to anchor a signed
// deployment attestation onto the relevant CMDB CI, proving that what was
// deployed (image digest, commit) matches the evidence produced by the
// pipeline (build log, runtime snapshot) and, when present, the change that
// authorized it.
const AnchorEventType = "deployment.attested"

// ArtifactEventType is emitted when a build artifact is reported to a trail
// (`fides artifact report`). The CMDB sink consumes it to keep a queryable
// image CI per digest, so the change gate can anchor a change's cmdb_ci.
const ArtifactEventType = "artifact.reported"

// artifactPayload is the artifact.reported event body.
type artifactPayload struct {
	SHA256 string `json:"sha256"`
	Name   string `json:"name"`
	Type   string `json:"type"`
}

// deliverArtifact upserts a cmdb_ci_docker_image CI carrying the reported
// digest, so a later change gate can resolve the change's Configuration item
// (cmdb_ci) from the trail's artifacts. This is the producer half of the
// binary anchor; ResolveImageCIsByDigest is the consumer.
//
// The digest is written into short_description ("<name> binary digest
// sha256:<hex>") because that is the field ServiceNow can actually filter on
// for this class — the same field, in the same format, the resolver matches.
// Idempotent: an image CI already recorded for the digest is left untouched.
// Non-image artifacts (sbom, sarif, ...) are skipped.
func (s *CMDBSink) deliverArtifact(ctx context.Context, ev events.Event) error {
	cfg, enabled, err := s.loader.ServiceNowConfig(ctx, ev.OrgID)
	if err != nil || !enabled {
		return err
	}

	var p artifactPayload
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return err
	}
	sha := strings.TrimPrefix(strings.TrimSpace(p.SHA256), "sha256:")
	if sha == "" {
		return nil
	}
	// Only container images anchor a change. An empty type is treated as an
	// image (the CLI's default `--type docker`); everything else is skipped.
	switch p.Type {
	case "", "docker", "container", "image":
	default:
		return nil
	}

	client, err := s.newClient(cfg)
	if err != nil {
		return err
	}

	// Idempotent: skip if an image CI for this digest already exists.
	if res, err := client.QueryTable(ctx, "cmdb_ci_docker_image", "short_descriptionLIKEsha256:"+sha, "sys_id"); err == nil && res != nil && len(res.Result) > 0 {
		return nil
	}

	name := p.Name
	if name == "" {
		name = "image"
	}
	short := sha
	if len(short) > 12 {
		short = short[:12]
	}
	// discovery_source must be a valid choice of cmdb_ci.discovery_source. The
	// Table API does not validate it the way IRE does — it stores an unknown
	// value as empty and returns 201, so a hardcoded "fides" produced CIs that
	// were created successfully and then attributable to nobody. Use the same
	// configured source the IRE path uses.
	_, err = client.CreateRecord(ctx, "cmdb_ci_docker_image", map[string]any{
		"name":               fmt.Sprintf("%s@sha256:%s", name, short),
		"short_description":  fmt.Sprintf("%s binary digest sha256:%s", name, sha),
		"discovery_source":   client.cfg.DataSource,
		"operational_status": "1",
	})
	return err
}

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
