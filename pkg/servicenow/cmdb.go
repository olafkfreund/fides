package servicenow

import (
	"context"
	"encoding/json"
	"fmt"

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

// Deliver builds and posts an IRE payload for the snapshot's running services.
func (s *CMDBSink) Deliver(ctx context.Context, ev events.Event) error {
	if ev.Type != CMDBEventType {
		return nil
	}
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
