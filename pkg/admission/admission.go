// Package admission implements a Kubernetes ValidatingAdmissionWebhook that
// rejects Pods whose container image digests are either unregistered in Fides
// (shadow deployments) or registered but non-compliant. It reuses the same
// artifact/compliance model as Fides' drift detection, turning it into a
// deploy-time gate.
package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Mode controls enforcement.
type Mode string

const (
	// ModeEnforce denies non-compliant/shadow workloads.
	ModeEnforce Mode = "enforce"
	// ModeAudit allows everything but attaches warnings (dry-run).
	ModeAudit Mode = "audit"
)

// ---- AdmissionReview wire types (admission.k8s.io/v1, minimal subset) ----

type AdmissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    *AdmissionRequest  `json:"request,omitempty"`
	Response   *AdmissionResponse `json:"response,omitempty"`
}

type AdmissionRequest struct {
	UID       string          `json:"uid"`
	Namespace string          `json:"namespace"`
	Object    json.RawMessage `json:"object"`
}

type AdmissionResponse struct {
	UID      string   `json:"uid"`
	Allowed  bool     `json:"allowed"`
	Status   *Status  `json:"status,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

type Status struct {
	Code    int32  `json:"code,omitempty"`
	Message string `json:"message"`
}

// pod is the minimal shape needed to enumerate container images.
type pod struct {
	Spec struct {
		Containers          []container `json:"containers"`
		InitContainers      []container `json:"initContainers"`
		EphemeralContainers []container `json:"ephemeralContainers"`
	} `json:"spec"`
}

type container struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

// ExtractImages returns every container image referenced by a Pod object.
func ExtractImages(raw json.RawMessage) ([]string, error) {
	var p pod
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("decode pod: %w", err)
	}
	var images []string
	for _, set := range [][]container{p.Spec.InitContainers, p.Spec.Containers, p.Spec.EphemeralContainers} {
		for _, c := range set {
			if c.Image != "" {
				images = append(images, c.Image)
			}
		}
	}
	return images, nil
}

// extractDigest returns the hex sha256 from a digest-pinned image reference
// (e.g. "repo@sha256:abcd..."), or "" if the image is not digest-pinned.
func extractDigest(image string) string {
	const marker = "@sha256:"
	i := strings.Index(image, marker)
	if i < 0 {
		return ""
	}
	hex := image[i+len(marker):]
	// A sha256 digest is 64 lowercase hex chars; strip any trailing tag noise.
	if len(hex) < 64 {
		return ""
	}
	hex = hex[:64]
	for _, r := range hex {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return ""
		}
	}
	return hex
}

// ImageStatus is the Fides view of an image digest.
type ImageStatus struct {
	Registered bool
	Compliant  bool
}

// Checker resolves an image digest's status within a tenant.
type Checker interface {
	CheckImage(ctx context.Context, orgID uuid.UUID, sha256 string) (ImageStatus, error)
}

// Reviewer evaluates a Pod's images against Fides.
type Reviewer struct {
	Checker Checker
	Mode    Mode
}

// Decision is the outcome of reviewing a set of images.
type Decision struct {
	Allowed  bool
	Message  string
	Warnings []string
}

// Evaluate checks each image's digest. Digest-pinned images are verified;
// un-pinned images are allowed with a warning (a digest can't be resolved at
// admission time). In enforce mode any shadow/non-compliant image denies the
// pod; in audit mode the same conditions become warnings.
func (rv *Reviewer) Evaluate(ctx context.Context, orgID uuid.UUID, images []string) Decision {
	var reasons, warnings []string

	for _, img := range images {
		digest := extractDigest(img)
		if digest == "" {
			warnings = append(warnings, fmt.Sprintf("image %q is not digest-pinned; Fides cannot verify it", img))
			continue
		}
		st, err := rv.Checker.CheckImage(ctx, orgID, digest)
		if err != nil {
			if rv.Mode == ModeEnforce {
				return Decision{Allowed: false, Message: fmt.Sprintf("Fides compliance check failed for %q", img)}
			}
			warnings = append(warnings, fmt.Sprintf("Fides check errored for %q: %v", img, err))
			continue
		}
		switch {
		case !st.Registered:
			reasons = append(reasons, fmt.Sprintf("image %q (sha256:%s) is not registered in Fides (shadow deployment)", img, digest[:12]))
		case !st.Compliant:
			reasons = append(reasons, fmt.Sprintf("image %q is registered but fails Fides compliance", img))
		}
	}

	if len(reasons) > 0 {
		if rv.Mode == ModeEnforce {
			return Decision{Allowed: false, Message: "Fides admission denied: " + strings.Join(reasons, "; "), Warnings: warnings}
		}
		warnings = append(warnings, reasons...)
	}
	return Decision{Allowed: true, Warnings: warnings}
}

// Review reads a Pod from an AdmissionRequest and produces a response.
func (rv *Reviewer) Review(ctx context.Context, orgID uuid.UUID, req *AdmissionRequest) *AdmissionResponse {
	if req == nil {
		return &AdmissionResponse{Allowed: true}
	}
	images, err := ExtractImages(req.Object)
	if err != nil {
		// Fail open on an unparseable object only in audit mode; enforce denies.
		if rv.Mode == ModeEnforce {
			return &AdmissionResponse{UID: req.UID, Allowed: false, Status: &Status{Code: 400, Message: "could not parse pod object"}}
		}
		return &AdmissionResponse{UID: req.UID, Allowed: true, Warnings: []string{"Fides could not parse the pod object"}}
	}
	d := rv.Evaluate(ctx, orgID, images)
	resp := &AdmissionResponse{UID: req.UID, Allowed: d.Allowed, Warnings: d.Warnings}
	if d.Message != "" {
		resp.Status = &Status{Message: d.Message}
	}
	return resp
}
