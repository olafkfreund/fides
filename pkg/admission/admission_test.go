package admission

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestExtractDigest(t *testing.T) {
	d := strings.Repeat("a", 64)
	cases := map[string]string{
		"repo@sha256:" + d:                       d,
		"reg.io/ns/img@sha256:" + d:              d,
		"repo:tag":                               "",
		"repo@sha256:short":                      "",
		"repo@sha256:" + strings.Repeat("z", 64): "", // non-hex
	}
	for in, want := range cases {
		if got := extractDigest(in); got != want {
			t.Errorf("extractDigest(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractImages(t *testing.T) {
	podJSON := []byte(`{"spec":{
		"initContainers":[{"name":"i","image":"init@sha256:x"}],
		"containers":[{"name":"a","image":"app:1"},{"name":"b","image":"b@sha256:y"}],
		"ephemeralContainers":[{"name":"e","image":"debug:latest"}]
	}}`)
	imgs, err := ExtractImages(podJSON)
	if err != nil {
		t.Fatalf("ExtractImages: %v", err)
	}
	if len(imgs) != 4 {
		t.Fatalf("expected 4 images, got %v", imgs)
	}
}

type fakeChecker map[string]ImageStatus

func (f fakeChecker) CheckImage(_ context.Context, _ uuid.UUID, sha string) (ImageStatus, error) {
	return f[sha], nil // unknown digest -> zero value (Registered=false)
}

func TestEvaluateEnforceDeniesShadowAndNonCompliant(t *testing.T) {
	good := strings.Repeat("a", 64)
	bad := strings.Repeat("b", 64)
	shadow := strings.Repeat("c", 64)
	checker := fakeChecker{
		good: {Registered: true, Compliant: true},
		bad:  {Registered: true, Compliant: false},
		// shadow is absent -> Registered:false
	}
	rv := &Reviewer{Checker: checker, Mode: ModeEnforce}

	// Compliant only -> allowed.
	if d := rv.Evaluate(context.Background(), uuid.New(), []string{"r@sha256:" + good}); !d.Allowed {
		t.Fatalf("compliant image should be allowed: %+v", d)
	}
	// Non-compliant -> denied.
	if d := rv.Evaluate(context.Background(), uuid.New(), []string{"r@sha256:" + bad}); d.Allowed {
		t.Fatalf("non-compliant image should be denied")
	}
	// Shadow -> denied with a reason mentioning shadow.
	d := rv.Evaluate(context.Background(), uuid.New(), []string{"r@sha256:" + shadow})
	if d.Allowed || !strings.Contains(d.Message, "shadow") {
		t.Fatalf("shadow image should be denied with a shadow reason: %+v", d)
	}
}

func TestEvaluateAuditAllowsButWarns(t *testing.T) {
	shadow := strings.Repeat("c", 64)
	rv := &Reviewer{Checker: fakeChecker{}, Mode: ModeAudit}
	d := rv.Evaluate(context.Background(), uuid.New(), []string{"r@sha256:" + shadow})
	if !d.Allowed {
		t.Fatalf("audit mode must allow")
	}
	if len(d.Warnings) == 0 {
		t.Fatalf("audit mode should warn about the shadow image")
	}
}

func TestEvaluateUnpinnedImageWarnsNotDenied(t *testing.T) {
	rv := &Reviewer{Checker: fakeChecker{}, Mode: ModeEnforce}
	d := rv.Evaluate(context.Background(), uuid.New(), []string{"repo:latest"})
	if !d.Allowed {
		t.Fatalf("un-pinned image should not be denied (can't verify), got %+v", d)
	}
	if len(d.Warnings) == 0 {
		t.Fatalf("un-pinned image should produce a warning")
	}
}

func TestReviewEchoesUID(t *testing.T) {
	good := strings.Repeat("a", 64)
	rv := &Reviewer{Checker: fakeChecker{good: {Registered: true, Compliant: true}}, Mode: ModeEnforce}
	obj, _ := json.Marshal(map[string]any{"spec": map[string]any{
		"containers": []map[string]string{{"name": "a", "image": "r@sha256:" + good}},
	}})
	resp := rv.Review(context.Background(), uuid.New(), &AdmissionRequest{UID: "uid-123", Object: obj})
	if resp.UID != "uid-123" || !resp.Allowed {
		t.Fatalf("expected allowed response echoing uid, got %+v", resp)
	}
}
