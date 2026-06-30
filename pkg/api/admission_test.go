package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fides/pkg/admission"

	"github.com/google/uuid"
)

func postReview(t *testing.T, s *Server, body string) admission.AdmissionReview {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admission/validate", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleAdmissionValidate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var out admission.AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return out
}

func TestAdmissionPathIsPublic(t *testing.T) {
	if !isPublicPath("/api/v1/admission/validate") {
		t.Fatalf("admission webhook path must be public (mTLS-authenticated by the API server)")
	}
}

func TestAdmissionAllowsWhenOrgUnconfigured(t *testing.T) {
	t.Setenv("FIDES_ADMISSION_ORG_ID", "")
	s := newTestServer()
	out := postReview(t, s, `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"u1","object":{}}}`)
	if out.Response == nil || out.Response.UID != "u1" || !out.Response.Allowed {
		t.Fatalf("expected allowed response echoing uid u1, got %+v", out.Response)
	}
	if len(out.Response.Warnings) == 0 {
		t.Fatalf("expected a misconfiguration warning")
	}
}

func TestAdmissionAuditAllowsUnpinnedImage(t *testing.T) {
	t.Setenv("FIDES_ADMISSION_ORG_ID", uuid.NewString())
	t.Setenv("FIDES_ADMISSION_MODE", "audit")
	s := newTestServer() // nil DB is fine: un-pinned image never hits the checker
	body := `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"u2","object":{"spec":{"containers":[{"name":"a","image":"nginx:latest"}]}}}}`
	out := postReview(t, s, body)
	if out.Response == nil || !out.Response.Allowed {
		t.Fatalf("audit mode should allow an un-pinned image, got %+v", out.Response)
	}
	if len(out.Response.Warnings) == 0 {
		t.Fatalf("expected a 'not digest-pinned' warning")
	}
}
