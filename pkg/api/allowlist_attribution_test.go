package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"fides/pkg/auth"
)

// approved_by is the "who accepted this risk" half of an allowlist entry. The
// handler used p.Email directly, which is EMPTY for a machine principal -- and
// a machine principal is what CI uses, so the entries that actually exist on
// the live instance carry no approver at all. approverIdentity already solves
// this for approvals; the allowlist just never used it.
func TestApproverIdentityNeverEmptyForMachinePrincipals(t *testing.T) {
	cases := map[string]struct {
		p    auth.Principal
		want string
	}{
		"human with email": {
			auth.Principal{Email: "olaf@freundcloud.com", Kind: "session"},
			"olaf@freundcloud.com",
		},
		"service account with a user id": {
			auth.Principal{UserID: uuid.MustParse("11111111-2222-3333-4444-555555555555"), Kind: "service"},
			"11111111-2222-3333-4444-555555555555",
		},
		"bare org token — no email, no user id": {
			auth.Principal{Kind: "service"},
			"service-account",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := approverIdentity(&tc.p)
			if got != tc.want {
				t.Errorf("approverIdentity = %q, want %q", got, tc.want)
			}
			if got == "" {
				t.Error("approved_by must never be empty — an accepted risk with no approver " +
					"is not an attributable exception")
			}
		})
	}
}

// The reason guard runs before any database work, so this needs no Postgres:
// a request without a justification must be rejected outright rather than
// silently stored as a blank exception.
func TestAddAllowlistRequiresAReason(t *testing.T) {
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{OrgID: uuid.New(), Role: auth.RoleAdmin, Kind: "service"})
	envID := uuid.New().String()

	for name, body := range map[string]string{
		"missing":    `{"artifact_sha256":"` + strings64() + `"}`,
		"empty":      `{"artifact_sha256":"` + strings64() + `","reason":""}`,
		"whitespace": `{"artifact_sha256":"` + strings64() + `","reason":"   "}`,
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost,
				"/api/v1/environments/"+envID+"/allowlist", bytes.NewReader([]byte(body)))
			req = req.WithContext(ctx)
			req.SetPathValue("id", envID)
			w := httptest.NewRecorder()

			(&Server{}).handleAddAllowlist(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 — an allowlist entry without a reason "+
					"is an unevaluatable accepted risk", w.Code)
			}
		})
	}
}

func strings64() string { return "0a80d1f17932146c960925abca093e15f27cdec85305199320812cace6ad67a7" }
