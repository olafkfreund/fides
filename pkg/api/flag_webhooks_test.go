package api

import "testing"

func TestParseUnleashWebhook(t *testing.T) {
	cases := []struct {
		body            string
		wantKey, wantSt string
		wantActor       string
	}{
		{`{"type":"feature-environment-enabled","createdBy":"olaf@acme.com","featureName":"checkout-v2","environment":"production"}`, "checkout-v2", "on", "olaf@acme.com"},
		{`{"type":"feature-environment-disabled","createdBy":"ci","featureName":"new-pricing","environment":"prod"}`, "new-pricing", "off", "ci"},
		{`{"type":"feature-updated","createdBy":"a","featureName":"f","environment":"e"}`, "f", "updated", "a"},
	}
	for _, c := range cases {
		req, ok := parseUnleashWebhook([]byte(c.body))
		if !ok || req.FlagKey != c.wantKey || req.NewState != c.wantSt || req.Actor != c.wantActor {
			t.Errorf("parseUnleash(%s) = %+v ok=%v, want key=%s state=%s actor=%s", c.body, req, ok, c.wantKey, c.wantSt, c.wantActor)
		}
	}
	// A payload with no feature name is not a flag change.
	if _, ok := parseUnleashWebhook([]byte(`{"type":"x"}`)); ok {
		t.Error("expected parse failure for a payload with no featureName")
	}
}

func TestParseFlagsmithWebhook(t *testing.T) {
	body := `{"event_type":"AUDIT_LOG_CREATED","data":{"log":"Flag state updated for feature 'checkout_v2'","author":{"email":"user@acme.com"},"environment":{"name":"Production"}}}`
	req, ok := parseFlagsmithWebhook([]byte(body))
	if !ok || req.FlagKey != "checkout_v2" || req.Actor != "user@acme.com" || req.Environment != "Production" {
		t.Fatalf("parseFlagsmith = %+v ok=%v, want checkout_v2/user@acme.com/Production", req, ok)
	}
	// A log with no quoted feature name yields no flag key.
	if _, ok := parseFlagsmithWebhook([]byte(`{"data":{"log":"something else"}}`)); ok {
		t.Error("expected parse failure when no feature name is present")
	}
}
