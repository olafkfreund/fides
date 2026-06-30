package policy

import "testing"

func TestEvaluateRuleBoolean(t *testing.T) {
	e := NewPolicyEngine()

	cases := []struct {
		name    string
		payload string
		query   string
		want    bool
	}{
		{"zero critical vulns passes", `{"critical": 0}`, `.critical == 0`, true},
		{"nonzero critical fails", `{"critical": 3}`, `.critical == 0`, false},
		{"array length check", `{"vulns": []}`, `.vulns | length == 0`, true},
		{"nested field", `{"scan": {"passed": true}}`, `.scan.passed`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := e.EvaluateRule(tc.payload, tc.query)
			if err != nil {
				t.Fatalf("EvaluateRule: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestEvaluateRuleInvalidJSON(t *testing.T) {
	e := NewPolicyEngine()
	if _, err := e.EvaluateRule(`{not json`, `.x == 1`); err == nil {
		t.Fatalf("expected error for invalid JSON payload")
	}
}

func TestEvaluateRuleInvalidQuery(t *testing.T) {
	e := NewPolicyEngine()
	if _, err := e.EvaluateRule(`{"x":1}`, `.x ==`); err == nil {
		t.Fatalf("expected error for invalid jq query")
	}
}

func TestEvaluateAttestationAllRules(t *testing.T) {
	e := NewPolicyEngine()
	payload := `{"critical": 0, "high": 0, "tests_passed": true}`

	ok, failed, err := e.EvaluateAttestation(payload, []string{
		`.critical == 0`,
		`.high == 0`,
		`.tests_passed`,
	})
	if err != nil {
		t.Fatalf("EvaluateAttestation: %v", err)
	}
	if !ok || len(failed) != 0 {
		t.Fatalf("expected all rules to pass, failed=%v", failed)
	}

	// One failing rule must be reported and the overall result must be false.
	ok, failed, _ = e.EvaluateAttestation(payload, []string{`.critical == 0`, `.high == 5`})
	if ok {
		t.Fatalf("expected attestation to fail")
	}
	if len(failed) != 1 || failed[0] != `.high == 5` {
		t.Fatalf("expected the failing rule to be reported, got %v", failed)
	}
}
