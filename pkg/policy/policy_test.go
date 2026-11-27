package policy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

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
		{"multiple true values", `null`, `true, true`, true},
		{"later false value", `null`, `true, false`, false},
		{"earlier false value", `null`, `false, true`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := e.EvaluateRule(context.Background(), tc.payload, tc.query)
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
	if _, err := e.EvaluateRule(context.Background(), `{not json`, `.x == 1`); err == nil {
		t.Fatalf("expected error for invalid JSON payload")
	}
}

func TestEvaluateRuleInvalidQuery(t *testing.T) {
	e := NewPolicyEngine()
	if _, err := e.EvaluateRule(context.Background(), `{"x":1}`, `.x ==`); err == nil {
		t.Fatalf("expected error for invalid jq query")
	}
}

func TestEvaluateAttestationAllRules(t *testing.T) {
	e := NewPolicyEngine()
	payload := `{"critical": 0, "high": 0, "tests_passed": true}`

	ok, failed, err := e.EvaluateAttestation(context.Background(), payload, []string{
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
	ok, failed, _ = e.EvaluateAttestation(context.Background(), payload, []string{`.critical == 0`, `.high == 5`})
	if ok {
		t.Fatalf("expected attestation to fail")
	}
	if len(failed) != 1 || failed[0] != `.high == 5` {
		t.Fatalf("expected the failing rule to be reported, got %v", failed)
	}
}

func TestEvaluateRuleOutputErrors(t *testing.T) {
	e := NewPolicyEngine()
	for _, query := range []string{`empty`, `true, 1`, `false, null`, `true, error("fixture")`} {
		t.Run(query, func(t *testing.T) {
			if ok, err := e.EvaluateRule(context.Background(), `null`, query); ok || err == nil {
				t.Fatalf("got (%v, %v), want false and an error", ok, err)
			}
		})
	}
}

func TestEvaluationContext(t *testing.T) {
	e := NewPolicyEngine()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	deadline, stop := context.WithTimeout(context.Background(), time.Millisecond)
	defer stop()
	<-deadline.Done()

	for _, ctx := range []context.Context{cancelled, deadline} {
		t.Run(ctx.Err().Error(), func(t *testing.T) {
			if ok, err := e.EvaluateRule(ctx, `null`, `true`); ok || !errors.Is(err, ctx.Err()) {
				t.Fatalf("got (%v, %v), want false and %v", ok, err, ctx.Err())
			}

			ok, failed, err := e.EvaluateAttestation(ctx, `null`, []string{`true`, `false`})
			if ok || err != nil || len(failed) != 1 || !strings.Contains(failed[0], ctx.Err().Error()) {
				t.Fatalf("got (%v, %v, %v), want one failed rule with %v", ok, failed, err, ctx.Err())
			}

			ok, failed, err = e.EvaluateAttestation(ctx, `null`, nil)
			if !ok || len(failed) != 0 || err != nil {
				t.Fatalf("empty rule list got (%v, %v, %v), want success", ok, failed, err)
			}
		})
	}
}

type cancelOnIteratorCheck struct {
	context.Context
	cancel context.CancelFunc
}

func (ctx cancelOnIteratorCheck) Done() <-chan struct{} {
	ctx.cancel()
	return ctx.Context.Done()
}

func TestEvaluateRuleCancelsInIterator(t *testing.T) {
	active, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Cancel when the jq iterator first asks whether its context is done.
	ctx := cancelOnIteratorCheck{Context: active, cancel: cancel}
	got, err := evaluateRule(ctx, `null`, `true, true`)
	if got || !errors.Is(err, context.Canceled) {
		t.Fatalf("got (%v, %v), want false and context cancellation", got, err)
	}
}
