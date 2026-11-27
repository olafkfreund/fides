package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/itchyny/gojq"
)

const evaluationBudget = time.Second

type PolicyEngine struct{}

func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{}
}

// EvaluateRule parses the payload JSON and evaluates it against the JQ query.
// It passes only if the query emits at least one value and every value is true.
func (e *PolicyEngine) EvaluateRule(ctx context.Context, payloadJSON string, jqQuery string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, evaluationBudget)
	defer cancel()
	return evaluateRule(ctx, payloadJSON, jqQuery)
}

func evaluateRule(ctx context.Context, payloadJSON string, jqQuery string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	// Parse input JSON
	var input interface{}
	if err := json.Unmarshal([]byte(payloadJSON), &input); err != nil {
		return false, fmt.Errorf("failed to parse payload JSON: %w", err)
	}

	// Parse JQ query
	query, err := gojq.Parse(jqQuery)
	if err != nil {
		return false, fmt.Errorf("failed to parse JQ query '%s': %w", jqQuery, err)
	}

	// Run JQ query
	iter := query.RunWithContext(ctx, input)
	seen, passed := false, true
	for {
		val, ok := iter.Next()
		if !ok {
			break
		}
		if err, isErr := val.(error); isErr {
			return false, fmt.Errorf("error running JQ query: %w", err)
		}

		boolVal, isBool := val.(bool)
		if !isBool {
			return false, fmt.Errorf("JQ query output is not a boolean")
		}
		seen = true
		passed = passed && boolVal
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !seen {
		return false, fmt.Errorf("JQ query did not return any values")
	}
	return passed, nil
}

// EvaluateAttestation runs all rules of an attestation type against the attestation payload.
// Returns true if all rules evaluate to true.
func (e *PolicyEngine) EvaluateAttestation(ctx context.Context, payloadJSON string, rules []string) (bool, []string, error) {
	ctx, cancel := context.WithTimeout(ctx, evaluationBudget)
	defer cancel()

	var failedRules []string
	for _, rule := range rules {
		ok, err := evaluateRule(ctx, payloadJSON, rule)
		if err != nil {
			failedRules = append(failedRules, fmt.Sprintf("rule '%s' error: %v", rule, err))
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if !ok {
			failedRules = append(failedRules, rule)
		}
	}
	return len(failedRules) == 0, failedRules, nil
}
