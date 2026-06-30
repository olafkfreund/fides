package policy

import (
	"encoding/json"
	"fmt"

	"github.com/itchyny/gojq"
)

type PolicyEngine struct{}

func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{}
}

// EvaluateRule parses the payload JSON and evaluates it against the JQ query.
// It returns true if the JQ expression evaluates to true, false otherwise.
func (e *PolicyEngine) EvaluateRule(payloadJSON string, jqQuery string) (bool, error) {
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
	iter := query.Run(input)
	for {
		val, ok := iter.Next()
		if !ok {
			break
		}
		if err, isErr := val.(error); isErr {
			return false, fmt.Errorf("error running JQ query: %w", err)
		}

		// Check if the output is a boolean and true
		if boolVal, isBool := val.(bool); isBool {
			return boolVal, nil
		}
	}

	// Default fallback if no boolean was returned
	return false, fmt.Errorf("JQ query did not evaluate to a boolean")
}

// EvaluateAttestation runs all rules of an attestation type against the attestation payload.
// Returns true if all rules evaluate to true.
func (e *PolicyEngine) EvaluateAttestation(payloadJSON string, rules []string) (bool, []string, error) {
	var failedRules []string
	for _, rule := range rules {
		ok, err := e.EvaluateRule(payloadJSON, rule)
		if err != nil {
			failedRules = append(failedRules, fmt.Sprintf("rule '%s' error: %v", rule, err))
			continue
		}
		if !ok {
			failedRules = append(failedRules, rule)
		}
	}
	return len(failedRules) == 0, failedRules, nil
}
