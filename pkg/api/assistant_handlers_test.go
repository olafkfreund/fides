package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"fides/pkg/ai"
)

type policyGenerationFailure struct {
	ai.LLMClient
}

func (policyGenerationFailure) GeneratePolicy(context.Context, string, string) (string, error) {
	return "", errors.New("local model failure")
}

func TestAIGeneratePolicyFallbackJSON(t *testing.T) {
	input := generatePolicyReq{Framework: "SOC \"2\"\nType II", Description: "Check \"builds\"\nand deployments"}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	type control struct {
		Name          string   `json:"name"`
		Attestation   string   `json:"attestation_type"`
		JQExpressions []string `json:"jq_expressions"`
	}
	vulnerability := control{"vulnerability-check", "snyk-scan", []string{".vulnerabilities.critical == 0"}}
	unitTest := control{"unit-test-verification", "junit", []string{".failures == 0", ".errors == 0"}}
	for _, tc := range []struct {
		name     string
		llm      ai.LLMClient
		prefix   string
		controls []control
	}{
		{"no model", nil, "LLM Generated Policy", []control{vulnerability, unitTest}},
		{"model error", policyGenerationFailure{}, "LLM Fallback Policy", []control{vulnerability}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := &Server{LLM: tc.llm}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/ai/generate-policy", bytes.NewReader(body))
			rec := httptest.NewRecorder()
			srv.handleAIGeneratePolicy(rec, req)
			if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("HTTP %d (%s): %s", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
			}
			var out struct {
				Name        string `json:"name"`
				Description string `json:"description"`
				Rules       struct {
					Controls []control `json:"controls"`
				} `json:"rules"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatalf("invalid policy JSON: %v: %s", err, rec.Body)
			}
			if out.Name != input.Framework+"-compliance-policy" ||
				out.Description != tc.prefix+" for "+input.Framework+" compliance: "+input.Description {
				t.Fatalf("fallback name and description: %q, %q", out.Name, out.Description)
			}
			if !reflect.DeepEqual(out.Rules.Controls, tc.controls) {
				t.Fatalf("controls = %v, want %v", out.Rules.Controls, tc.controls)
			}
		})
	}
}
