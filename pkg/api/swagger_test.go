package api

import (
	"encoding/json"
	"testing"
)

// TestSwaggerJSONValid guards the hand-maintained OpenAPI spec: it must stay
// valid JSON and document the key endpoints, so a malformed edit fails here
// instead of silently breaking the /swagger UI.
func TestSwaggerJSONValid(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(SwaggerJSON), &doc); err != nil {
		t.Fatalf("SwaggerJSON is not valid JSON: %v", err)
	}
	paths, ok := doc["paths"].(map[string]any)
	if !ok || len(paths) == 0 {
		t.Fatal("SwaggerJSON has no paths object")
	}
	for _, p := range []string{
		"/impact", "/vex", "/vulnerabilities/backfill", "/metrics/dora",
		"/trails/{id}/anchor", "/trails/{id}/verify-chain", "/reports/cra-incidents",
	} {
		if _, ok := paths[p]; !ok {
			t.Errorf("SwaggerJSON missing documented path %q", p)
		}
	}
}
