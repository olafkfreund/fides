package api

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fides/pkg/policy"
)

func TestAttestationSchemaDraft2020(t *testing.T) {
	definition := `{
		"$schema":"https://json-schema.org/draft/2020-12/schema",
		"$id":"https://synthetic.invalid/root",
		"$defs":{"item":{"$id":"item","$anchor":"count","type":"integer"}},
		"prefixItems":[{"$ref":"item#count"}],
		"unevaluatedItems":false
	}`
	for _, tc := range []struct {
		payload string
		path    string
	}{
		{`[1]`, ""},
		{`["one"]`, "/0"},
	} {
		got, err := runAttestationSchema(t.Context(), definition, &tc.payload)
		if err != nil || got.SchemaError != "" {
			t.Fatalf("schema compilation: %+v, %v", got, err)
		}
		if tc.path == "" && len(got.Reasons) != 0 || tc.path != "" && (len(got.Reasons) != 1 || got.Reasons[0].Path != tc.path) {
			t.Fatalf("validate %s: %+v", tc.payload, got.Reasons)
		}
	}
}

func TestAttestationSchemaDynamicReference(t *testing.T) {
	definition := `{
		"$dynamicAnchor":"node",
		"type":"object",
		"properties":{"children":{"type":"array","items":{"$dynamicRef":"#node"}}}
	}`
	payload := `{"children":[{"children":[{}]}]}`
	got, err := runAttestationSchema(t.Context(), definition, &payload)
	if err != nil || got.SchemaError != "" || len(got.Reasons) != 0 {
		t.Fatalf("expected recursive Draft 2020-12 reference to validate: %+v, %v", got, err)
	}
}

func TestAttestationSchemaRejectsInvalidDefinitions(t *testing.T) {
	localFile := filepath.Join(t.TempDir(), "synthetic-schema.json")
	if err := os.WriteFile(localFile, []byte(`{"$anchor":"item"}`), 0600); err != nil {
		t.Fatal(err)
	}
	fileURL := url.URL{Scheme: "file", Path: localFile, Fragment: "item"}
	for _, schema := range []string{
		`{"type":"invalid"}`,
		`{"$ref":"#/$defs/missing"}`,
		`{"$ref":"https://synthetic.invalid/elsewhere"}`,
		fmt.Sprintf(`{"$dynamicRef":%q}`, fileURL.String()),
		`{"$schema":"https://synthetic.invalid/dialect"}`,
		`{} true`,
		`{"enum":[1e40000, 1e40000]}`,
		`null`,
		strings.Repeat(" ", maxAttestationSchemaBytes+1),
		strings.Repeat(`{"not":`, maxSchemaJSONDepth+1) + "true" + strings.Repeat("}", maxSchemaJSONDepth+1),
	} {
		got, err := runAttestationSchema(t.Context(), schema, nil)
		if err != nil || got.SchemaError == "" {
			t.Fatalf("expected a configuration error: %+v, %v", got, err)
		}
	}
}

func TestAttestationSchemaWorkLimit(t *testing.T) {
	payload := `"` + strings.Repeat("x", maxSchemaPayloadBytes) + `"`
	result, err := runAttestationSchema(t.Context(), "{}", &payload)
	if err != nil || result.SchemaError != "" || len(result.Reasons) != 1 || result.Reasons[0].Code != "schema_work_limit" {
		t.Fatalf("expected a validation work limit: %+v, %v", result, err)
	}
}

func TestAttestationSchemaReasonsBounded(t *testing.T) {
	schema := `{"additionalProperties":{"type":"integer"}}`
	payload := `{"~a/b":"x","a":"x","b":"x","c":"x","d":"x","e":"x","f":"x","g":"x","h":"x","i":"x","j":"x"}`
	want := []string{"/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h"}
	got, err := runAttestationSchema(t.Context(), schema, &payload)
	if err != nil || got.SchemaError != "" || len(got.Reasons) != maxSchemaErrors {
		t.Fatalf("expected %d reasons: %+v, %v", maxSchemaErrors, got, err)
	}
	for i, reason := range got.Reasons {
		if reason.Code != "schema_validation_failed" || reason.Path != want[i] || reason.Message == "" {
			t.Fatalf("reason %d: %+v", i, reason)
		}
	}
	payload = `{"~a/b":"x"}`
	got, err = runAttestationSchema(t.Context(), schema, &payload)
	if err != nil || len(got.Reasons) != 1 || got.Reasons[0].Path != "/~0a~1b" {
		t.Fatalf("expected escaped JSON Pointer: %+v, %v", got, err)
	}
}

func TestAttestationSchemaAndJQ(t *testing.T) {
	server := &Server{PolicyEngine: policy.NewPolicyEngine()}
	rules := []string{`.approved == true`}
	schema := `{"properties":{"approved":{"type":"boolean"}}}`
	for _, tc := range []struct {
		schema, payload, reason string
		compliant               bool
	}{
		{"", `{}`, "", false},
		{schema, `{"approved": false}`, "", false},
		{schema, `{"approved": true}`, "", true},
		{schema, `{"approved": "true"}`, "schema_validation_failed", false},
		{`"legacy"`, `{"approved": true}`, "schema_configuration_invalid", false},
	} {
		got, err := server.checkAttestationType(t.Context(), sql.NullString{String: tc.schema, Valid: tc.schema != ""}, tc.payload, rules)
		if err != nil || got.compliant != tc.compliant || tc.reason == "" && len(got.reasons) != 0 ||
			tc.reason != "" && (len(got.reasons) != 1 || got.reasons[0].Code != tc.reason) {
			t.Fatalf("schema %s, payload %s: %+v, %v", tc.schema, tc.payload, got, err)
		}
	}
}
