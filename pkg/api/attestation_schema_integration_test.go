package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"fides/pkg/auth"
	"fides/pkg/models"
)

func applyAttestationValidationMigration(t *testing.T, pool *sql.DB) {
	t.Helper()
	migration, err := os.ReadFile("../../pkg/db/migrations/0029_attestation_validation_errors.sql")
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, pool, string(migration))
}

func TestAttestationSchemaLifecycleIntegration(t *testing.T) {
	f := newRouteAuthFixture(t)
	admin, viewer := f.sessions[auth.RoleAdmin], f.sessions[auth.RoleViewer]
	foreign := routeSession(t, f.server, f.other["org"], auth.RoleViewer, time.Hour)
	const collection = "/api/v1/attestation-types"
	create := func(body string, status int) models.AttestationType {
		t.Helper()
		rec := serveMutation(t, f.handler, "POST "+collection, body, admin, status, "")
		var typ models.AttestationType
		if status == http.StatusCreated {
			if err := json.Unmarshal(rec.Body.Bytes(), &typ); err != nil {
				t.Fatal(err)
			}
		}
		return typ
	}
	create(`{"name":"bad","schema":"{\"type\":17}"}`, http.StatusBadRequest)
	untyped := create(`{"name":"untyped"}`, http.StatusCreated)
	var absent bool
	if err := f.pool.QueryRow(`SELECT schema IS NULL FROM attestation_types WHERE id = $1`, untyped.ID).Scan(&absent); err != nil || !absent {
		t.Fatalf("schema-less create stored SQL NULL: %v, %v", absent, err)
	}
	typ := create(`{"name":"review","schema":"{\"properties\":{\"approved\":{\"type\":\"boolean\"}}}","jq_rules":[".approved == true"]}`, http.StatusCreated)
	mustExec(t, f.pool, `INSERT INTO attestation_types (org_id,name,schema) VALUES ($1,'review','false')`, f.other["org"])
	create(`{"name":"review"}`, http.StatusConflict)
	path := collection + "/" + typ.ID.String()
	serveMutation(t, f.handler, "GET "+path, "", foreign, http.StatusNotFound, "")
	rec := serveMutation(t, f.handler, "GET "+collection+"?limit=1", "", viewer, http.StatusOK, "")
	link := rec.Header().Get("Link")
	next, _, found := strings.Cut(strings.TrimPrefix(link, "<"), ">")
	if !found {
		t.Fatalf("expected a next-page Link, got %q", link)
	}
	serveMutation(t, f.handler, "GET "+next, "", viewer, http.StatusOK, "")
	serveMutation(t, f.handler, "GET "+next, "", foreign, http.StatusBadRequest, "")
	for _, p := range []string{"GET " + path, "PATCH " + path} {
		rec := serveMutation(t, f.handler, p, `{"description":"updated"}`, admin, http.StatusOK, "")
		var current models.AttestationType
		if err := json.Unmarshal(rec.Body.Bytes(), &current); err != nil || current.Schema == "" {
			t.Fatalf("%s lost schema: %s, %v", p, rec.Body.String(), err)
		}
	}
	serveMutation(t, f.handler, "PATCH "+path, `{"schema":"null"}`, admin, http.StatusBadRequest, "")

	report := func(payload, wantCode string, compliant bool) {
		t.Helper()
		body, err := json.Marshal(reportAttestationReq{TrailID: f.own["trail"], Name: "review-check", TypeName: "review", Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		rec := serveMutation(t, f.handler, "POST /api/v1/attestations", string(body), admin, http.StatusCreated, "")
		var received models.Attestation
		if err := json.Unmarshal(rec.Body.Bytes(), &received); err != nil || received.Payload != payload || received.IsCompliant != compliant {
			t.Fatalf("ingest verdict or payload differs: %s, %v", rec.Body.String(), err)
		}
		rec = serveMutation(t, f.handler, "GET /api/v1/attestations/"+received.ID.String(), "", viewer, http.StatusOK, "")
		var detail struct {
			Payload          json.RawMessage                     `json:"payload"`
			ValidationErrors []models.AttestationValidationError `json:"validation_errors"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
			t.Fatalf("stored payload could not be decoded: %s, %v", rec.Body.String(), err)
		}
		var want bytes.Buffer
		if err := json.Compact(&want, []byte(payload)); err != nil || !bytes.Equal(detail.Payload, want.Bytes()) {
			t.Fatalf("stored payload differs: got %s, want %s", detail.Payload, want.Bytes())
		}
		for _, reasons := range [][]models.AttestationValidationError{received.ValidationErrors, detail.ValidationErrors} {
			if reasons == nil || wantCode == "" && len(reasons) != 0 || wantCode != "" && (len(reasons) != 1 || reasons[0].Code != wantCode) {
				t.Fatalf("unexpected reasons: %+v, expected code %q", reasons, wantCode)
			}
		}
	}

	report(`{"approved": "yes"}`, "schema_validation_failed", false)
	report(`{"approved": false}`, "", false)
	report(`{"approved": true}`, "", true)
	mustExec(t, f.pool, `UPDATE attestation_types SET schema = '{"type":123}' WHERE id = $1`, typ.ID)
	report(`{"approved": true}`, "schema_configuration_invalid", false)
	for _, clearing := range []string{`{"schema":null}`, `{"schema":""}`} {
		serveMutation(t, f.handler, "PATCH "+path, `{"schema":"false"}`, admin, http.StatusOK, "")
		report(`{"approved": true}`, "schema_validation_failed", false)
		serveMutation(t, f.handler, "PATCH "+path, clearing, admin, http.StatusOK, "")
		report(`{"approved": true}`, "", true)
	}
	serveMutation(t, f.handler, "DELETE "+path, "", admin, http.StatusNoContent, "")
	serveMutation(t, f.handler, "GET "+path, "", viewer, http.StatusNotFound, "")
}
