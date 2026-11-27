package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fides/pkg/auth"
)

func TestEnvironmentLifecycleIntegration(t *testing.T) {
	f := newRouteAuthFixture(t)
	admin, viewer := f.sessions[auth.RoleAdmin], f.sessions[auth.RoleViewer]
	request := func(pattern, body string, credential routeCredential, status int) *httptest.ResponseRecorder {
		t.Helper()
		return serveMutation(t, f.handler, pattern, body, credential, status, "")
	}
	record := func(rec *httptest.ResponseRecorder) environmentRecord {
		t.Helper()
		var env environmentRecord
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		return env
	}

	const environments = "/api/v1/environments"
	const create = "POST " + environments + "?create_only=true"
	s3 := record(request(create, `{"name":"bucket","type":"s3","description":"initial"}`, admin, 201))
	path := environments + "/" + s3.ID.String()
	request(create, `{"name":"bucket","type":"cloud-run"}`, admin, 409)
	request("PATCH "+path, `{"name":"seed environment"}`, admin, 409)
	request("PATCH "+path, `{"type":"   "}`, admin, 400)
	request("GET "+environments+"/invalid", "", viewer, 400)
	request("GET "+environments+"/"+f.other["env"], "", viewer, 404)
	if got := record(request("GET "+path, "", viewer, 200)); got != s3 {
		t.Fatalf("conflicting requests changed the environment: %+v, want %+v", got, s3)
	}

	request("POST /api/v1/snapshots", fmt.Sprintf(`{"environment_id":%q,"artifacts":[]}`, s3.ID), admin, 201)
	request("POST "+path+"/archive", "", admin, 200)
	request(create, `{"name":"bucket","type":"cloud-run"}`, admin, 409)
	updated := record(request("PATCH "+path, `{"name":"renamed-bucket","description":""}`, admin, 200))
	if updated.ID != s3.ID || !updated.Archived || updated.Name != "renamed-bucket" || updated.Type != "s3" || updated.Description != "" {
		t.Fatalf("unexpected patch result: %+v", updated)
	}
	if got := record(request("GET "+path, "", viewer, 200)); got != updated {
		t.Fatalf("archived environment = %+v, want %+v", got, updated)
	}

	legacy := record(request("POST "+environments, `{"name":"renamed-bucket","type":"custom-runtime"}`, admin, 201))
	if legacy.ID != s3.ID || legacy.Type != "custom-runtime" || record(request("GET "+path, "", viewer, 200)).Archived {
		t.Fatalf("legacy POST did not upsert and reactivate the same record: %+v", legacy)
	}
}

func TestTerraformEnvironmentIntegration(t *testing.T) {
	f := newRouteAuthFixture(t)
	terraform, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform is required for the provider lifecycle check")
	}
	server := httptest.NewServer(f.handler)
	t.Cleanup(server.Close)
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", filepath.Join(dir, "terraform-provider-fides"), ".")
	build.Dir = "../../terraform-provider-fides"
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build local Terraform provider: %v\n%s", err, out)
	}

	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("terraform.rc", fmt.Sprintf(`
provider_installation {
  dev_overrides {
    "olafkfreund/fides" = %q
  }
}
`, dir))
	t.Setenv("TF_CLI_CONFIG_FILE", filepath.Join(dir, "terraform.rc"))
	t.Setenv("TF_IN_AUTOMATION", "1")
	t.Setenv("CHECKPOINT_DISABLE", "1")
	config := func(name, kind string) {
		write("main.tf", fmt.Sprintf(`
terraform {
  required_providers {
    fides = { source = "olafkfreund/fides" }
  }
}
provider "fides" {
  endpoint  = %q
  api_token = %q
}
resource "fides_environment" "test" {
  name = %q
  type = %q
}
`, server.URL, fixtureBearer, name, kind))
	}
	run := func(wantError string, args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, terraform, args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if wantError != "" {
			if err == nil || !strings.Contains(string(out), wantError) {
				t.Fatalf("terraform %v: wanted error %q, got %v\n%s", args, wantError, err, out)
			}
		} else if err != nil {
			t.Fatalf("terraform %v: %v\n%s", args, err, out)
		}
	}
	config("tf-original", "cloud-run")
	run("", "apply", "-auto-approve", "-input=false", "-no-color")
	var id string
	if err := f.pool.QueryRow(`SELECT id FROM environments WHERE org_id = $1 AND name = 'tf-original' AND type = 'cloud-run'`, f.own["org"]).Scan(&id); err != nil {
		t.Fatal(err)
	}
	serveMutation(t, f.handler, "POST /api/v1/snapshots", fmt.Sprintf(`{"environment_id":%q,"artifacts":[]}`, id), f.sessions[auth.RoleAdmin], 201, "")

	config("tf-renamed", "azure-apps")
	run("", "apply", "-auto-approve", "-input=false", "-no-color")
	run("", "state", "rm", "fides_environment.test")
	run("environment name already exists", "apply", "-auto-approve", "-input=false", "-no-color")
	run("", "import", "-input=false", "-no-color", "fides_environment.test", id)
	run("", "plan", "-input=false", "-no-color", "-detailed-exitcode")
	run("", "destroy", "-auto-approve", "-input=false", "-no-color")

	var name, kind string
	var archived bool
	var snapshots, duplicates int
	err = f.pool.QueryRow(`SELECT name, type, archived,
		(SELECT count(*) FROM environment_snapshots WHERE environment_id = $1),
		(SELECT count(*) FROM environments WHERE org_id = $2 AND name IN ('tf-original', 'tf-renamed'))
		FROM environments WHERE id = $1 AND org_id = $2`, id, f.own["org"]).Scan(&name, &kind, &archived, &snapshots, &duplicates)
	if err != nil {
		t.Fatal(err)
	}
	if name != "tf-renamed" || kind != "azure-apps" || !archived || snapshots != 1 || duplicates != 1 {
		t.Fatalf("after destroy: name=%q type=%q archived=%t snapshots=%d matching environments=%d",
			name, kind, archived, snapshots, duplicates)
	}
}
