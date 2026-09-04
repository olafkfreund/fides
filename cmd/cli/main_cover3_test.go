package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// handleSnapshot shells out to docker/kubectl/aws directly (not through an
// injectable seam, unlike dockerSnapshotArtifacts's inspect callback). To
// exercise those branches deterministically we put a fake executable ahead of
// the real one on PATH and assert on the resulting snapshot request.

// mainStubExecutable writes an executable shell script named `name` into a
// fresh temp dir and prepends that dir to PATH for the duration of the test.
func mainStubExecutable(t *testing.T, name, script string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nset -e\n"+script+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestHandleSnapshotDockerReportsRunningContainers(t *testing.T) {
	mainStubExecutable(t, "docker", `
if [ "$1" = "ps" ]; then
  printf 'c1\tweb\n'
elif [ "$1" = "inspect" ]; then
  printf 'sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n'
fi
`)
	srv, got := recordingServer(t, `{"status":"ok"}`)
	handleSnapshot(cfg(srv), []string{"docker", "--env", "env-1"})

	if got.path != "/api/v1/snapshots" {
		t.Fatalf("path = %s", got.path)
	}
	if got.body["environment_id"] != "env-1" {
		t.Errorf("environment_id = %v", got.body["environment_id"])
	}
	arts, ok := got.body["artifacts"].([]any)
	if !ok || len(arts) != 1 {
		t.Fatalf("artifacts = %v, want 1 entry", got.body["artifacts"])
	}
	art := arts[0].(map[string]any)
	if art["sha256"] != "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" || art["service_name"] != "web" {
		t.Errorf("artifact = %+v", art)
	}
}

func TestHandleSnapshotK8sFallsBackToKubectl(t *testing.T) {
	// No KUBERNETES_SERVICE_HOST/PORT set (the default test env), so
	// fetchPodsJSON falls back to `kubectl get pods -A -o json`.
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	digest := strings.Repeat("a", 64)
	mainStubExecutable(t, "kubectl", `
cat <<EOF
{"items":[{"metadata":{"name":"pod-1","namespace":"apps"},"status":{"containerStatuses":[{"name":"app","image":"acme/app:latest","imageID":"acme/app@sha256:`+digest+`"}]}}]}
EOF
`)
	srv, got := recordingServer(t, `{"status":"ok"}`)
	handleSnapshot(cfg(srv), []string{"k8s", "--env", "env-2"})

	arts, ok := got.body["artifacts"].([]any)
	if !ok || len(arts) != 1 {
		t.Fatalf("artifacts = %v, want 1 entry", got.body["artifacts"])
	}
	art := arts[0].(map[string]any)
	if art["sha256"] != digest || art["service_name"] != "app" {
		t.Errorf("artifact = %+v", art)
	}
}

func TestHandleSnapshotK8sFiltersSystemNamespaces(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	digest := strings.Repeat("b", 64)
	mainStubExecutable(t, "kubectl", `
cat <<EOF
{"items":[
  {"metadata":{"name":"coredns-1","namespace":"kube-system"},"status":{"containerStatuses":[{"name":"coredns","image":"coredns:1","imageID":"coredns@sha256:`+digest+`"}]}},
  {"metadata":{"name":"pod-2","namespace":"apps"},"status":{"containerStatuses":[{"name":"app2","image":"acme/app2:latest","imageID":"acme/app2@sha256:`+digest+`"}]}}
]}
EOF
`)
	srv, got := recordingServer(t, `{"status":"ok"}`)
	handleSnapshot(cfg(srv), []string{"k8s", "--env", "env-2b"})

	arts, ok := got.body["artifacts"].([]any)
	if !ok || len(arts) != 1 {
		t.Fatalf("artifacts = %v, want only the non-system pod's container", got.body["artifacts"])
	}
	art := arts[0].(map[string]any)
	if art["service_name"] != "app2" {
		t.Errorf("expected the kube-system container filtered out, got %+v", art)
	}
}

func TestHandleSnapshotLambdaResolvesZipDigest(t *testing.T) {
	digest := strings.Repeat("c", 64)
	mainStubExecutable(t, "aws", `
if [ "$1" = "lambda" ] && [ "$2" = "list-functions" ]; then
  cat <<EOF
{"Functions":[{"FunctionName":"fn-zip","CodeSha256":"`+digest+`","PackageType":"Zip"}]}
EOF
fi
`)
	srv, got := recordingServer(t, `{"status":"ok"}`)
	handleSnapshot(cfg(srv), []string{"lambda", "--env", "env-3"})

	arts, ok := got.body["artifacts"].([]any)
	if !ok || len(arts) != 1 {
		t.Fatalf("artifacts = %v, want 1 entry", got.body["artifacts"])
	}
	art := arts[0].(map[string]any)
	if art["sha256"] != digest || art["service_name"] != "fn-zip" {
		t.Errorf("artifact = %+v", art)
	}
}

func TestHandleSnapshotECSResolvesContainerDigest(t *testing.T) {
	digest := strings.Repeat("d", 64)
	mainStubExecutable(t, "aws", `
if [ "$1" = "ecs" ] && [ "$2" = "list-tasks" ]; then
  echo '{"taskArns":["arn:aws:ecs:task/1"]}'
elif [ "$1" = "ecs" ] && [ "$2" = "describe-tasks" ]; then
  cat <<EOF
{"tasks":[{"taskArn":"arn:aws:ecs:task/1","containers":[{"name":"svc","image":"acct.dkr.ecr/repo:tag","imageDigest":"sha256:`+digest+`"}]}]}
EOF
fi
`)
	srv, got := recordingServer(t, `{"status":"ok"}`)
	handleSnapshot(cfg(srv), []string{"ecs", "--env", "env-4", "--cluster", "prod"})

	arts, ok := got.body["artifacts"].([]any)
	if !ok || len(arts) != 1 {
		t.Fatalf("artifacts = %v, want 1 entry", got.body["artifacts"])
	}
	art := arts[0].(map[string]any)
	if art["sha256"] != digest || art["service_name"] != "svc" {
		t.Errorf("artifact = %+v", art)
	}
}

func TestHandleSnapshotECSNoTasksReportsEmptySnapshot(t *testing.T) {
	mainStubExecutable(t, "aws", `
if [ "$1" = "ecs" ] && [ "$2" = "list-tasks" ]; then
  echo '{"taskArns":[]}'
fi
`)
	srv, got := recordingServer(t, `{"status":"ok"}`)
	handleSnapshot(cfg(srv), []string{"ecs", "--env", "env-5", "--cluster", "prod"})

	if got.body["artifacts"] != nil {
		t.Errorf("artifacts = %v, want none (no ECS tasks running)", got.body["artifacts"])
	}
}

// An unrecognized runtime type matches none of the docker/k8s/lambda/ecs
// branches, so the collected-artifacts list is empty and the handler still
// reports a (empty) snapshot rather than silently doing nothing.
func TestHandleSnapshotUnknownRuntimeStillReports(t *testing.T) {
	srv, got := recordingServer(t, `{"status":"ok"}`)
	handleSnapshot(cfg(srv), []string{"server", "--env", "env-6"})

	if got.path != "/api/v1/snapshots" || got.body["environment_id"] != "env-6" {
		t.Errorf("request = %+v %s", got.body, got.path)
	}
}
