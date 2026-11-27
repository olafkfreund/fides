package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

const (
	testCloudDigestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testCloudDigestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestCloudRunSnapshot(t *testing.T) {
	for _, scenario := range []string{"complete", "missing sidecar", "mutable digest", "traffic changed"} {
		t.Run(scenario, func(t *testing.T) {
			serviceReads := 0
			run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if _, ok := ctx.Deadline(); !ok || name != "gcloud" || !slices.Contains(args, "--region=europe-west1") ||
					!slices.Contains(args, "--project=example-project") {
					t.Fatalf("unexpected command %s %v", name, args)
				}
				switch args[3] {
				case "api":
					serviceReads++
					if scenario == "traffic changed" && serviceReads == 2 {
						return []byte(`{"status":{"traffic":[{"revisionName":"api-final","percent":100}]}}`), nil
					}
					return []byte(`{"spec":{"traffic":[{"revisionName":"desired-only","percent":100}]},"status":{"traffic":[
						{"revisionName":"api-green","percent":20},{"revisionName":"api-blue","percent":80},
						{"revisionName":"api-green","tag":"preview"},{"revisionName":"api-tagged","tag":"test"},
						{"revisionName":"inactive","percent":0}]}}`), nil
				case "api-blue", "api-tagged":
					return fmt.Appendf(nil, `{"metadata":{"name":%q},"spec":{"containers":[{"image":"app:latest"}]},
						"status":{"imageDigest":"example/app@sha256:%s"}}`, args[3], testCloudDigestA), nil
				case "api-green":
					sidecar := fmt.Sprintf(`,{"name":"worker","imageDigest":"example/worker@sha256:%s"}`, testCloudDigestB)
					switch scenario {
					case "missing sidecar":
						sidecar = ""
					case "mutable digest":
						sidecar = `,{"name":"worker","imageDigest":"example/worker:latest"}`
					}
					return fmt.Appendf(nil, `{"metadata":{"name":"api-green"},"spec":{"containers":[{"name":"server"},{"name":"worker","image":"worker:latest"}]},
						"status":{"containerStatuses":[{"name":"server","imageDigest":"sha256:%s"}%s]}}`, testCloudDigestB, sidecar), nil
				default:
					t.Fatalf("unexpected revision describe %v", args)
					return nil, nil
				}
			}
			if scenario != "complete" {
				ctx, cancel := context.WithTimeout(t.Context(), snapshotTestTimeout)
				defer cancel()
				artifacts, err := cloudRunSnapshotArtifacts(ctx, "api", "europe-west1", "example-project", run)
				if err == nil || artifacts != nil {
					t.Fatalf("partial revision returned %v, %v", artifacts, err)
				}
				return
			}
			srv, got := recordingServer(t, "")
			handleSnapshotWithCommand(cfg(srv), []string{"cloud-run", "--env", "env-id", "--service", "api",
				"--region", "europe-west1", "--project", "example-project"}, run)
			if got.method != "POST" || got.path != "/api/v1/snapshots" || got.body["environment_id"] != "env-id" {
				t.Fatalf("unexpected snapshot request %#v", got)
			}
			if serviceReads != 2 {
				t.Fatalf("service reads = %d, want 2", serviceReads)
			}
			artifacts := got.body["artifacts"].([]any)
			if len(artifacts) != 4 {
				t.Fatalf("unexpected artifacts %v", artifacts)
			}
			wantNames := []string{"api/api-blue", "api/api-green/server", "api/api-green/worker", "api/api-tagged"}
			wantDigests := []string{testCloudDigestA, testCloudDigestB, testCloudDigestB, testCloudDigestA}
			for i, raw := range artifacts {
				artifact := raw.(map[string]any)
				if artifact["service_name"] != wantNames[i] || artifact["sha256"] != wantDigests[i] {
					t.Errorf("unexpected artifact %v", artifact)
				}
			}
		})
	}
}

func TestCloudSnapshotCollectionFailureDoesNotPost(t *testing.T) {
	if os.Getenv("FIDES_SNAPSHOT_SUBPROCESS") == "1" {
		handleSnapshotWithCommand(CLIConfig{ServerURL: os.Getenv("FIDES_SERVER_URL")}, []string{"s3", "--env", "env-id", "--bucket", "example"},
			func(context.Context, string, ...string) ([]byte, error) {
				return []byte("provider-stdout-secret"), errors.New("provider-stderr-secret")
			})
		return
	}
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("failed collection issued a snapshot")
	}))
	defer srv.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCloudSnapshotCollectionFailureDoesNotPost$")
	cmd.Env = append(os.Environ(), "FIDES_SNAPSHOT_SUBPROCESS=1", "FIDES_SERVER_URL="+srv.URL)
	out, err := cmd.CombinedOutput()
	var status *exec.ExitError
	if !errors.As(err, &status) || status.ExitCode() != 1 || !strings.Contains(string(out), "S3 list-objects-v2 failed") ||
		strings.Contains(string(out), "secret") {
		t.Fatalf("unexpected exit %v or output %q", err, out)
	}
}
