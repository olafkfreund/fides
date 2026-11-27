package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type azureSnapshotTransport func(*http.Request) (*http.Response, error)

func (f azureSnapshotTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func azureFixtureCommand(t *testing.T, kind, runtime, setting string) snapshotCommand {
	t.Helper()
	return func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name != "az" || ctx.Err() != nil {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		switch strings.Join(args[:3], " ") {
		case "resource show --resource-type":
			return json.Marshal(azureSnapshotApp{
				Name: "sample-app", Kind: kind, State: "Running", Availability: "Normal",
				Host: "sample-app-hash.uk-west.azurewebsites.net", Modified: "2024-04-01T00:00:00Z",
			})
		case "webapp config show", "functionapp config show":
			return json.Marshal(runtime)
		case "webapp config appsettings", "functionapp config appsettings":
			return json.Marshal(setting)
		case "account get-access-token --resource":
			return []byte("fixture-token\n"), nil
		}
		return nil, fmt.Errorf("unexpected Azure command: %s", strings.Join(args, " "))
	}
}

func TestAzureContainerSnapshot(t *testing.T) {
	sha := strings.Repeat("a", 64)
	for _, tt := range []struct {
		runtime string
		want    bool
	}{
		{"DOCKER|sample.azurecr.io/app@" + "sha256:" + sha, true},
		{"DOCKER|sample.azurecr.io/app:latest", false},
		{"sitecontainers", false},
	} {
		t.Run(tt.runtime, func(t *testing.T) {
			run := azureFixtureCommand(t, "app,linux,container", tt.runtime, "")
			got, err := collectAzureSnapshot(t.Context(), nil, "group", "sample-app", run)
			if tt.want {
				if err != nil || len(got) != 1 || got[0]["sha256"] != sha || got[0]["service_name"] != "sample-app" {
					t.Fatalf("snapshot = %v, %v", got, err)
				}
			} else if err == nil || len(got) > 0 {
				t.Fatalf("expected an error without evidence, got %v, %v", got, err)
			}
		})
	}
}

func TestAzurePackageSnapshot(t *testing.T) {
	packageBytes := []byte("PK\x03\x04deployment bytes")
	const localHost = "sample-app-hash.scm.uk-west.azurewebsites.net"
	const remoteHost = "sample.blob.core.windows.net"
	want := fmt.Sprintf("%x", sha256.Sum256(packageBytes))
	for _, tt := range []struct {
		name, setting string
		changed       bool
		wantRequest   int
	}{
		{"local package", "1", false, 4},
		{"changed package", "1", true, 3},
		{"versioned blob", "https://" + remoteHost + "/releases/app.zip?versionid=2025-05-01T00:00:00Z", false, 1},
		{"mutable blob", "https://" + remoteHost + "/releases/app.zip", true, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var requests int
			client := &http.Client{Transport: azureSnapshotTransport(func(req *http.Request) (*http.Response, error) {
				requests++
				if req.Method != http.MethodGet || req.URL.Scheme != "https" {
					t.Fatalf("unexpected method or scheme: %s %s", req.Method, req.URL.Scheme)
				}
				var data []byte
				resp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}
				switch req.URL.Hostname() {
				case localHost:
					if req.Header.Get("Authorization") != "Bearer fixture-token" {
						t.Fatal("missing Entra authorization for the app's Kudu host")
					}
					switch req.URL.Path {
					case azurePackagePath + "packagename.txt":
						data = []byte("active.zip\n")
					case azurePackagePath + "active.zip":
						resp.Header.Set("ETag", `"fixture-etag"`)
						data = packageBytes
						if req.Header.Get("If-None-Match") == `"fixture-etag"` && !tt.changed {
							resp.StatusCode, data = http.StatusNotModified, nil
						}
					default:
						t.Fatalf("unexpected Kudu path: %s", req.URL.Path)
					}
				case remoteHost:
					if req.Header.Get("Authorization") != "" || req.URL.Query().Get("versionid") == "" {
						t.Fatal("Azure Blob request must use the configured version without SCM credentials")
					}
					data = packageBytes
				default:
					t.Fatalf("unexpected package host: %s", req.URL.Hostname())
				}
				resp.Body = io.NopCloser(bytes.NewReader(data))
				resp.ContentLength = int64(len(data))
				return resp, nil
			})}
			run := azureFixtureCommand(t, "functionapp,linux", "DOTNET-ISOLATED|8.0", tt.setting)
			got, err := collectAzureSnapshot(t.Context(), client, "group", "sample-app", run)
			if tt.changed {
				if err == nil || len(got) != 0 {
					t.Fatalf("expected safe rejection, got %v, %v", got, err)
				}
			} else if err != nil || len(got) != 1 || got[0]["sha256"] != want {
				t.Fatalf("snapshot = %v, %v, want %s", got, err, want)
			}
			if requests != tt.wantRequest {
				t.Errorf("package requests = %d, want %d", requests, tt.wantRequest)
			}
		})
	}
}
