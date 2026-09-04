package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- pure function tests ---

func TestParseKV(t *testing.T) {
	t.Run("empty returns nil", func(t *testing.T) {
		m, err := parseKV("")
		if err != nil || m != nil {
			t.Fatalf("parseKV(\"\") = %v, %v, want nil, nil", m, err)
		}
	})

	t.Run("parses pairs", func(t *testing.T) {
		m, err := parseKV("a=1,b=2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if m["a"] != "1" || m["b"] != "2" {
			t.Errorf("m = %v, want a=1 b=2", m)
		}
	})

	t.Run("value may contain equals", func(t *testing.T) {
		m, err := parseKV("k=v=v2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if m["k"] != "v=v2" {
			t.Errorf("m[k] = %q, want v=v2", m["k"])
		}
	})

	t.Run("missing equals is an error", func(t *testing.T) {
		_, err := parseKV("noequals")
		if err == nil {
			t.Fatal("expected error for missing '='")
		}
	})

	t.Run("empty key is an error", func(t *testing.T) {
		_, err := parseKV("=val")
		if err == nil {
			t.Fatal("expected error for empty key")
		}
	})
}

func TestParseJSONObject(t *testing.T) {
	t.Run("empty returns nil", func(t *testing.T) {
		m, err := parseJSONObject("")
		if err != nil || m != nil {
			t.Fatalf("parseJSONObject(\"\") = %v, %v, want nil, nil", m, err)
		}
	})

	t.Run("parses inline JSON", func(t *testing.T) {
		m, err := parseJSONObject(`{"a":1,"b":"two"}`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if m["a"] != float64(1) || m["b"] != "two" {
			t.Errorf("m = %v", m)
		}
	})

	t.Run("invalid JSON is an error", func(t *testing.T) {
		_, err := parseJSONObject(`{not json`)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})

	t.Run("reads from .json file", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "payload.json")
		if err := os.WriteFile(p, []byte(`{"x":42}`), 0o600); err != nil {
			t.Fatal(err)
		}
		m, err := parseJSONObject(p)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if m["x"] != float64(42) {
			t.Errorf("m = %v", m)
		}
	})

	t.Run("missing .json file is an error", func(t *testing.T) {
		_, err := parseJSONObject(filepath.Join(t.TempDir(), "missing.json"))
		if err == nil {
			t.Fatal("expected error for missing file")
		}
	})
}

func TestEncryptPayload(t *testing.T) {
	t.Run("no key set is an error", func(t *testing.T) {
		t.Setenv("FIDES_ENCRYPTION_KEY", "")
		_, _, err := encryptPayload("payload")
		if err == nil {
			t.Fatal("expected error when FIDES_ENCRYPTION_KEY is unset")
		}
	})

	t.Run("encrypts with key set", func(t *testing.T) {
		t.Setenv("FIDES_ENCRYPTION_KEY", "test-encryption-key-material")
		out, encrypted, err := encryptPayload("secret-payload")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !encrypted {
			t.Error("expected encrypted = true")
		}
		if out == "" || out == "secret-payload" {
			t.Errorf("output looks unencrypted: %q", out)
		}
	})
}

func TestPrintModelUsage(t *testing.T) {
	// Just exercise it for coverage; it only writes to stdout.
	printModelUsage()
}

// --- handler dispatch / success paths ---

func modelServer(t *testing.T, reply string) (*captured, CLIConfig) {
	t.Helper()
	srv, got := recordingServer(t, reply)
	return got, cfg(srv)
}

func TestHandleModel_Dispatch(t *testing.T) {
	got, c := modelServer(t, `{"id":"trail-1"}`)

	handleModel(c, []string{"register", "--flow", "flow-1", "--version", "v1.0.0"})

	if got.method != http.MethodPost {
		t.Errorf("method = %s, want POST", got.method)
	}
	if got.path != "/api/v1/trails" {
		t.Errorf("path = %q, want /api/v1/trails", got.path)
	}
}

func TestHandleModelRegister(t *testing.T) {
	got, c := modelServer(t, `{"id":"trail-1"}`)

	handleModelRegister(c, []string{
		"--flow", "flow-1", "--version", "v1.0.0",
		"--repository", "https://example.com/repo.git",
		"--commit", "abcdef", "--branch", "main",
		"--framework", "pytorch", "--risk-category", "limited",
		"--purpose", "test purpose", "--tags", "team=ml,tier=high",
	})

	if got.method != http.MethodPost {
		t.Errorf("method = %s, want POST", got.method)
	}
	if got.path != "/api/v1/trails" {
		t.Errorf("path = %q, want /api/v1/trails", got.path)
	}
	if got.body["name"] != "v1.0.0" {
		t.Errorf("body name = %v, want v1.0.0", got.body["name"])
	}
	if got.body["flow_id"] != "flow-1" {
		t.Errorf("body flow_id = %v, want flow-1", got.body["flow_id"])
	}
}

func TestHandleModelAttest(t *testing.T) {
	t.Run("basic evidence", func(t *testing.T) {
		got, c := modelServer(t, `{"id":"att-1"}`)

		handleModelAttest(c, []string{
			"--trail", "trail-1", "--kind", "evaluation",
			"--summary", `{"accuracy":0.9}`,
			"--findings", "f1,f2",
			"--compliant",
		})

		if got.method != http.MethodPost {
			t.Errorf("method = %s, want POST", got.method)
		}
		if got.path != "/api/v1/attestations" {
			t.Errorf("path = %q, want /api/v1/attestations", got.path)
		}
		// Multipart body, not JSON -- check the raw form data for the fields
		// that matter.
		if !strings.Contains(got.raw, `name="trail_id"`) || !strings.Contains(got.raw, "trail-1") {
			t.Errorf("raw body %q does not carry trail_id=trail-1", got.raw)
		}
		if !strings.Contains(got.raw, "f1") || !strings.Contains(got.raw, "f2") {
			t.Errorf("raw body %q does not carry the findings", got.raw)
		}
	})

	t.Run("with attachments and encryption", func(t *testing.T) {
		t.Setenv("FIDES_ENCRYPTION_KEY", "test-encryption-key-material")
		dir := t.TempDir()
		f1 := filepath.Join(dir, "evidence.txt")
		if err := os.WriteFile(f1, []byte("evidence data"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, c := modelServer(t, `{"id":"att-2"}`)

		handleModelAttest(c, []string{
			"--trail", "trail-2", "--kind", "bias-audit",
			"--metadata", `{"reviewer":"alice"}`,
			"--attachments", f1,
			"--encrypt",
		})

		if got.hits != 1 {
			t.Fatalf("expected exactly one request, got %d", got.hits)
		}
		if got.method != http.MethodPost {
			t.Errorf("method = %s, want POST", got.method)
		}
	})
}

func TestHandleModelInferenceLog(t *testing.T) {
	t.Run("with explicit hashes", func(t *testing.T) {
		got, c := modelServer(t, `{"id":"inf-1"}`)

		handleModelInferenceLog(c, []string{
			"--trail", "trail-1",
			"--input-hash", strings.Repeat("a", 64),
			"--output-hash", strings.Repeat("b", 64),
			"--decision", "approved",
			"--confidence", "0.87",
			"--actor", "reviewer-1",
			"--metadata", `{"note":"ok"}`,
		})

		if got.method != http.MethodPost {
			t.Errorf("method = %s, want POST", got.method)
		}
	})

	t.Run("hashes files", func(t *testing.T) {
		dir := t.TempDir()
		in := filepath.Join(dir, "input.bin")
		out := filepath.Join(dir, "output.bin")
		if err := os.WriteFile(in, []byte("input-data"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, []byte("output-data"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, c := modelServer(t, `{"id":"inf-2"}`)

		handleModelInferenceLog(c, []string{
			"--trail", "trail-1",
			"--input-file", in,
			"--output-file", out,
			"--decision", "denied",
		})

		if got.hits != 1 {
			t.Fatalf("expected exactly one request, got %d", got.hits)
		}
	})
}

func TestHandleModelVersions(t *testing.T) {
	got, c := modelServer(t, `[{"id":"trail-1"}]`)

	handleModelVersions(c, []string{"--flow", "flow-1"})

	if got.method != http.MethodGet {
		t.Errorf("method = %s, want GET", got.method)
	}
	if got.path != "/api/v1/flows/flow-1/trails" {
		t.Errorf("path = %q, want /api/v1/flows/flow-1/trails", got.path)
	}
}

func TestHandleModelTimeline(t *testing.T) {
	got, c := modelServer(t, `[{"id":"att-1"}]`)

	handleModelTimeline(c, []string{"--trail", "trail-1"})

	if got.method != http.MethodGet {
		t.Errorf("method = %s, want GET", got.method)
	}
	if got.path != "/api/v1/search/attestations" {
		t.Errorf("path = %q, want /api/v1/search/attestations", got.path)
	}
	if !strings.Contains(got.query, "trail=trail-1") {
		t.Errorf("query = %q, want it to carry trail=trail-1", got.query)
	}
}
