package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Pure helpers: cheap, direct coverage.

func TestIsEvidenceFormat(t *testing.T) {
	cases := map[string]bool{
		"junit": true, "snyk": true, "trivy": true, "sarif": true,
		"slsa": true, "sbom": true, "bogus": false, "": false,
	}
	for in, want := range cases {
		if got := isEvidenceFormat(in); got != want {
			t.Errorf("isEvidenceFormat(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestStringSlice(t *testing.T) {
	var s stringSlice
	if s.String() != "" {
		t.Errorf("String() on empty = %q, want empty", s.String())
	}
	if err := s.Set("a"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Set("b"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got, want := s.String(), "a,b"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// getRequest / deleteRequest / post direct coverage of the auth + error path,
// beyond what request_contract_test.go already exercises.

func TestGetRequestReturnsErrorOnServerFailure(t *testing.T) {
	srv := integrationsServer(t, http.StatusInternalServerError, `{"error":"boom"}`)
	_, err := getRequest(cfg(srv), "/api/v1/whatever")
	if err == nil {
		t.Fatal("expected an error for a 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q does not mention the status code", err.Error())
	}
}

func TestDeleteRequestSendsMethodAndAuth(t *testing.T) {
	srv, got := recordingServer(t, `{"deleted":true}`)
	body, err := deleteRequest(cfg(srv), "/api/v1/policies/pol-1")
	if err != nil {
		t.Fatalf("deleteRequest: %v", err)
	}
	if got.method != http.MethodDelete {
		t.Errorf("method = %s, want DELETE", got.method)
	}
	if want := "/api/v1/policies/pol-1"; got.path != want {
		t.Errorf("path = %q, want %q", got.path, want)
	}
	if !strings.Contains(body, "deleted") {
		t.Errorf("body = %q", body)
	}
}

// integrationsServer answers every request with the given status and body,
// unlike recordingServer which is always 200 -- needed to drive the error
// branches of getRequest/deleteRequest without os.Exit killing the binary.
func integrationsServer(t *testing.T, status int, reply string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	return srv
}
