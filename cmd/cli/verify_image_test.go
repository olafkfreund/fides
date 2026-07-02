package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fides/pkg/cosignverify"
)

// mockVerifier is a cosignverify.Verifier stub that returns a canned verdict
// or error, letting tests exercise runVerifyImage without any network access
// or a real cosign/Sigstore bundle.
type mockVerifier struct {
	verdict *cosignverify.Verdict
	err     error
	gotOpts cosignverify.Options
}

func (m *mockVerifier) Verify(_ context.Context, opts cosignverify.Options) (*cosignverify.Verdict, error) {
	m.gotOpts = opts
	if m.err != nil {
		return nil, m.err
	}
	return m.verdict, nil
}

func int64ptr(v int64) *int64 { return &v }

func TestRunVerifyImage_MissingRequiredFlags(t *testing.T) {
	v := &mockVerifier{}
	var out bytes.Buffer
	code := runVerifyImage(CLIConfig{}, v, &out, []string{})
	if code != exitError {
		t.Fatalf("expected exitError (%d), got %d", exitError, code)
	}
	if !strings.Contains(out.String(), "Usage:") {
		t.Fatalf("expected usage message, got: %s", out.String())
	}
}

func TestRunVerifyImage_VerifierOperationalError(t *testing.T) {
	v := &mockVerifier{err: cosignverify.ErrBundleRequired}
	var out bytes.Buffer
	code := runVerifyImage(CLIConfig{}, v, &out, []string{"--sha256", "deadbeef", "--signer", "user@example.com"})
	if code != exitError {
		t.Fatalf("expected exitError (%d) on verifier error, got %d", exitError, code)
	}
}

func TestRunVerifyImage_VerificationFailedExitsGateCode(t *testing.T) {
	v := &mockVerifier{verdict: &cosignverify.Verdict{
		Verified: false,
		Digest:   "deadbeef",
		Method:   "keyless",
		Reason:   "certificate identity mismatch",
	}}
	var out bytes.Buffer
	code := runVerifyImage(CLIConfig{}, v, &out, []string{"--sha256", "deadbeef", "--signer", "user@example.com"})
	if code != exitVerifyFailed {
		t.Fatalf("expected exitVerifyFailed (%d) for a failed verdict, got %d", exitVerifyFailed, code)
	}
	if !strings.Contains(out.String(), "COSIGN VERIFICATION FAILED") {
		t.Fatalf("expected failure message, got: %s", out.String())
	}
}

func TestRunVerifyImage_VerificationPassedExitsZero(t *testing.T) {
	v := &mockVerifier{verdict: &cosignverify.Verdict{
		Verified: true,
		Digest:   "deadbeef",
		Method:   "keyless",
		Signer:   "user@example.com",
		Issuer:   "https://accounts.example.com",
		LogIndex: int64ptr(42),
	}}
	var out bytes.Buffer
	code := runVerifyImage(CLIConfig{}, v, &out, []string{"--sha256", "deadbeef", "--signer", "user@example.com", "--issuer", "https://accounts.example.com"})
	if code != exitOK {
		t.Fatalf("expected exitOK (%d) for a passed verdict, got %d", exitOK, code)
	}
	if !strings.Contains(out.String(), "COSIGN VERIFICATION PASSED") {
		t.Fatalf("expected pass message, got: %s", out.String())
	}
	if v.gotOpts.Digest != "deadbeef" || v.gotOpts.Signer != "user@example.com" || v.gotOpts.Issuer != "https://accounts.example.com" {
		t.Fatalf("verifier did not receive expected options: %+v", v.gotOpts)
	}
}

func TestRunVerifyImage_KeyBasedOptionsPassthrough(t *testing.T) {
	v := &mockVerifier{verdict: &cosignverify.Verdict{Verified: true, Digest: "deadbeef", Method: "key"}}
	var out bytes.Buffer
	code := runVerifyImage(CLIConfig{}, v, &out, []string{"--sha256", "deadbeef", "--key", "/tmp/pub.pem"})
	if code != exitOK {
		t.Fatalf("expected exitOK for key-based verification, got %d", code)
	}
	if v.gotOpts.KeyPath != "/tmp/pub.pem" {
		t.Fatalf("expected KeyPath to be forwarded, got %+v", v.gotOpts)
	}
}

// TestRunVerifyImage_RecordsAttestationShape verifies that when --trail is
// set, the verdict is posted to /api/v1/attestations with type_name
// "cosign-verification" and a JSON payload matching cosignverify.Verdict.
func TestRunVerifyImage_RecordsAttestationShape(t *testing.T) {
	verdict := &cosignverify.Verdict{
		Verified: true,
		Digest:   "deadbeef",
		Method:   "keyless",
		Signer:   "user@example.com",
		Issuer:   "https://accounts.example.com",
		LogIndex: int64ptr(7),
	}

	var gotTrailID, gotArtifactSHA, gotName, gotTypeName, gotPayload string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/attestations" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Fatalf("ParseMultipartForm: %v", err)
		}
		gotTrailID = r.FormValue("trail_id")
		gotArtifactSHA = r.FormValue("artifact_sha256")
		gotName = r.FormValue("name")
		gotTypeName = r.FormValue("type_name")
		gotPayload = r.FormValue("payload")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"att-1"}`))
	}))
	defer srv.Close()

	v := &mockVerifier{verdict: verdict}
	var out bytes.Buffer
	config := CLIConfig{ServerURL: srv.URL}
	code := runVerifyImage(config, v, &out, []string{
		"--sha256", "deadbeef",
		"--signer", "user@example.com",
		"--issuer", "https://accounts.example.com",
		"--trail", "trail-123",
	})
	if code != exitOK {
		t.Fatalf("expected exitOK, got %d (output: %s)", code, out.String())
	}
	if gotTrailID != "trail-123" {
		t.Fatalf("expected trail_id=trail-123, got %q", gotTrailID)
	}
	if gotArtifactSHA != "deadbeef" {
		t.Fatalf("expected artifact_sha256=deadbeef, got %q", gotArtifactSHA)
	}
	if gotName != "cosign-verification" {
		t.Fatalf("expected name=cosign-verification, got %q", gotName)
	}
	if gotTypeName != "cosign-verification" {
		t.Fatalf("expected type_name=cosign-verification, got %q", gotTypeName)
	}

	var recorded cosignverify.Verdict
	if err := json.Unmarshal([]byte(gotPayload), &recorded); err != nil {
		t.Fatalf("payload is not valid JSON: %v (%s)", err, gotPayload)
	}
	if recorded.Verified != verdict.Verified || recorded.Digest != verdict.Digest ||
		recorded.Method != verdict.Method || recorded.Signer != verdict.Signer ||
		recorded.Issuer != verdict.Issuer || recorded.LogIndex == nil || *recorded.LogIndex != 7 {
		t.Fatalf("recorded attestation payload does not match verdict: %+v", recorded)
	}
}

// TestRunVerifyImage_FailedVerdictStillRecordsAttestation ensures a failed
// verification is still recorded as evidence (compliant=false) and the
// deploy-gate exit code takes priority over the "recorded" success path.
func TestRunVerifyImage_FailedVerdictStillRecordsAttestation(t *testing.T) {
	var recordedPayload string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseMultipartForm(1 << 20)
		recordedPayload = r.FormValue("payload")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"att-2"}`))
	}))
	defer srv.Close()

	v := &mockVerifier{verdict: &cosignverify.Verdict{
		Verified: false,
		Digest:   "baadf00d",
		Method:   "keyless",
		Reason:   "no matching certificate identity",
	}}
	var out bytes.Buffer
	code := runVerifyImage(CLIConfig{ServerURL: srv.URL}, v, &out, []string{
		"--sha256", "baadf00d", "--signer", "attacker@example.com", "--trail", "trail-456",
	})
	if code != exitVerifyFailed {
		t.Fatalf("expected exitVerifyFailed (%d), got %d", exitVerifyFailed, code)
	}
	if !strings.Contains(recordedPayload, `"verified":false`) {
		t.Fatalf("expected recorded payload to mark verified=false: %s", recordedPayload)
	}
}
