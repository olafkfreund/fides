package cosignverify

import (
	"context"
	"errors"
	"testing"
)

func TestOptionsValidate(t *testing.T) {
	tests := []struct {
		name    string
		opts    Options
		wantErr bool
	}{
		{"missing digest", Options{Signer: "user@example.com"}, true},
		{"missing signer and key", Options{Digest: "abc"}, true},
		{"keyless ok", Options{Digest: "abc", Signer: "user@example.com"}, false},
		{"key-based ok without signer", Options{Digest: "abc", KeyPath: "/tmp/key.pem"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSigstoreVerifierRequiresBundle(t *testing.T) {
	v := NewSigstoreVerifier()
	_, err := v.Verify(context.Background(), Options{Digest: "deadbeef", Signer: "user@example.com"})
	if !errors.Is(err, ErrBundleRequired) {
		t.Fatalf("expected ErrBundleRequired, got %v", err)
	}
}

func TestSigstoreVerifierRejectsInvalidOptions(t *testing.T) {
	v := NewSigstoreVerifier()
	if _, err := v.Verify(context.Background(), Options{Signer: "user@example.com"}); err == nil {
		t.Fatal("expected an error for a missing digest")
	}
}

func TestSigstoreVerifierRejectsInvalidDigest(t *testing.T) {
	v := NewSigstoreVerifier()
	_, err := v.Verify(context.Background(), Options{
		Digest:     "not-hex",
		Signer:     "user@example.com",
		BundlePath: "testdata/does-not-exist.json",
	})
	if err == nil {
		t.Fatal("expected an error for a non-hex digest")
	}
}
