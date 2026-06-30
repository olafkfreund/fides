package crypto

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, err := DeriveKey("a-reasonably-long-test-passphrase")
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}

	plain := []byte("sensitive evidence payload")
	ct, err := Encrypt(plain, key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := Decrypt(ct, key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch: got %q want %q", got, plain)
	}
}

func TestDeriveKeyUsesBase64KeyDirectly(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	encoded := base64.StdEncoding.EncodeToString(raw)

	key, err := DeriveKey(encoded)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	if !bytes.Equal(key, raw) {
		t.Fatalf("expected base64 key to be used verbatim")
	}
}

func TestDeriveKeyPassphraseIsDeterministicAnd32Bytes(t *testing.T) {
	k1, err := DeriveKey("hunter2")
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	k2, _ := DeriveKey("hunter2")
	if len(k1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(k1))
	}
	if !bytes.Equal(k1, k2) {
		t.Fatalf("KDF must be deterministic for the same passphrase")
	}
	// Different passphrase must produce a different key.
	k3, _ := DeriveKey("hunter3")
	if bytes.Equal(k1, k3) {
		t.Fatalf("different passphrases must yield different keys")
	}
}

func TestDeriveKeyRejectsEmpty(t *testing.T) {
	if _, err := DeriveKey(""); err == nil {
		t.Fatalf("expected error for empty secret")
	}
}

func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	key, _ := DeriveKey("another-test-passphrase")
	ct, _ := Encrypt([]byte("data"), key)
	// Flip a character in the base64 ciphertext.
	tampered := "A" + ct[1:]
	if _, err := Decrypt(tampered, key); err == nil {
		t.Fatalf("expected decryption of tampered ciphertext to fail")
	}
}
