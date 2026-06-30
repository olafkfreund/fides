package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/scrypt"
)

// kdfSalt is a fixed application salt used to stretch passphrase-based keys.
// A fixed salt is required here because the key must be derived identically on
// both the encrypting (CLI) and decrypting (server) sides from a shared secret
// that is never transmitted alongside the ciphertext. For stronger guarantees,
// operators should supply a full 32-byte key (base64-encoded) instead of a
// passphrase, in which case it is used directly without stretching.
var kdfSalt = []byte("fides-kdf-v1-static-salt-0001")

// scrypt cost parameters (interactive use).
const (
	scryptN = 1 << 15 // CPU/memory cost
	scryptR = 8
	scryptP = 1
)

// Encrypt encrypts plainText using the provided key (must be 32 bytes for AES-256)
func Encrypt(plainText []byte, key []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("key must be exactly 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherText := gcm.Seal(nonce, nonce, plainText, nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// Decrypt decrypts cipherTextBase64 using the provided key
func Decrypt(cipherTextBase64 string, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be exactly 32 bytes for AES-256")
	}

	cipherText, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, actualCipherText := cipherText[:nonceSize], cipherText[nonceSize:]
	return gcm.Open(nil, nonce, actualCipherText, nil)
}

// DeriveKey derives a 32-byte AES-256 key from the supplied secret.
//
// If the secret is a base64-encoded 32-byte value it is used directly (the
// recommended configuration). Otherwise the secret is treated as a passphrase
// and stretched with scrypt and a fixed application salt, which eliminates the
// low-entropy/predictable-padding weakness of naive truncation.
func DeriveKey(secret string) ([]byte, error) {
	if secret == "" {
		return nil, errors.New("encryption secret must not be empty")
	}

	// Preferred path: a full 32-byte key provided as base64.
	if raw, err := base64.StdEncoding.DecodeString(secret); err == nil && len(raw) == 32 {
		return raw, nil
	}

	// Fallback: stretch the passphrase with scrypt into a 32-byte key.
	key, err := scrypt.Key([]byte(secret), kdfSalt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return nil, err
	}
	return key, nil
}
