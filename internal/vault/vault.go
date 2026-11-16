// Package vault encrypts secrets at rest with AES-256-GCM under a key kept in
// the user's profile directory.
//
// This is the first line of defence, not the last: the key sits next to the
// database, so it protects copied databases and backups, not a compromised
// account. A later step hands the key to the system keychain instead.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// keySize is the AES-256 key length.
const keySize = 32

// Vault seals and opens secrets.
type Vault struct {
	aead cipher.AEAD
}

// Open loads the key at path, creating it with 0600 permissions when missing.
func Open(path string) (*Vault, error) {
	key, err := loadOrCreateKey(path)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("vault: cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: gcm: %w", err)
	}
	return &Vault{aead: aead}, nil
}

// Encrypt seals a plaintext secret and returns base64, or "" for no secret.
func (v *Vault) Encrypt(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}

	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("vault: nonce: %w", err)
	}

	sealed := v.aead.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt opens a value produced by Encrypt.
func (v *Vault) Decrypt(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("vault: decode: %w", err)
	}
	if len(data) < v.aead.NonceSize() {
		return "", errors.New("vault: sealed value is too short")
	}

	nonce, ciphertext := data[:v.aead.NonceSize()], data[v.aead.NonceSize():]
	plain, err := v.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("vault: open: %w", err)
	}
	return string(plain), nil
}

// loadOrCreateKey reads the key file, creating a random one when absent.
func loadOrCreateKey(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("vault: key path is required")
	}

	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) != keySize {
			return nil, fmt.Errorf("vault: %s holds %d bytes, want %d", path, len(data), keySize)
		}
		return data, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("vault: read key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("vault: create key directory: %w", err)
	}

	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("vault: generate key: %w", err)
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, fmt.Errorf("vault: write key: %w", err)
	}
	return key, nil
}
