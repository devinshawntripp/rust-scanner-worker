package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
)

const (
	ivLength  = 12
	tagLength = 16
)

// DecryptAES256GCM decrypts data encrypted by the Node.js crypto module
// using AES-256-GCM. The data format is: IV (12 bytes) || ciphertext || auth tag (16 bytes).
// The key is a 32-byte value derived from a 64-char hex string.
func DecryptAES256GCM(keyHex string, data []byte) (string, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("invalid hex key: %w", err)
	}
	if len(key) != 32 {
		return "", fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	if len(data) < ivLength+tagLength {
		return "", fmt.Errorf("data too short: %d bytes", len(data))
	}

	iv := data[:ivLength]
	ciphertext := data[ivLength : len(data)-tagLength]
	tag := data[len(data)-tagLength:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, ivLength)
	if err != nil {
		return "", fmt.Errorf("cipher.NewGCM: %w", err)
	}

	// GCM expects ciphertext || tag concatenated
	sealed := append(ciphertext, tag...)
	plaintext, err := gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		return "", fmt.Errorf("gcm.Open: %w", err)
	}
	return string(plaintext), nil
}
