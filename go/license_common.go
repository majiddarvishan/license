// license_common.go
package main

import (
	// "bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	// "encoding/binary"
	"fmt"
	"io"
	// "os"
)

func getHardwareFingerprint() []byte {
	// You can use syscall + `dmidecode` or platform-specific libraries
	// For now, a fake example
	cpu := []byte("CPU-FAKE-123456")
	disk := []byte("DISK-FAKE-ABCDEF")
	h := sha256.New()
	h.Write(cpu)
	h.Write(disk)
	return h.Sum(nil)
}

func deriveAESKey() []byte {
	// Pretend this is obfuscated or derived across functions
	return []byte("12345678901234567890123456789012") // 32 bytes for AES-256
}

func encryptAndHMAC(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	io.ReadFull(rand.Reader, nonce)

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	mac.Write(ciphertext)
	hmacSum := mac.Sum(nil)

	return append(append(nonce, ciphertext...), hmacSum...), nil
}

func decryptAndVerify(data []byte, key []byte) ([]byte, error) {
	if len(data) < 12+32 {
		return nil, fmt.Errorf("invalid license format")
	}
	nonce := data[:12]
	hmacOffset := len(data) - 32
	ciphertext := data[12:hmacOffset]
	expectedMac := data[hmacOffset:]

	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	mac.Write(ciphertext)
	actualMac := mac.Sum(nil)

	if !hmac.Equal(expectedMac, actualMac) {
		return nil, fmt.Errorf("invalid HMAC")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}
