package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	// "os"
	"strings"
)

// getHardwareFingerprint collects:
//  - first non-loopback MAC
//  - DMI product serial
//  - /etc/machine-id
// and returns SHA256(mac||serial||machineID).
func getHardwareFingerprint() []byte {
	var buf bytes.Buffer

	// 1) MAC address
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, ifi := range ifaces {
			if ifi.Flags&net.FlagLoopback == 0 && len(ifi.HardwareAddr) == 6 {
				buf.Write(ifi.HardwareAddr)
				break
			}
		}
	}

	// 2) DMI product serial
	serial, err := ioutil.ReadFile("/sys/class/dmi/id/product_serial")
	if err == nil {
		s := strings.TrimSpace(string(serial))
		buf.WriteString(s)
	}

	// 3) Machine ID fallback
	mid, err := ioutil.ReadFile("/etc/machine-id")
	if err == nil {
		buf.Write(bytes.TrimSpace(mid))
	}

	h := sha256.Sum256(buf.Bytes())
	return h[:]
}

// hexFingerprint returns fingerprint as hex string
func hexFingerprint() string {
	return hex.EncodeToString(getHardwareFingerprint())
}

// deriveAESKey yields a 32-byte key (obfuscate in production)
func deriveAESKey() []byte {
	// example static key (32 bytes)
	return []byte("12345678901234567890123456789012")
}

// encryptAndHMAC encrypts plaintext with AES-GCM, then appends HMAC-SHA256
func encryptAndHMAC(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
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

// decryptAndVerify checks HMAC then decrypts AES-GCM
func decryptAndVerify(data []byte, key []byte) ([]byte, error) {
	if len(data) < 12+32 {
		return nil, fmt.Errorf("invalid license length")
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
		return nil, fmt.Errorf("HMAC mismatch")
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
