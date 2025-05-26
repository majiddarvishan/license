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
	"net"
	"os"
)

// getHardwareFingerprint collects:
//  - first non-loopback MAC
//  - CPU serial from /proc/cpuinfo
//  - disk serial from /sys/block/sda/device/serial
// and returns SHA256(mac||cpuSerial||diskSerial).
func getHardwareFingerprint() []byte {
    var buf bytes.Buffer

    // 1) MAC address (first non-loopback)
    ifaces, err := net.Interfaces()
    if err == nil {
        for _, ifi := range ifaces {
            if ifi.Flags&net.FlagLoopback == 0 && len(ifi.HardwareAddr) == 6 {
                buf.Write(ifi.HardwareAddr)
                break
            }
        }
    }

    // 2) CPU info (hash entire /proc/cpuinfo)
    if cpuInfo, err := os.ReadFile("/proc/cpuinfo"); err == nil {
        buf.Write(cpuInfo)
    }

    // // 3) Disk model & vendor
    // if model, err := os.ReadFile("/sys/block/sda/device/model"); err == nil {
    //     buf.Write(bytes.TrimSpace(model))
    // }
    // if vendor, err := os.ReadFile("/sys/block/sda/device/vendor"); err == nil {
    //     buf.Write(bytes.TrimSpace(vendor))
    // }

    // Final SHA-256
    sum := sha256.Sum256(buf.Bytes())
    return sum[:]

}

// hexFingerprint returns fingerprint as hex string
func hexFingerprint() string {
	return hex.EncodeToString(getHardwareFingerprint())
}

// deriveAESKey yields a 32-byte key, split across multiple helpers
func deriveAESKey() []byte {
	var key [32]byte
	populatePart1(key[:16])
	populatePart2(key[16:])
	mixKeyFragments(key[:])
	return key[:]
}

// populatePart1 fills the first half of the key
func populatePart1(buf []byte) {
	// obfuscated constants for part 1
	part := []byte{0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
					  0x10,0x32,0x54,0x76,0x98,0xBA,0xDC,0xFE}
	for i := range buf {
		buf[i] = part[i] ^ 0xA5
	}
}

// populatePart2 fills the second half of the key
func populatePart2(buf []byte) {
	// obfuscated constants for part 2
	part := []byte{0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
					  0xEF,0xCD,0xAB,0x89,0x67,0x45,0x23,0x01}
	for i := range buf {
		buf[i] = part[i] + 0x3C
	}
}

// mixKeyFragments applies a final transformation across the full key
func mixKeyFragments(key []byte) {
	for i := range key {
		key[i] = (key[i] + byte((i*31)&0xFF))
	}
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
