// // go.mod
// module github.com/yourorg/licensing

// go 1.20

// require (
// 	// no external deps
// )


// // license_common.go
// package main

// import (
//     "bytes"
//     "crypto/aes"
//     "crypto/cipher"
//     "crypto/hmac"
//     "crypto/rand"
//     "crypto/sha256"
//     "encoding/binary"
//     "encoding/hex"
//     "fmt"
//     "io"
//     "io/ioutil"
//     "net"
//     "os"
//     "strings"
// )

// // getHardwareFingerprint collects:
// //  - first non-loopback MAC
// //  - DMI product serial
// //  - /etc/machine-id
// // and returns SHA256(mac||serial||machineID).
// func getHardwareFingerprint() []byte {
//     var buf bytes.Buffer

//     // 1) MAC address
//     ifaces, err := net.Interfaces()
//     if err == nil {
//         for _, ifi := range ifaces {
//             if ifi.Flags&net.FlagLoopback == 0 && len(ifi.HardwareAddr) == 6 {
//                 buf.Write(ifi.HardwareAddr)
//                 break
//             }
//         }
//     }

//     // 2) DMI product serial
//     serial, err := ioutil.ReadFile("/sys/class/dmi/id/product_serial")
//     if err == nil {
//         s := strings.TrimSpace(string(serial))
//         buf.WriteString(s)
//     }

//     // 3) Machine ID fallback
//     mid, err := ioutil.ReadFile("/etc/machine-id")
//     if err == nil {
//         buf.Write(bytes.TrimSpace(mid))
//     }

//     h := sha256.Sum256(buf.Bytes())
//     return h[:]
// }

// // hexFingerprint returns fingerprint as hex string
// func hexFingerprint() string {
//     return hex.EncodeToString(getHardwareFingerprint())
// }

// // deriveAESKey yields a 32-byte key, split across multiple helpers
// func deriveAESKey() []byte {
//     var key [32]byte
//     populatePart1(key[:16])
//     populatePart2(key[16:])
//     mixKeyFragments(key[:])
//     return key[:]
// }

// // populatePart1 fills the first half of the key
// func populatePart1(buf []byte) {
//     part := []byte{0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
//         0x10,0x32,0x54,0x76,0x98,0xBA,0xDC,0xFE}
//     for i := range buf {
//         buf[i] = part[i] ^ 0xA5
//     }
// }

// // populatePart2 fills the second half of the key
// func populatePart2(buf []byte) {
//     part := []byte{0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
//         0xEF,0xCD,0xAB,0x89,0x67,0x45,0x23,0x01}
//     for i := range buf {
//         buf[i] = part[i] + 0x3C
//     }
// }

// // mixKeyFragments applies a final transformation across the full key
// func mixKeyFragments(key []byte) {
//     for i := range key {
//         key[i] = (key[i] + byte((i*31)&0xFF))
//     }
// }

// // encryptAndHMAC encrypts plaintext with AES-GCM, then appends HMAC-SHA256
// func encryptAndHMAC(plaintext []byte, key []byte) ([]byte, error) {
//     block, err := aes.NewCipher(key)
//     if err != nil {
//         return nil, err
//     }
//     nonce := make([]byte, 12)
//     _, err = io.ReadFull(rand.Reader, nonce)
//     if err != nil {
//         return nil, err
//     }
//     aesgcm, err := cipher.NewGCM(block)
//     if err != nil {
//         return nil, err
//     }
//     ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

//     mac := hmac.New(sha256.New, key)
//     mac.Write(nonce)
//     mac.Write(ciphertext)
//     hmacSum := mac.Sum(nil)

//     return append(append(nonce, ciphertext...), hmacSum...), nil
// }

// // decryptAndVerify checks HMAC then decrypts AES-GCM
// func decryptAndVerify(data []byte, key []byte) ([]byte, error) {
//     if len(data) < 12+32 {
//         return nil, fmt.Errorf("invalid license length")
//     }
//     nonce := data[:12]
//     hmacOffset := len(data) - 32
//     ciphertext := data[12:hmacOffset]
//     expectedMac := data[hmacOffset:]

//     mac := hmac.New(sha256.New, key)
//     mac.Write(nonce)
//     mac.Write(ciphertext)
//     actualMac := mac.Sum(nil)

//     if !hmac.Equal(expectedMac, actualMac) {
//         return nil, fmt.Errorf("HMAC mismatch")
//     }

//     block, err := aes.NewCipher(key)
//     if err != nil {
//         return nil, err
//     }
//     aesgcm, err := cipher.NewGCM(block)
//     if err != nil {
//         return nil, err
//     }
//     return aesgcm.Open(nil, nonce, ciphertext, nil)
// }

// // license_gen.go
// package main

// import (
//     "bytes"
//     "encoding/binary"
//     "fmt"
//     "os"
//     "strconv"
//     "time"
// )

// func main() {
//     if len(os.Args) != 4 {
//         fmt.Println("Usage: license_gen <version> <expiry_unix> <output.lic>")
//         os.Exit(1)
//     }
//     version, _ := strconv.ParseUint(os.Args[1], 10, 32)
//     expiry, _ := strconv.ParseInt(os.Args[2], 10, 64)
//     outFile := os.Args[3]

//     // Build payload: version(4)|expiry(8)|fingerprint
//     buf := new(bytes.Buffer)
//     binary.Write(buf, binary.BigEndian, uint32(version))
//     binary.Write(buf, binary.BigEndian, expiry)
//     buf.Write(getHardwareFingerprint())

//     key := deriveAESKey()
//     lic, err := encryptAndHMAC(buf.Bytes(), key)
//     if err != nil {
//         panic(err)
//     }

//     err = os.WriteFile(outFile, lic, 0644)
//     if err != nil {
//         panic(err)
//     }
//     fmt.Printf("Generated license v%%d expiring %%s
// ", version, time.Unix(expiry, 0).UTC())
// }

// // license_verify.go
// package main

// import (
//     "bytes"
//     "encoding/binary"
//     "fmt"
//     "os"
//     "time"
// )

// func main() {
//     if len(os.Args) != 2 {
//         fmt.Println("Usage: license_verify <license.lic>")
//         os.Exit(1)
//     }
//     data, err := os.ReadFile(os.Args[1])
//     if err != nil {
//         panic(err)
//     }

//     key := deriveAESKey()
//     plain, err := decryptAndVerify(data, key)
//     if err != nil {
//         fmt.Println("Invalid license:", err)
//         os.Exit(1)
//     }

//     r := bytes.NewReader(plain)
//     var version uint32
//     var expiry int64
//     binary.Read(r, binary.BigEndian, &version)
//     binary.Read(r, binary.BigEndian, &expiry)
//     fp := make([]byte, 32)
//     r.Read(fp)

//     if time.Now().Unix() > expiry {
//         fmt.Println("License expired on", time.Unix(expiry, 0).UTC())
//         os.Exit(1)
//     }

//     if !bytes.Equal(fp, getHardwareFingerprint()) {
//         fmt.Println("Fingerprint mismatch")
//         os.Exit(1)
//     }

//     fmt.Printf("License valid; version = %d; expires = %s
// ", version, time.Unix(expiry, 0).UTC())
// }

// package main

// import (
// 	"bytes"
// 	"encoding/binary"
// 	"fmt"
// 	"os"
// )

// func main() {
// 	if len(os.Args) != 3 {
// 		fmt.Println("Usage: license_gen <version> <output.lic>")
// 		os.Exit(1)
// 	}
// 	var version uint32
// 	_, err := fmt.Sscanf(os.Args[1], "%d", &version)
// 	if err != nil {
// 		fmt.Println("Invalid version")
// 		os.Exit(1)
// 	}

// 	// Build payload: version||fingerprint
// 	buf := new(bytes.Buffer)
// 	binary.Write(buf, binary.BigEndian, version)
// 	buf.Write(getHardwareFingerprint())

// 	key := deriveAESKey()
// 	lic, err := encryptAndHMAC(buf.Bytes(), key)
// 	if err != nil {
// 		panic(err)
// 	}

// 	err = os.WriteFile(os.Args[2], lic, 0644)
// 	if err != nil {
// 		panic(err)
// 	}
// 	fmt.Println("License generated to", os.Args[2])
// }

// // license_verify.go
// package main

// import (
// 	"bytes"
// 	"encoding/binary"
// 	"fmt"
// 	"os"
// )

// func main() {
// 	if len(os.Args) != 2 {
// 		fmt.Println("Usage: license_verify <license.lic>")
// 		os.Exit(1)
// 	}
// 	data, err := os.ReadFile(os.Args[1])
// 	if err != nil {
// 		panic(err)
// 	}

// 	key := deriveAESKey()
// 	plain, err := decryptAndVerify(data, key)
// 	if err != nil {
// 		fmt.Println("Invalid license:", err)
// 		os.Exit(1)
// 	}

// 	// parse version and fingerprint
// 	r := bytes.NewReader(plain)
// 	var version uint32
// 	binary.Read(r, binary.BigEndian, &version)
// 	fp := make([]byte, 32)
// 	r.Read(fp)

// 	// verify fingerprint
// 	if !bytes.Equal(fp, getHardwareFingerprint()) {
// 		fmt.Println("Fingerprint mismatch")
// 		os.Exit(1)
// 	}

// 	fmt.Printf("License valid; version = %d\n", version)
// }
