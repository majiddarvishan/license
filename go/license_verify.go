package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: license_verify <license.lic>")
		os.Exit(1)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}

	key := deriveAESKey()
	plain, err := decryptAndVerify(data, key)
	if err != nil {
		fmt.Println("Invalid license:", err)
		os.Exit(1)
	}

	// parse version and fingerprint
	r := bytes.NewReader(plain)
	var version uint32
	binary.Read(r, binary.BigEndian, &version)
	fp := make([]byte, 32)
	r.Read(fp)

	// verify fingerprint
	if !bytes.Equal(fp, getHardwareFingerprint()) {
		fmt.Println("Fingerprint mismatch")
		os.Exit(1)
	}

	fmt.Printf("License valid; version = %d\n", version)
}
