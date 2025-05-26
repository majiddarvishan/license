package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: license_gen <version> <output.lic>")
		os.Exit(1)
	}
	var version uint32
	_, err := fmt.Sscanf(os.Args[1], "%d", &version)
	if err != nil {
		fmt.Println("Invalid version")
		os.Exit(1)
	}

	// Build payload: version||fingerprint
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, version)
	buf.Write(getHardwareFingerprint())

	key := deriveAESKey()
	lic, err := encryptAndHMAC(buf.Bytes(), key)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(os.Args[2], lic, 0644)
	if err != nil {
		panic(err)
	}
	fmt.Println("License generated to", os.Args[2])
}
