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
		return
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}

	key := deriveAESKey()
	plain, err := decryptAndVerify(data, key)
	if err != nil {
		fmt.Println("Invalid license:", err)
		return
	}

	buf := bytes.NewReader(plain)
	var version uint32
	binary.Read(buf, binary.BigEndian, &version)
	fp := make([]byte, 32)
	buf.Read(fp)

	actual := getHardwareFingerprint()
	if !bytes.Equal(fp, actual) {
		fmt.Println("License invalid for this machine.")
		return
	}
	fmt.Printf("License valid. Version: %d\n", version)
}
