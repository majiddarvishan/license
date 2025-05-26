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
		return
	}
	version := uint32(0)
	fmt.Sscanf(os.Args[1], "%d", &version)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, version)
	buf.Write(getHardwareFingerprint())

	key := deriveAESKey()
	enc, err := encryptAndHMAC(buf.Bytes(), key)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(os.Args[2], enc, 0644)
	if err != nil {
		panic(err)
	}
	fmt.Println("License generated.")
}
