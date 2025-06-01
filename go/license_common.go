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
	"strings"

	"os/exec"
	"runtime"
	"sort"

    "github.com/shirou/gopsutil/v3/cpu"
)

// HardwareID represents different hardware identifiers
type HardwareID struct {
	MachineID    string
	CPUInfo      string
	MACAddresses []string
	SystemUUID   string
	DiskSerial   string
}

// GetMachineID reads the machine ID from /etc/machine-id (Linux) or equivalent
func GetMachineID() (string, error) {
	var paths []string

	switch runtime.GOOS {
	case "linux":
		paths = []string{"/etc/machine-id", "/var/lib/dbus/machine-id"}
	case "darwin":
		// macOS doesn't have machine-id, we'll use system_profiler later
		return "", fmt.Errorf("machine-id not available on macOS")
	case "windows":
		// Windows uses different approach
		return getWindowsMachineID()
	}

	for _, path := range paths {
		if data, err := os.ReadFile(path); err == nil {
			return strings.TrimSpace(string(data)), nil
		}
	}

	return "", fmt.Errorf("machine-id not found")
}

// getWindowsMachineID gets Windows machine GUID
func getWindowsMachineID() (string, error) {
	cmd := exec.Command("wmic", "csproduct", "get", "UUID", "/value")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "UUID=") {
			return strings.TrimSpace(strings.Split(line, "=")[1]), nil
		}
	}

	return "", fmt.Errorf("UUID not found")
}

// GetCPUInfo gets CPU information
func GetCPUInfo() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return getCPUInfoLinux()
	case "darwin":
		return getCPUInfoMacOS()
	case "windows":
		return getCPUInfoWindows()
	}

	return "", fmt.Errorf("unsupported OS")
}

func getCPUInfoLinux() (string, error) {
	// Get CPU info
	infoStats, err := cpu.Info()
	if err != nil || len(infoStats) == 0 {
		fmt.Println("Error getting CPU info:", err)
		return "", err
	}
	cpuModel := infoStats[0].ModelName
	cpuFreq := fmt.Sprintf("%.2f MHz", infoStats[0].Mhz)

	// Get core counts
	physicalCores, err := cpu.Counts(false)
	if err != nil {
		fmt.Println("Error getting physical core count:", err)
		return "", err
	}
	logicalCores, err := cpu.Counts(true)
	if err != nil {
		fmt.Println("Error getting logical core count:", err)
		return "", err
	}

	// Get average CPU usage over 1 second
	// percentages, err := cpu.Percent(time.Second, false)
	// if err != nil || len(percentages) == 0 {
	// 	fmt.Println("Error getting CPU usage:", err)
	// 	return
	// }
	// avgCPUUsage := fmt.Sprintf("%.2f%%", percentages[0])

	// Merge into a single string
	result := []string{
		"Model: " + cpuModel,
		fmt.Sprintf("Physical Cores: %d", physicalCores),
		fmt.Sprintf("Logical CPUs: %d", logicalCores),
		"Frequency: " + cpuFreq,
		// "Usage: " + avgCPUUsage,
	}

	finalStr := strings.Join(result, " | ")

	return finalStr, nil
}

// func getCPUInfoLinux() (string, error) {
// 	data, err := os.ReadFile("/proc/cpuinfo")
// 	if err != nil {
// 		return "", err
// 	}

// 	lines := strings.Split(string(data), "\n")
// 	var cpuInfo []string

// 	for _, line := range lines {
// 		if strings.Contains(line, "model name") ||
// 		   strings.Contains(line, "cpu family") ||
// 		   strings.Contains(line, "vendor_id") ||
//            strings.Contains(line, "stepping") {
// 			cpuInfo = append(cpuInfo, strings.TrimSpace(line))
// 		}
// 	}

// 	if len(cpuInfo) > 0 {
// 		return cpuInfo[0], nil // Return first CPU's info
// 	}

// 	return "", fmt.Errorf("CPU info not found")
// }

func getCPUInfoMacOS() (string, error) {
	cmd := exec.Command("sysctl", "-n", "machdep.cpu.brand_string")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func getCPUInfoWindows() (string, error) {
	cmd := exec.Command("wmic", "cpu", "get", "Name", "/value")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Name=") {
			return strings.TrimSpace(strings.Split(line, "=")[1]), nil
		}
	}

	return "", fmt.Errorf("CPU name not found")
}

// GetMACAddresses gets all network interface MAC addresses
func GetMACAddresses() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var macs []string
	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		if len(iface.HardwareAddr) > 0 {
			macs = append(macs, iface.HardwareAddr.String())
		}
	}

	// Sort for consistency
	sort.Strings(macs)
	return macs, nil
}

// GetSystemUUID gets system UUID via dmidecode (Linux/macOS) or wmic (Windows)
func GetSystemUUID() (string, error) {
	switch runtime.GOOS {
	case "linux", "darwin":
		cmd := exec.Command("dmidecode", "-s", "system-uuid")
		output, err := cmd.Output()
		if err != nil {
			return "", err
		}
		uuid := strings.TrimSpace(string(output))
		if uuid == "Not Specified" || uuid == "" {
			return "", fmt.Errorf("system UUID not available")
		}
		return uuid, nil

	case "windows":
		return getWindowsMachineID() // Same as machine ID for Windows
	}

	return "", fmt.Errorf("unsupported OS")
}

// GetDiskSerial gets primary disk serial number
func GetDiskSerial() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return getDiskSerialLinux()
	case "darwin":
		return getDiskSerialMacOS()
	case "windows":
		return getDiskSerialWindows()
	}

	return "", fmt.Errorf("unsupported OS")
}

func getDiskSerialLinux() (string, error) {
	// Try to get serial from /sys/block/sda/serial or similar
	disks := []string{"sda", "nvme0n1", "vda"}

	for _, disk := range disks {
		path := fmt.Sprintf("/sys/block/%s/serial", disk)
		if data, err := os.ReadFile(path); err == nil {
			return strings.TrimSpace(string(data)), nil
		}
	}

	// Alternative: use lsblk
	cmd := exec.Command("lsblk", "-d", "-o", "SERIAL", "-n")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			serial := strings.TrimSpace(line)
			if serial != "" && serial != "Not Specified" {
				return serial, nil
			}
		}
	}

	return "", fmt.Errorf("disk serial not found")
}

func getDiskSerialMacOS() (string, error) {
	cmd := exec.Command("system_profiler", "SPSerialATADataType")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Serial Number:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}

	return "", fmt.Errorf("disk serial not found")
}

func getDiskSerialWindows() (string, error) {
	cmd := exec.Command("wmic", "diskdrive", "get", "SerialNumber", "/value")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "SerialNumber=") {
			serial := strings.TrimSpace(strings.Split(line, "=")[1])
			if serial != "" {
				return serial, nil
			}
		}
	}

	return "", fmt.Errorf("disk serial not found")
}

// CollectHardwareInfo collects all available hardware information
func CollectHardwareInfo() *HardwareID {
	hwid := &HardwareID{}

	if machineID, err := GetMachineID(); err == nil {
		hwid.MachineID = machineID
	}

	if cpuInfo, err := GetCPUInfo(); err == nil {
		hwid.CPUInfo = cpuInfo
	}

	if macs, err := GetMACAddresses(); err == nil {
		hwid.MACAddresses = macs
	}

	if uuid, err := GetSystemUUID(); err == nil {
		hwid.SystemUUID = uuid
	}

	if diskSerial, err := GetDiskSerial(); err == nil {
		hwid.DiskSerial = diskSerial
	}

	return hwid
}

// GenerateUniqueID creates a unique hardware fingerprint
func (h *HardwareID) GenerateUniqueID() string {
	var components []string

	if h.MachineID != "" {
		components = append(components, "machine:"+h.MachineID)
	}

	if h.SystemUUID != "" {
		components = append(components, "uuid:"+h.SystemUUID)
	}

	if h.CPUInfo != "" {
		components = append(components, "cpu:"+h.CPUInfo)
	}

	// if len(h.MACAddresses) > 0 {
	// 	components = append(components, "mac:"+strings.Join(h.MACAddresses, ","))
	// }

	// if h.DiskSerial != "" {
	// 	components = append(components, "disk:"+h.DiskSerial)
	// }

	// Join all components and hash
	combined := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(combined))
	return fmt.Sprintf("%x", hash)
}

// GenerateShortID creates a shorter hardware fingerprint using MD5
func (h *HardwareID) GenerateShortID() []byte {
	var components []string

	if h.MachineID != "" {
		components = append(components, h.MachineID)
	}

	if h.SystemUUID != "" {
		components = append(components, h.SystemUUID)
	}

    if h.CPUInfo != "" {
		components = append(components, h.CPUInfo)
	}

	// if len(h.MACAddresses) > 0 {
	// 	components = append(components, h.MACAddresses[0]) // Use first MAC only
	// }

	combined := strings.Join(components, "")
	// hash := md5.Sum([]byte(combined))
	// return fmt.Sprintf("%x", hash)

    // Final SHA-256
    sum := sha256.Sum256([]byte(combined))
    return sum[:]
}

// getHardwareFingerprint collects:
//  - first non-loopback MAC
//  - CPU serial from /proc/cpuinfo
//  - disk serial from /sys/block/sda/device/serial
// and returns SHA256(mac||cpuSerial||diskSerial).
func getHardwareFingerprint() []byte {
    var buf bytes.Buffer

    // 1) MAC address (first non-loopback)
    // ifaces, err := net.Interfaces()
    // if err == nil {
    //     for _, ifi := range ifaces {
    //         if ifi.Flags&net.FlagLoopback == 0 && len(ifi.HardwareAddr) == 6 {
    //             buf.Write(ifi.HardwareAddr)
    //             break
    //         }
    //     }
    // }

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
