#ifndef HARDWARE_UTILS_H
#define HARDWARE_UTILS_H

#include <string>

// Retrieve hardware-specific identifiers
std::string getMacAddress();
std::string getCpuId();
std::string getDiskSerial();

// Combine into a SHA-256 fingerprint
std::string getHardwareFingerprint();

// AES key assembly (obfuscated fragments)
void assembleAesKey(unsigned char outKey[32]);

#endif // HARDWARE_UTILS_H