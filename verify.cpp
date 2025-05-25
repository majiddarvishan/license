#include "common.hpp"

#include <string>
#include <fstream>
#include <iostream>

bool verifySignature(const std::string &fingerprint,
                     const std::string &base64Sig,
                     const std::string &pubKeyFile)
{
    using namespace CryptoPP;
    AutoSeededRandomPool rng;
    RSA::PublicKey pub;
    FileSource fs(pubKeyFile.c_str(), true);
    pub.Load(fs);

    std::string sig;
    StringSource(base64Sig, true,
        new Base64Decoder(
            new StringSink(sig)
        )
    );
    RSASS<PSSR, SHA256>::Verifier verifier(pub);
    return verifier.VerifyMessage((byte*)fingerprint.data(), fingerprint.size(),
                                  (byte*)sig.data(), sig.size());
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <license.sig> <public.key>\n";
        return 1;
    }
    std::string sigFile = argv[1];
    std::string pubKeyFile = argv[2];

    std::ifstream ifs(sigFile);
    std::string base64Sig((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    std::string fingerprint = getHardwareFingerprint();
    std::cout << "Fingerprint: " << fingerprint << std::endl;

    if (verifySignature(fingerprint, base64Sig, pubKeyFile)) {
        std::cout << "License valid." << std::endl;
    } else {
        std::cout << "Invalid license." << std::endl;
        return 1;
    }
    return 0;
}

/*
 * ----- Obfuscation & Bundling Tips -----
 * 1. Strip symbols & use UPX (or commercial packers) on the release binary.
 * 2. Hide key-check logic in multiple translation units; split functions.
 * 3. Employ anti-debugging (e.g., detect IsDebuggerPresent on Win) and integrity checks.
 * 4. Encrypt configuration strings and decrypt at runtime.
 * 5. Code-sign your executable to prevent tampering.
 * 6. For cross-platform packaging, bundle in an installer that verifies signature before install.
 *
 * ----- Recommended Third-Party Libraries -----
 * - **Crypto++**: Core cryptographic operations (SHA, RSA, Base64).
 * - **OpenSSL**: Alternative crypto backend, TLS support for online license checks.
 * - **Boost.UUID**: Generate and parse GUIDs for extra entropy in fingerprints.
 * - **libcurl / Poco::Net**: Perform HTTP(S) license validation and renewals.
 * - **Poco::Util**: Configuration file parsing and command-line options.
 * - **spdlog**: Fast, header-only logging for audit trails.
 * - **cxxopts**: Lightweight CLI parsing for license-tool flags.
 * - **HWID (e.g. Microsoft TPM Base Services)**: If targeting TPM-bound licensing.
 * - **Qt (QSysInfo)**: Cross-platform system information (CPU, disk, network).
 *
 * ----- Full-Suite Licensing SDKs (do-it-all) -----
 * Consider these commercial / open-source SDKs that handle fingerprinting, keygen, validation,
 * online activation, and tamper-protection out of the box:
 *
 * - **Cryptolens** (C++ SDK)            : Cloud-based licensing with per-feature control, HWID binding, grace periods.
 * - **WyDay LimeLM**                    : Lightweight C++ license manager with node-locked and floating licenses.
 * - **Infralock** (Kiteworks)           : Full SDK for hardware-tied licenses, TPM integration, auto-updates.
 * - **SafeNet Sentinel LDK**            : Industry-standard, highly secure licensing & entitlement platform.
 * - **Reprise License Manager (RLM)**    : Flexible host ID and license daemon for network & node-locked.
 * - **SoftwareKey System (SKU)**         : Cloud and on-prem licensing with hardware binding, analytics.
 * - **Portable Licensing by Themida**   : Protect executables + hardware licensing via VM obfuscation.
 *
 * These SDKs require integration work but remove most DIY complexity and include GUI tools,
 * license portals, and support.
 */
