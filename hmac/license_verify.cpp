#include "hardware_utils.h"
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <fstream>
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <license.bin>\n";
        return 1;
    }
    // Read license blob
    std::ifstream ifs(argv[1], std::ios::binary);
    std::string blob((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    size_t minSize = CryptoPP::AES::BLOCKSIZE + 32;
    if (blob.size() < minSize) { std::cerr << "License too short\n"; return 1; }

    // Split IV, cipher, MAC
    size_t ivLen = CryptoPP::AES::BLOCKSIZE;
    size_t macLen= 32;
    std::string iv = blob.substr(0, ivLen);
    std::string cipher = blob.substr(ivLen, blob.size()-ivLen-macLen);
    std::string mac    = blob.substr(blob.size()-macLen);

    // Verify HMAC
    unsigned char key[32]; assembleAesKey(key);
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, sizeof(key));
    std::string ivc = iv + cipher;
    bool hmacOk = false;
    try {
        CryptoPP::StringSource(ivc + mac, true,
            new CryptoPP::HashVerificationFilter(hmac,
                new CryptoPP::ArraySink((uint8_t*)&hmacOk, sizeof(hmacOk)),
                CryptoPP::HashVerificationFilter::THROW_EXCEPTION
            )
        );
    } catch(...) {
        std::cerr << "HMAC mismatch or tamper detected\n";
        return 1;
    }

    // Decrypt AES-CBC
    std::string plain;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key, sizeof(key), (const uint8_t*)iv.data());
    CryptoPP::StringSource ss2(cipher, true,
        new CryptoPP::StreamTransformationFilter(dec,
            new CryptoPP::StringSink(plain)
        )
    );

    // Parse version + fingerprint
    if (plain.size() < 4) { std::cerr << "Plaintext too small\n"; return 1; }
    uint32_t version = (uint8_t)plain[0]<<24 | (uint8_t)plain[1]<<16 |
                       (uint8_t)plain[2]<<8  | (uint8_t)plain[3];
    std::string fpIn = plain.substr(4);

    // Compute expected fingerprint
    std::string expectedFp = getHardwareFingerprint();
    if (fpIn != expectedFp) { std::cerr << "Fingerprint mismatch\n"; return 1; }

    std::cout << "License valid; version = " << version << std::endl;
    return 0;
}
