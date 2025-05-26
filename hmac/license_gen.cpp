#include "hardware_utils.h"
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <fstream>
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0]
                  << " <version> <out.license>\n";
        return 1;
    }
    uint32_t version = std::stoul(argv[1]);
    std::string outFile = argv[2];

    // Compute fingerprint
    std::string fp = getHardwareFingerprint();

    // Assemble AES key
    unsigned char key[32];
    assembleAesKey(key);

    // Build plaintext: 4-byte BE version + fingerprint
    std::string plain;
    plain.push_back((version>>24)&0xFF);
    plain.push_back((version>>16)&0xFF);
    plain.push_back((version>>8)&0xFF);
    plain.push_back((version>>0)&0xFF);
    plain += fp;

    // Generate IV
    CryptoPP::AutoSeededRandomPool rng;
    uint8_t iv[CryptoPP::AES::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    // Encrypt (AES-CBC)
    std::string cipher;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key, sizeof(key), iv);
    CryptoPP::StringSource ss1(plain, true,
        new CryptoPP::StreamTransformationFilter(enc,
            new CryptoPP::StringSink(cipher)
        )
    );

    // Compute HMAC-SHA256
    std::string mac;
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, sizeof(key));
    std::string ivc(reinterpret_cast<char*>(iv), sizeof(iv));
    ivc += cipher;
    CryptoPP::StringSource ss2(ivc, true,
        new CryptoPP::HashFilter(hmac,
            new CryptoPP::StringSink(mac)
        )
    );

    // Write license file: IV|cipher|MAC
    std::ofstream ofs(outFile, std::ios::binary);
    ofs.write((char*)iv, sizeof(iv));
    ofs.write(cipher.data(), cipher.size());
    ofs.write(mac.data(), mac.size());

    std::cout << "License generated for version " << version << std::endl;
    return 0;
}