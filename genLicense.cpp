/*
 * ----- License Generator Tool (C++) -----
 * links Crypto++
 * Usage: gen_license <private.key> <fingerprint.txt> <license.sig>
 */

#include "common.hpp"

#include <string>
#include <fstream>
#include <iostream>

int main(int argc, char* argv[])
{
    using namespace CryptoPP;
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <private.key> <fingerprint.txt> <license.sig>\n";
        return 1;
    }
    std::string privKeyFile = argv[1];
    std::string fpFile      = argv[2];
    std::string outSigFile  = argv[3];

    std::ifstream fpf(fpFile);
    std::string fingerprint((std::istreambuf_iterator<char>(fpf)), std::istreambuf_iterator<char>());

    FileSource fs(privKeyFile.c_str(), true);
    RSA::PrivateKey priv;
    priv.Load(fs);

    AutoSeededRandomPool rng;
    RSASS<PSSR, SHA256>::Signer signer(priv);

    StringSource(fingerprint, true,
        new SignerFilter(rng, signer,
            new Base64Encoder(
                new FileSink(outSigFile.c_str())
            )
        )
    );
    std::cout << "License generated in " << outSigFile << std::endl;
    return 0;
}
