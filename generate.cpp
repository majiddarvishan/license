#include "common.hpp"

#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/pssr.h>

/*
 * ----- Generating RSA Key Pair -----
 * Use OpenSSL to create a 2048-bit private and public key:
 *
 * $ openssl genpkey -algorithm RSA -out private.key -pkeyopt rsa_keygen_bits:2048
 * $ openssl rsa -pubout -in private.key -out public.key
 *
 * Or generate keys programmatically in C++ (Crypto++):
 */
void generate_rsa()
{
      using namespace CryptoPP;
      AutoSeededRandomPool rng;
      RSA::PrivateKey priv;
      priv.GenerateRandomWithKeySize(rng, 2048);
      RSA::PublicKey pub(priv);
      // Save private key
      FileSink fs1("private.key"); priv.DEREncode(fs1);
      // Save public key
      FileSink fs2("public.key"); pub.DEREncode(fs2);
}

void generate_fp()
{
    std::string fp = getHardwareFingerprint();

    std::ofstream fpf("fingerprint.txt");
    if (fpf.is_open()) {
        fpf << fp;
        fpf.close();
    } else {
        std::cerr << "Error opening fingerprint.txt for writing." << std::endl;
    }
}

void generate_license()
{
    using namespace CryptoPP;

    std::string privKeyFile = "private.key";
    std::string fpFile      = "fingerprint.txt";
    std::string outSigFile  = "license.sig";

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
}

int main()
{
    generate_rsa();
    generate_fp();
    generate_license();

    return 0;
}
