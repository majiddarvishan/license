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

void generate_fp(std::string& fp)
{
    fp = getHardwareFingerprint();
}

void generate_license(const std::string& fp)
{
    using namespace CryptoPP;

    std::string privKeyFile = "private.key";
    std::string outSigFile  = "license.sig";

    FileSource fs(privKeyFile.c_str(), true);
    RSA::PrivateKey priv;
    priv.Load(fs);

    AutoSeededRandomPool rng;
    RSASS<PSSR, SHA256>::Signer signer(priv);

    StringSource(fp, true,
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

    std::string fp;
    generate_fp(fp);
    generate_license(fp);

    return 0;
}
