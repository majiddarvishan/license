// #include <iostream>
// #include <string>
// #include <vector>
// #include <sstream>
// #include <fstream>

// Crypto++ headers (install Crypto++ library)
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

int main()
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
