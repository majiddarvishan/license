
int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <license.sig> <public.key>\n";
        return 1;
    }
    std::string sigFile = argv[1];
    std::string pubKeyFile = argv[2];

    std::ifstream ifs(sigFile);
    std::string base64Sig((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    // In Docker: mount host fingerprint file or pass via ENV
    std::string fingerprint;
    if (std::getenv("HOST_FP_FILE")) {
        std::ifstream fpf(std::getenv("HOST_FP_FILE"));
        fingerprint.assign((std::istreambuf_iterator<char>(fpf)), std::istreambuf_iterator<char>());
    } else {
        fingerprint = getHardwareFingerprint();
    }
    std::cout << "Fingerprint: " << fingerprint << std::endl;

    if (verifySignature(fingerprint, base64Sig, pubKeyFile)) {
        std::cout << "License valid." << std::endl;
    } else {
        std::cout << "Invalid license." << std::endl;
        return 1;
    }
    // ... proceed with protected functionality
    return 0;
}

/*
 * Docker Integration Tips:
 * 1) Build your image with Crypto++ and binaries copied in.
 * 2) Pass in <license.sig> and <public.key> via Docker volumes or ENV:
 *    docker run -v /path/to/license.sig:/app/license.sig \
 *               -v /path/to/public.key:/app/public.key \
 *               -e HOST_FP_FILE=/mnt/host_fp.txt \
 *               myapp:latest ./myapp /app/license.sig /app/public.key
 *
 * 3) If container cannot access host hardware, pre-generate the host fingerprint:
 *    $ ./gen_fp > host_fp.txt
 *    then mount host_fp.txt as HOST_FP_FILE.
 *
 * 4) For automated CI/CD, generate license inside pipeline and COPY into image.
 *
 * 5) Alternatively, implement an online validation endpoint:
 *    - Container authenticates to your license server with token.
 *    - Server verifies host ID and returns license blob.
 */

/*
 * Other tools remain unchanged...
 */
