#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>

// Crypto++ headers (install Crypto++ library)
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/pssr.h>

#ifdef _WIN32
  #include <windows.h>
  #include <iphlpapi.h>
  #include <intrin.h>
  #pragma comment(lib, "iphlpapi.lib")
#else
  #include <unistd.h>
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <sys/ioctl.h>
  #include <net/if.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <ifaddrs.h>
  #include <fcntl.h>
  #include <linux/hdreg.h>
  #include <linux/if_packet.h>
  #include <net/ethernet.h> /* the L2 protocols */
#endif

// ----- Utility: SHA-256 Hash -----
std::string sha256(const std::string &input) {
    CryptoPP::SHA256 hash;
    std::string digest;
    CryptoPP::StringSource ss(input, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest), false
            )
        )
    );
    return digest;
}

// ----- Get MAC Address (first non-loopback) -----
std::string getMacAddress() {
#ifdef _WIN32
    ULONG buflen = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &buflen);
    std::vector<BYTE> buffer(buflen);
    IP_ADAPTER_ADDRESSES* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, addrs, &buflen) != NO_ERROR)
        return "";
    for (auto p = addrs; p; p = p->Next) {
        if (p->PhysicalAddressLength == 6) {
            std::ostringstream oss;
            for (int i = 0; i < 6; ++i)
                oss << std::hex << (int)p->PhysicalAddress[i];
            return oss.str();
        }
    }
    return "";
#else
    struct ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr) == -1) return "";
    for (auto ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
            if (s->sll_halen == 6) {
                std::ostringstream oss;
                for (int i = 0; i < 6; ++i)
                    oss << std::hex << (int)s->sll_addr[i];
                freeifaddrs(ifaddr);
                return oss.str();
            }
        }
    }
    freeifaddrs(ifaddr);
    return "";
#endif
}

// ----- Get CPU ID -----
std::string getCpuId() {
#ifdef _WIN32
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 0);
    std::ostringstream oss;
    oss << std::hex << cpuInfo[1] << cpuInfo[3] << cpuInfo[2];
    return oss.str();
#else
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    while (std::getline(cpuinfo, line)) {
        if (line.find("Serial") != std::string::npos || line.find("cpu family") != std::string::npos) {
            auto pos = line.find(":");
            if (pos != std::string::npos)
                return line.substr(pos + 1);
        }
    }
    return "";
#endif
}

// ----- Get Disk Serial Number -----
std::string getDiskSerial() {
#ifdef _WIN32
    DWORD serial = 0;
    if (GetVolumeInformationA(
        "C:\\",
        nullptr, 0,
        &serial,
        nullptr, nullptr,
        nullptr, 0))
    {
        std::ostringstream oss;
        oss << std::hex << serial;
        return oss.str();
    }
    return "";
#else
    const char *device = "/dev/sda";
    int fd = open(device, O_RDONLY | O_NONBLOCK);
    if (fd < 0) return "";
    struct hd_driveid id;
    if (ioctl(fd, HDIO_GET_IDENTITY, &id) == 0) {
        close(fd);
        return std::string(reinterpret_cast<const char*>(id.serial_no));
    }
    close(fd);
    return "";
#endif
}

// ----- Combine hardware info into fingerprint -----
std::string getHardwareFingerprint() {
    std::string mac  = getMacAddress();
    std::string cpu  = getCpuId();
    std::string disk = getDiskSerial();
    return sha256(cpu + mac + disk);
}

// ----- Verify RSA signature (base64) -----
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

int main()
{
    std::string fp = getHardwareFingerprint(); // reuse your function
    std::cout << fp;
    return 0;
}

