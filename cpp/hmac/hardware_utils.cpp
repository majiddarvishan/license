#include "hardware_utils.h"
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#ifdef _WIN32
  #include <windows.h>
  #include <iphlpapi.h>
  #include <intrin.h>
  #pragma comment(lib, "iphlpapi.lib")
#else
  #include <unistd.h>
  #include <sys/ioctl.h>
  #include <net/if.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <ifaddrs.h>
  #include <fcntl.h>
  #include <linux/hdreg.h>
  #include <linux/if_packet.h>
#endif
#include <vector>
#include <sstream>
#include <fstream>

using namespace CryptoPP;

std::string sha256(const std::string &input) {
    SHA256 hash;
    std::string digest;
    StringSource ss(input, true,
        new HashFilter(hash,
            new HexEncoder(
                new StringSink(digest), false
            )
        )
    );
    return digest;
}

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
            for (int i = 0; i < 6; ++i) oss << std::hex << (int)p->PhysicalAddress[i];
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
                for (int i = 0; i < 6; ++i) oss << std::hex << (int)s->sll_addr[i];
                freeifaddrs(ifaddr);
                return oss.str();
            }
        }
    }
    freeifaddrs(ifaddr);
    return "";
#endif
}

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
        if (line.find("Serial") != std::string::npos) {
            auto pos = line.find(":");
            return line.substr(pos+1);
        }
    }
    return "";
#endif
}

std::string getDiskSerial() {
#ifdef _WIN32
    DWORD serial = 0;
    if (GetVolumeInformationA("C:\\", nullptr,0,&serial,nullptr,nullptr,nullptr,0)) {
        std::ostringstream oss; oss << std::hex << serial;
        return oss.str();
    }
    return "";
#else
    const char* device = "/dev/sda";
    int fd = open(device, O_RDONLY|O_NONBLOCK);
    if (fd<0) return "";
    struct hd_driveid id;
    if(ioctl(fd, HDIO_GET_IDENTITY, &id)==0){ close(fd); return std::string(reinterpret_cast<const char*>(id.serial_no));} close(fd);
    return "";
#endif
}

std::string getHardwareFingerprint() {
    auto mac = getMacAddress();
    auto cpu = getCpuId();
    auto disk= getDiskSerial();
    return sha256(cpu + mac + disk);
}

void assembleAesKey(unsigned char outKey[32]) {
    // Obfuscated key fragments
    static const unsigned char K1[8] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    static const unsigned char K2[8] = {0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
    // etc, you can expand more fragments

    for(int i=0;i<8;++i) outKey[i]   = K1[i] ^ 0xA5;
    for(int i=8;i<16;++i)outKey[i]   = K2[i-8] + 0x3C;
    // fill rest with custom operations
    for(int i=16;i<32;++i) outKey[i] = (byte)(i * 31);
}