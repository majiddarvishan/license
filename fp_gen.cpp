#include "common.hpp"

#include <string>
#include <fstream>
#include <iostream>

int main()
{
    std::string fp = getHardwareFingerprint();

    std::ofstream fpf("fingerprint.txt");
    if (fpf.is_open()) {
        fpf << fp;
        fpf.close();
    } else {
        std::cerr << "Error opening fingerprint.txt for writing." << std::endl;
    }

    return 0;
}

