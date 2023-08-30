#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include "ProtocolScanner.hpp"
#include "VulnerabilityAnalyzer.hpp"
#include "AutomaticScanScheduler.hpp"

void displayLogo() {
    std::string logo = R"(
    _____                         _  _                _____
   |  __ \                       | |(_)              |  ___|
   | |  \/ _   _   __ _  _ __  __| | _   __ _  _ __  | |__  _   _   ___
   | | __ | | | | / _` || '__|/ _` || | / _` || '_ \ |  __|| | | | / _ \
   | |_\ \| |_| || (_| || |  | (_| || || (_| || | | || |___| |_| ||  __/
    \____/ \__,_| \__,_||_|   \__,_||_| \__,_||_| |_|\____/ \__, | \___|
                                                             __/ |
                                                            |___/
    )";

    std::cout << logo << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <target> [<httpPort>] [<ftpPort>] [<scanInterval>] [<scanDuration>]" << std::endl;
        return 1;
    }

    std::string target = argv[1];
    // defaults
    int httpPort = 80;
    int ftpPort = 21;
    int scanInterval = 60;
    int scanDuration = 300;
    // end defaults

    if (argc >= 3) {
        httpPort = std::stoi(argv[2]);
    }
    if (argc >= 4) {
        ftpPort = std::stoi(argv[3]);
    }
    if (argc >= 5) {
        scanInterval = std::stoi(argv[4]);
    }
    if (argc >= 6) {
        scanDuration = std::stoi(argv[5]);
    }
    
    displayLogo();

    ProtocolScanner scanner;
    AutomaticScanScheduler scheduler(scanner, target, httpPort, ftpPort, scanInterval, scanDuration);
    std::thread schedulerThread(scheduler);

    std::this_thread::sleep_for(std::chrono::seconds(scanDuration));
    schedulerThread.join();

    VulnerabilityAnalyzer analyzer;
    std::vector<IdentifiedService> identifiedServices;

    for (int port : {httpPort, ftpPort}) {
        identifiedServices.push_back(analyzer.identifyService(port));
    }

    std::cout << "Identified Services:" << std::endl;
    for (const IdentifiedService& service : identifiedServices) {
        std::cout << "Port: " << service.port << ": " << service.service << std::endl;
    }

    return 0;
}
