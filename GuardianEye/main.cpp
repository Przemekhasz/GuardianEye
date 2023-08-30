#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include "ProtocolScanner.hpp"
#include "VulnerabilityAnalyzer.hpp"
#include "AutomaticScanScheduler.hpp"

int main(int argc, char* argv[]) {
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

    if (argc < 6) {
        std::cerr << "Usage: " << argv[0] << " <target> <httpPort> <ftpPort> <scanInterval> <scanDuration>" << std::endl;
        return 1;
    }

    std::string target = argv[1];
    int httpPort = std::stoi(argv[2]);
    int ftpPort = std::stoi(argv[3]);
    int scanInterval = std::stoi(argv[4]);
    int scanDuration = std::stoi(argv[5]);
    std::vector<int> openPorts;

    ProtocolScanner scanner;
    AutomaticScanScheduler scheduler(scanner, target, httpPort, ftpPort, scanInterval, scanDuration);
    std::thread schedulerThread(scheduler);

    std::this_thread::sleep_for(std::chrono::seconds(scanDuration));
    schedulerThread.join();
    
    VulnerabilityAnalyzer analyzer;
    std::vector<IdentifiedService> identifiedServices;

    for (int port : openPorts) {
        identifiedServices.push_back(analyzer.identifyService(port));
    }

    std::cout << "Identified Services:" << std::endl;
    for (const IdentifiedService& service : identifiedServices) {
        std::cout << "Port: " << service.port << ": " << service.service << std::endl;
    }

    return 0;
}
