#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <initializer_list>
#include "ProtocolScanner.hpp"
#include "VulnerabilityAnalyzer.hpp"
#include "AutomaticScanScheduler.hpp"
#include "ArgumentSetBuilder.hpp"

void displayLogo() {
    std::string logo =
        "    _____                         _  _                _____\n"
        "   |  __ \\                       | |(_)              |  ___|\n"
        "   | |  \\/ _   _   __ _  _ __  __| | _   __ _  _ __  | |__  _   _   ___\n"
        "   | | __ | | | | / _` || '__|/ _` || | / _` || '_ \\ |  __|| | | | / _ \\\n"
        "   | |_\\ \\| |_| || (_| || |  | (_| || || (_| || | | || |___| |_| ||  __/\n"
        "    \\____/ \\__,_| \\__,_||_|   \\__,_||_| \\__,_||_| |_|\\____/ \\__, | \\___|\n"
        "                                                             __/ |\n"
        "                                                            |___/\n";

    std::cout << logo << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <target> [<httpPort>] [<ftpPort>] [<scanInterval>] [<scanDuration>]" << std::endl;
        return 1;
    }

    displayLogo();
    
    ArgumentSetBuilder builder;
    
    builder
        .addArgument("target", 6, 15, 0, 255);
    
    std::vector<std::string> arguments;
    arguments.push_back(argv[1]);
    
    std::string target = argv[1];
    // defaults
    int httpPort = 80;
    int ftpPort = 21;
    int scanInterval = 60;
    int scanDuration = 300;

    if (argc >= 3) {
        builder.addArgument("httpPort", 2, 5, 1, 65535);
        arguments.push_back(argv[2]);
        httpPort = std::stoi(argv[2]);
    }
    if (argc >= 4) {
        builder.addArgument("ftpPort", 2, 5, 1, 65535);
        arguments.push_back(argv[3]);
        ftpPort = std::stoi(argv[3]);
    }
    if (argc >= 5) {
        builder.addArgument("scanInterval", 1, 5, 1, 3600);
        arguments.push_back(argv[4]);
        scanInterval = std::stoi(argv[4]);
    }
    if (argc >= 6) {
        builder.addArgument("scanDuration", 1, 300, 1, 1800);
        arguments.push_back(argv[5]);
        scanDuration = std::stoi(argv[5]);
    }
    
    builder.addArgumentSet(arguments);
    builder.validateArguments();


    ProtocolScanner scanner;
    AutomaticScanScheduler scheduler(scanner, target, httpPort, ftpPort, scanInterval, scanDuration);
    std::thread schedulerThread(scheduler);

    std::this_thread::sleep_for(std::chrono::seconds(scanDuration));
    schedulerThread.join();

    VulnerabilityAnalyzer analyzer;
    std::vector<IdentifiedService> identifiedServices;

    int ports[] = {httpPort, ftpPort};

    for (int port : ports) {
        identifiedServices.push_back(analyzer.identifyService(port));
    }

    std::cout << "Identified Services:" << std::endl;
    for (const IdentifiedService& service : identifiedServices) {
        std::cout << "Port: " << service.port << ": " << service.service << std::endl;
    }

    return 0;
}
