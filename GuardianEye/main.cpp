//
//  main.cpp
//  GuardianEye
//
//  Created by Przemysław Tarapacki on 30/08/2023.
//

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

bool scanPort(const std::string& target, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        std::cerr << "Socket error: " << strerror(errno) << std::endl;
        return false;
    }

    sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(target.c_str());

    if (connect(sock, reinterpret_cast<struct sockaddr*>(&server), sizeof(server)) == 0) {
        close(sock);
        return true;
    } else {
        close(sock);
        return false;
    }
}

void scanPortRange(const std::string& target, int startPort, int endPort, std::vector<int>& openPorts) {
    for (int port = startPort; port <= endPort; ++port) {
        if (scanPort(target, port)) {
            openPorts.push_back(port);
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <target> <startPort> <endPort>" << std::endl;
        return 1;
    }

    std::string target = argv[1];
    int startPort = std::stoi(argv[2]);
    int endPort = std::stoi(argv[3]);

    std::vector<int> openPorts;
    std::vector<std::thread> threads;

    const int numThreads = std::thread::hardware_concurrency();
    const int portsPerThread = (endPort - startPort + 1) / numThreads;

    for (int i = 0; i < numThreads; ++i) {
        int threadStartPort = startPort + i * portsPerThread;
        int threadEndPort = (i == numThreads - 1) ? endPort : threadStartPort + portsPerThread - 1;
        threads.emplace_back(scanPortRange, target, threadStartPort, threadEndPort, std::ref(openPorts));
    }

    for (std::thread& thread : threads) {
        thread.join();
    }

    if (!openPorts.empty()) {
        std::cout << "Open ports:" << std::endl;
        for (int port : openPorts) {
            std::cout << "Port " << port << " is open." << std::endl;
        }
    } else {
        std::cout << "No open ports found." << std::endl;
    }

    std::ofstream outputFile("scan_results.txt");
    if (outputFile.is_open()) {
        for (int port : openPorts) {
            outputFile << "Port " << port << " is open." << std::endl;
        }
        outputFile.close();
        std::cout << "Scan results saved to scan_results.txt" << std::endl;
    } else {
        std::cerr << "Failed to open output file." << std::endl;
    }

    return 0;
}
