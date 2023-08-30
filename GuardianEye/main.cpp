//
//  main.cpp
//  GuardianEye
//
//  Created by Przemysław Tarapacki on 30/08/2023.
//

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <thread>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

struct Vulnerability {
    int port;
    std::string service;
    std::string vulnerability;
};

bool scanPort(const std::string& target, int port, std::string& service) {
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
        char buffer[1024];
        ssize_t bytesRead = recv(sock, buffer, sizeof(buffer), 0);
        if (bytesRead > 0) {
            service = std::string(buffer, bytesRead);
        }
        close(sock);
        return true;
    } else {
        close(sock);
        return false;
    }
}

void scanNetwork(const std::string& subnet, int startPort, int endPort, std::vector<Vulnerability>& openVulnerabilities) {
    std::string nmapCommand = "nmap -p " + std::to_string(startPort) + "-" + std::to_string(endPort) + " " + subnet;
    
    FILE* nmapOutput = popen(nmapCommand.c_str(), "r");
    if (!nmapOutput) {
        std::cerr << "Failed to run Nmap command." << std::endl;
        return;
    }

    char buffer[128];
    while (fgets(buffer, sizeof(buffer), nmapOutput) != NULL) {
        std::string line(buffer);
        if (line.find("/tcp") != std::string::npos && line.find("open") != std::string::npos) {
            std::string service;
            int port = std::stoi(line.substr(0, line.find("/tcp")));
            if (scanPort(subnet, port, service)) {
                openVulnerabilities.push_back({port, service, ""});
            }
        }
    }

    pclose(nmapOutput);
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <subnet> <startPort> <endPort>" << std::endl;
        return 1;
    }

    std::string subnet = argv[1];
    int startPort = std::stoi(argv[2]);
    int endPort = std::stoi(argv[3]);

    std::vector<Vulnerability> openVulnerabilities;
    scanNetwork(subnet, startPort, endPort, openVulnerabilities);

    if (!openVulnerabilities.empty()) {
        std::cout << "Detected vulnerabilities:" << std::endl;
        for (const Vulnerability& vuln : openVulnerabilities) {
            std::cout << "Host: " << subnet << " Port: " << vuln.port << " (" << vuln.service << "): " << vuln.vulnerability << std::endl;
        }
    } else {
        std::cout << "No known vulnerabilities detected." << std::endl;
    }

    return 0;
}
