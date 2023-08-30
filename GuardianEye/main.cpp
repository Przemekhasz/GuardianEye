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

bool scanHttp(const std::string& target, int port) {
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
        
        std::string httpRequest = "GET / HTTP/1.1\r\nHost: " + target + "\r\n\r\n";
        const char* httpRequestCStr = httpRequest.c_str();
        
        if (send(sock, httpRequestCStr, strlen(httpRequestCStr), 0) == -1) {
            std::cerr << "Send error: " << strerror(errno) << std::endl;
            close(sock);
            return false;
        }

        char buffer[1024];
        ssize_t bytesRead = recv(sock, buffer, sizeof(buffer), 0);
        if (bytesRead > 0) {
            std::string httpResponse(buffer, bytesRead);
            if (httpResponse.find("200 OK") != std::string::npos) {
                return true;
            }
        }
        
        close(sock);
        return true;
    } else {
        close(sock);
        return false;
    }
}

bool scanFtp(const std::string& target, int port) {
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
            std::string ftpResponse(buffer, bytesRead);
            if (ftpResponse.substr(0, 3) == "220") {
                // FTP session ready to handle operations
                // TODO: add ftp session analysis
            }
        }
        
        close(sock);
        return true;
    } else {
        close(sock);
        return false;
    }
}

void scanApplicationProtocols(const std::string& target, int httpPort, int ftpPort, std::vector<Vulnerability>& openVulnerabilities) {
    if (scanHttp(target, httpPort)) {
        openVulnerabilities.push_back({httpPort, "HTTP", "HTTP service is open."});
    }
    if (scanFtp(target, ftpPort)) {
        openVulnerabilities.push_back({ftpPort, "FTP", "FTP service is open."});
    }
}

void automaticScanScheduler(const std::string& target, int httpPort, int ftpPort, int scanInterval, int scanDuration) {
    while (true) {
        std::vector<Vulnerability> openVulnerabilities;
        scanApplicationProtocols(target, httpPort, ftpPort, openVulnerabilities);
        
        if (!openVulnerabilities.empty()) {
            std::cout << "Detected vulnerabilities:" << std::endl;
            for (const Vulnerability& v : openVulnerabilities) {
                std::cout<< "Port: " << v.port << " (" << v.service << "): " << v.vulnerability << std::endl;
            }
        } else {
            std::cout << "No known vulnerabilities detected." << std::endl;
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(scanInterval));
    }
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " <target> <httpPort> <ftpPort> <scanInterval> <scanDuration>" << std::endl;
        return 1;
    }

    std::string target = argv[1];
    int httpPort = std::stoi(argv[2]);
    int ftpPort = std::stoi(argv[3]);
    int scanInterval = std::stoi(argv[4]);
    int scanDuration = std::stoi(argv[5]);

    std::thread schedulerThread(automaticScanScheduler, target, httpPort, ftpPort, scanInterval, scanDuration);
    std::this_thread::sleep_for(std::chrono::seconds(scanDuration));
    schedulerThread.join();
    
    return 0;
}
