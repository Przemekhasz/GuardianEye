#include "ProtocolScanner.hpp"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

std::vector<ProtocolConfiguration> customProtocols;
std::mutex resultsMutex;

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
                std::cout << "FTP session established on port " << port << " for target " << target << std::endl;
            }
        }
        
        close(sock);
        return true;
    } else {
        close(sock);
        return false;
    }
}

bool scanCustomProtocol(const std::string& target, const ProtocolConfiguration& protocolConfig) {
    std::cout << "Scanning port: " << protocolConfig.port << " for " << protocolConfig.protocolName << "..." << std::endl;
    
    if (protocolConfig.scanFunction == "scanHttp") {
        return scanHttp(target, protocolConfig.port);
    } else if (protocolConfig.scanFunction == "scanFtp") {
        return scanFtp(target, protocolConfig.port);
    }
    return false;
}

void distributedScan(const std::string& target) {
    for (const ProtocolConfiguration& protocolConfig : customProtocols) {
        if (scanCustomProtocol(target, protocolConfig)) {
            std::lock_guard<std::mutex> lock(resultsMutex);
            std::cout << "Node: " << target << " - Port: " << protocolConfig.port << " (" << protocolConfig.protocolName << ") is open." << std::endl;
        }
    }
}
