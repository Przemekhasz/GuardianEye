#include "ProtocolScanner.hpp"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

bool ProtocolScanner::scanHttp(const std::string& target, int port) {
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
                close(sock);
                return true;
            }
        }

        close(sock);
    } else {
        std::cerr << "Connect error: " << strerror(errno) << std::endl;
    }

    return false;
}

bool ProtocolScanner::scanFtp(const std::string& target, int port) {
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
                close(sock);
                return true;
            }
        }

        close(sock);
    } else {
        std::cerr << "Connect error: " << strerror(errno) << std::endl;
    }

    return false;
}
