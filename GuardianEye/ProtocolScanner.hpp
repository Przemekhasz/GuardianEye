#pragma once
#include <vector>
#include <string>
#include <thread>
#include <map>
#include <mutex>
#ifndef PROTOCOL_SCANNER_HPP
#define PROTOCOL_SCANNER_HPP

#include <string>

class ProtocolScanner {
public:
    ProtocolScanner() = default;
    ~ProtocolScanner() = default;

    bool scanHttp(const std::string& target, int port);
    bool scanFtp(const std::string& target, int port);

private:
};

#endif // PROTOCOL_SCANNER_HPP

