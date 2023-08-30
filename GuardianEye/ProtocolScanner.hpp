#pragma once
#include <vector>
#include <string>
#include <thread>
#include <map>
#include <mutex>

struct ProtocolConfiguration {
    int port;
    std::string protocolName;
    std::string scanFunction;
};

extern std::vector<ProtocolConfiguration> customProtocols;
extern std::mutex resultsMutex;

bool scanPort(const std::string& target, int port);
bool scanCustomProtocol(const std::string& target, const ProtocolConfiguration& protocolConfig);
void distributedScan(const std::string& target);
bool scanHttp(const std::string& target, int port);
bool scanFtp(const std::string& target, int port);
