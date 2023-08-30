#ifndef AUTOMATIC_SCAN_SCHEDULER_HPP
#define AUTOMATIC_SCAN_SCHEDULER_HPP

#include <string>
#include <vector>
#include <thread>
#include "ProtocolScanner.hpp"

class AutomaticScanScheduler {
public:
    AutomaticScanScheduler(ProtocolScanner& scanner, const std::string& target, int httpPort, int ftpPort, int scanInterval, int scanDuration);

    void operator()();

private:
    ProtocolScanner& m_scanner;
    std::string m_target;
    int m_httpPort;
    int m_ftpPort;
    int m_scanInterval;
    int m_scanDuration;
};

#endif
