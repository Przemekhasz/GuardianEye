#include "AutomaticScanScheduler.hpp"
#include <chrono>

AutomaticScanScheduler::AutomaticScanScheduler(ProtocolScanner& scanner, const std::string& target, int httpPort, int ftpPort, int scanInterval, int scanDuration)
    : m_scanner(scanner), m_target(target), m_httpPort(httpPort), m_ftpPort(ftpPort), m_scanInterval(scanInterval), m_scanDuration(scanDuration) {}

void AutomaticScanScheduler::operator()() {
    auto startTime = std::chrono::steady_clock::now();

    while (true) {
        auto currentTime = std::chrono::steady_clock::now();
        auto elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime).count();

        if (elapsedTime >= m_scanDuration) {
            break;
        }

        m_scanner.scanHttp(m_target, m_httpPort);
        m_scanner.scanFtp(m_target, m_ftpPort);

        std::this_thread::sleep_for(std::chrono::seconds(m_scanInterval));
    }
}
