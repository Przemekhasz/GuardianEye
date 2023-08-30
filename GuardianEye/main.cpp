#include <iostream>
#include <vector>
#include <thread>
#include "ProtocolScanner.hpp"
#include "VulnerabilityAnalyzer.hpp"

int main() {
    std::vector<std::string> nodes = {"node1", "node2", "node3"};
    std::vector<std::thread> scanThreads;

    for (const std::string& node : nodes) {
        scanThreads.emplace_back(distributedScan, node);
    }

    for (std::thread& thread : scanThreads) {
        thread.join();
    }

    analyzeVulnerabilities(customProtocols);

    return 0;
}
