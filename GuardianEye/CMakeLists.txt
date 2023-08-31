cmake_minimum_required(VERSION 3.0)

project(GuardianEye)

set(SOURCE_FILES
    main.cpp
    ProtocolScanner.cpp
    VulnerabilityAnalyzer.cpp
    AutomaticScanScheduler.cpp
    CustomValidator.cpp
    ArgumentSetBuilder.cpp
)

add_executable(GuardianEye ${SOURCE_FILES})
