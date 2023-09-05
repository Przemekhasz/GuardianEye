# GuardianEye Network Scanner

GuardianEye Network Scanner is a command-line tool written in C++ for scanning and analyzing open ports on target hosts. It offers a versatile set of features to help you identify potential vulnerabilities and security risks within your network infrastructure.

## Features

- **Advanced Service Recognition**: The tool can identify services running on open ports by analyzing server responses.
- **Security Verification**: Integrates with a vulnerability database to warn users about potential risks associated with open ports.
- **Network Host Scanning**: Capable of scanning an entire network to discover open ports on different hosts.
- **Application Layer Protocol Scanning**: Supports scanning application layer protocols like HTTP, FTP, SSH, etc.
- **Automated Scanning**: Offers a scheduler to automate scanning of specific hosts and ports at defined intervals.
- **Server and Service Recognition**: Automatically identifies the type of servers and services running on open ports.
- **Configurable Scanning**: Users can configure the tool to scan for custom protocols and parameters.
- **Cluster and Distributed Scanning**: Supports clustering and distributed environments to improve scanning efficiency.
- **Security Analysis**: Provides insights into potential threats and vulnerabilities found during scanning.

## Requirements

- C++ compiler (e.g., g++)
- Python (for running the automated scanning script)
- <strike>Nmap (for network scanning functionality)</strike>
- <strike>Python libraries: NumPy, Matplotlib (for visualization)</strike>

## Usage

1. Compile the project using the C++ compiler.
2. Run the executable with appropriate command-line arguments to perform scans.

Example:

```bash
./GuardianEye <target> [<httpPort>] [<ftpPort>] [<scanInterval>] [<scanDuration>]
```

## Getting Started

1. Clone this repository:

```bash
git clone https://github.com/yourusername/GuardianEye.git
```

2. Compile the code:

```bash
g++ -o GuardianEye main.cpp ProtocolScanner.cpp VulnerabilityAnalyzer.cpp -std=c++11 -lpthread
```

3. Run the executable with the desired parameters.

## TODO

- [ ] **Results Visualization**: Presents scan results in graphical charts or diagrams for better visualization.

## Contributing

Contributions are welcome! Please create pull requests for any enhancements, bug fixes, or new features.
