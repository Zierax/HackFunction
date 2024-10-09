# 🚀 Hackfunc Project

## 🌟 Overview

The **Hackfunc Project** is a comprehensive suite of cybersecurity tools and libraries designed to empower security researchers, penetration testers, and bug bounty hunters. It automates essential tasks in:

- 🕵️‍♂️ Reconnaissance
- 🔍 Vulnerability Scanning
- 🔐 Cryptography
- 📊 Blockchain Analysis
- 🌐 Network Security

Each module is crafted for flexibility, allowing seamless integration into larger security frameworks or independent use.

## 🔑 Key Features

- **🔐 Cryptography Module**: Secure data encryption, key generation, and hashing algorithms (RSA, AES, HMAC).
- **📊 Blockchain Module**: Smart contract vulnerability analysis and blockchain data interaction.
- **🌐 Infoga Module**: Domain and subdomain information gathering (WHOIS, SSL, etc.).
- **🛡️ Vuln Module**: Web application vulnerability scanning (SQL injection, XSS, CSRF).
- **🌍 Network Scans Module**: Comprehensive network reconnaissance tools (Nmap, Masscan, traceroute).

## 🏗️ Project Structure

The project is organized into modules, each targeting a specific cybersecurity domain:

````

hackfunc/
│
├── cryptography/       # Cryptographic functions (e.g., AES, RSA, HMAC)
│
├── blockchain/         # Blockchain analysis tools (e.g., smart contract analysis, etc.)
│
├── infoga/             # Information gathering (e.g., WHOIS, subdomain enumeration, etc.)
│
├── vuln/               # Vulnerability scanning (e.g., SQL injection, XSS, Command Injection, SSRF, etc.)
│
├── network_scans/      # Network scanning tools (e.g., Nmap, Masscan, traceroute, etc.)
│
└── utils/              # Utility functions (e.g., logging, argument parsing, etc.)
````

### 🔐 Cryptography
- Key generation, encryption, and decryption using algorithms like AES, RSA, and HMAC.

### 📊 Blockchain
- Tools for auditing smart contracts and analyzing token transfers.

### 🌐 Infoga
- Domain-related information gathering, including WHOIS and SSL details.

### 🛡️ Vuln
- Automated scans for web application vulnerabilities like SQL injection and XSS.

### 🌍 Network Scans
- Network scanning tools for port scanning, service enumeration, and diagnostics.

## 🛠️ Installation

To get started with Hackfunc, follow these steps:

1. **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/hackfunc.git
    cd hackfunc
    ```

2. **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3. **Set up your environment**:
    - Ensure external tools (e.g., Nmap, Masscan) are installed.
    - Set up necessary API keys or credentials for services like Shodan, Infoga.

## 📚 Usage

Each module can be executed independently or integrated into other scripts. Here are some examples:

### 🔐 Cryptography
- **Encrypting a file**:
    ```python
    from hackfunc.cryptography import AdvancedCryptography

    crypto = AdvancedCryptography()
    crypto.encrypt_file('path/to/file.txt', key='your_secret_key')
    ```

### 📊 Blockchain
- **Analyze a smart contract**:
    ```python
    from hackfunc.blockchain import BlockchainHacker

    hacker = BlockchainHacker()
    vulnerabilities = await hacker.analyze_smart_contract('0xContractAddress')
    print(vulnerabilities)
    ```

### 🌐 Infoga
- **Perform a WHOIS lookup**:
    ```python
    import whois

    domain_info = whois.whois('example.com')
    print(domain_info)
    ```

### 🛡️ Vuln
- **Scan for vulnerabilities**:
    ```python
    from hackfunc.vuln import VulnerabilityScanner

    scanner = VulnerabilityScanner('http://example.com')
    scanner.sql_injection_check()
    ```

### 🌍 Network Scans
- **Perform a Nmap scan**:
    ```python
    from hackfunc.network_scans import nmap_scan

    results = nmap_scan('192.168.1.1', ['TCP_SYN_SCAN', 'SERVICE_VERSION_INTENSITY'])
    print(results)
    ```

## 🏆 Best Practices

- **🔑 API Key Management**: Store keys securely using environment variables or configuration files.
- **⚠️ Error Handling**: Implement error handling for network issues or API errors.
- **🔄 Update Dependencies**: Regularly update libraries and tools.
- **⚖️ Legal Compliance**: Obtain permission before scanning or gathering information from external systems.


## 📜 License
- This project is licensed under the MIT License - see the LICENSE file for details.