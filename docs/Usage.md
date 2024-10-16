# Hackfunc Libraries Usage Guide
================================

This comprehensive guide provides detailed instructions on how to effectively utilize the `hackfunc` libraries for various cybersecurity tasks. Each module is thoroughly explained, including its functions, with step-by-step usage instructions.

## Table of Contents
1. [Cryptography Module](#1-cryptography-module)
    - [Key Generation and Encryption](#key-generation-and-encryption)
    - [Advanced Cryptographic Functions](#advanced-cryptographic-functions)
2. [Blockchain Module](#2-blockchain-module)
    - [Smart Contract Analysis](#smart-contract-analysis)
    - [Token Transfer Analysis](#token-transfer-analysis)
3. [Infoga Module](#3-infoga-module)
    - [Information Gathering](#information-gathering)
4. [Vuln Module](#4-vuln-module)
    - [Vulnerability Scanning](#vulnerability-scanning)
5. [Network Scans Module](#5-network-scans-module)
    - [Network Scanning](#network-scanning)
6. [Best Practices](#best-practices)

## 1. Cryptography Module
-------------------------

The `cryptography` module offers a wide range of cryptographic functions for secure data handling. Below are examples of how to use them:

### Key Generation and Encryption
---------------------------------

- **Generate a DH Public Key**:
    ```python
    from hackfunc.cryptography import AdvancedCryptography

    crypto = AdvancedCryptography()
    p, g = crypto.generate_dh_parameters()
    private_key = crypto.generate_dh_private_key(p, g)
    public_key = crypto.generate_dh_public_key(p, g, private_key)
    print(f"Generated DH Public Key: {public_key}")
    ```

- **Generate a DH Shared Secret**:
    ```python
    shared_secret = crypto.generate_dh_shared_secret(p, public_key, private_key)
    print(f"Shared Secret: {shared_secret}")
    ```

- **XOR Encryption/Decryption**:
    ```python
    plaintext = b"Hello, World!"
    key = b"secret"
    ciphertext = crypto.xor_encrypt(plaintext, key)
    decrypted_text = crypto.xor_decrypt(ciphertext, key)
    print(f"Decrypted Text: {decrypted_text}")
    ```

- **HMAC Generation and Verification**:
    ```python
    message = b"Important message"
    hmac = crypto.generate_hmac(key, message)
    is_valid = crypto.verify_hmac(key, message, hmac)
    print(f"HMAC is valid: {is_valid}")
    ```

- **ECDSA Key Pair Generation and Signing**:
    ```python
    private_key, public_key = crypto.generate_key_pair_ecdsa()
    signature = crypto.sign_ecdsa(private_key, message)
    is_verified = crypto.verify_ecdsa(public_key, message, signature)
    print(f"Signature is verified: {is_verified}")
    ```

- **File Encryption**:
    ```python
    crypto.encrypt_file('path/to/file.txt', key)
    ```

### Advanced Cryptographic Functions
-----------------------------------

- **AES-GCM Encryption/Decryption**:
    ```python
    key = crypto.secure_random_bytes(32)
    plaintext = "Hello, World!"
    ciphertext, nonce, aad = crypto.encrypt_aes_gcm(plaintext, key)
    decrypted_text = crypto.decrypt_aes_gcm(ciphertext, key, nonce, aad)
    print(f"Decrypted Text: {decrypted_text}")
    ```

- **RSA Key Pair Generation and Encryption/Decryption**:
    ```python
    private_key, public_key = crypto.generate_rsa_key_pair()
    ciphertext = crypto.rsa_encrypt(plaintext, public_key)
    decrypted_text = crypto.rsa_decrypt(ciphertext, private_key)
    print(f"Decrypted Text: {decrypted_text}")
    ```

- **Password Hashing and Verification with Argon2**:
    ```python
    hashed_password = crypto.hash_password_argon2("my_password")
    is_correct = crypto.verify_password_argon2("my_password", hashed_password)
    print(f"Password is correct: {is_correct}")
    ```

- **TOTP Generation and Verification**:
    ```python
    secret = crypto.generate_totp_secret()
    token = crypto.generate_totp(secret)
    is_valid = crypto.verify_totp(secret, token)
    print(f"TOTP is valid: {is_valid}")
    ```

## 2. Blockchain Module
-------------------------

The `blockchain` module is designed for smart contract analysis and blockchain interactions.

### Smart Contract Analysis
---------------------------

- **Analyze a Smart Contract**:
    ```python
    from hackfunc.blockchain import BlockchainHacker

    hacker = BlockchainHacker()
    vulnerabilities = await hacker.analyze_smart_contract('0xContractAddress')
    print(vulnerabilities)
    ```

- **Fuzz Test a Smart Contract Function**:
    ```python
    results = await hacker.fuzz_function('0xContractAddress', {'name': 'transfer', 'inputs': [{'type': 'address'}, {'type': 'uint256'}]})
    print(results)
    ```

- **Check for Specific Vulnerabilities**:
    - **Flashloan Vulnerability**:
        ```python
        flashloan_results = await hacker.check_flashloan_vulnerability(contract_code, contract_abi)
        print(flashloan_results)
        ```

    - **Oracle Manipulation**:
        ```python
        oracle_results = await hacker.check_oracle_manipulation(contract_code, contract_abi)
        print(oracle_results)
        ```

    - **Sandwich Attack**:
        ```python
        sandwich_results = await hacker.check_sandwich_attack(contract_code, contract_abi)
        print(sandwich_results)
        ```

    - **Governance Attack**:
        ```python
        governance_results = await hacker.check_governance_attack(contract_code, contract_abi)
        print(governance_results)
        ```

### Token Transfer Analysis
---------------------------

- **Analyze Token Transfers**:
    ```python
    transfer_analysis = await hacker.analyze_token_transfers('0xContractAddress', start_block=0, end_block=1000000)
    print(transfer_analysis)
    ```

## 3. Infoga Module
-------------------

The `infoga` module provides tools for information gathering.

### Information Gathering
-------------------------

- **WHOIS Lookup**:
    ```python
    import whois

    domain_info = whois.whois('example.com')
    print(domain_info)
    ```

- **Shodan Search**:
    ```python
    from shodan import Shodan

    api = Shodan('YOUR_API_KEY')
    results = api.search('apache')
    for result in results['matches']:
        print(f"IP: {result['ip_str']}")
    ```

- **Comprehensive Domain Information**:
    ```python
    domain_info = comprehensive_domain_info('example.com')
    print(domain_info)
    ```

- **Advanced SSL Information**:
    ```python
    ssl_info = advanced_ssl_info('example.com')
    print(ssl_info)
    ```

- **Subdomain Enumeration**:
    ```python
    subdomains = comprehensive_subdomain_enumeration('example.com')
    print(subdomains)
    ```

## 4. Vuln Module
-----------------

The `vuln` module is used for vulnerability scanning.

### Vulnerability Scanning
--------------------------

- **SQL Injection Check**:
    ```python
    from hackfunc.vuln import VulnerabilityScanner

    scanner = VulnerabilityScanner('http://example.com')
    scanner.sql_injection_check()
    ```

- **XSS Vulnerability Check**:
    ```python
    scanner.xss_check('http://example.com')
    ```

- **CSRF Token Check**:
    ```python
    scanner.csrf_token_check('http://example.com')
    ```

- **Clickjacking Check**:
    ```python
    scanner.clickjacking_check('http://example.com')
    ```

## 5. Network Scans Module
---------------------------

The `network_scans` module provides network scanning capabilities.

### Network Scanning
--------------------

- **Nmap Scan**:
    ```python
    from hackfunc.network_scans import nmap_scan

    results = nmap_scan('192.168.1.1', ['TCP_SYN_SCAN', 'SERVICE_VERSION_INTENSITY'])
    print(results)
    ```

- **Ping a Host**:
    ```python
    from hackfunc.network_scans import ping

    ping_results = ping('192.168.1.1')
    print(ping_results)
    ```

- **TCP Ping**:
    ```python
    from hackfunc.network_scans import tcp_ping

    tcp_ping_results = tcp_ping('192.168.1.1', port=80)
    print(tcp_ping_results)
    ```

- **Traceroute**:
    ```python
    from hackfunc.network_scans import traceroute

    traceroute_results = traceroute('192.168.1.1')
    print(traceroute_results)
    ```

- **Masscan Port Scan**:
    ```python
    from hackfunc.network_scans import masscan_port_scan

    masscan_results = masscan_port_scan('192.168.1.1')
    print(masscan_results)
    ```

- **Comprehensive Network Scan**:
    ```python
    from hackfunc.network_scans import comprehensive_network_scan

    network_results = comprehensive_network_scan('192.168.1.1')
    print(network_results)
    ```

## Best Practices
-----------------

- **Security**: Always encrypt sensitive data like API keys and credentials.
- **Error Handling**: Implement robust error handling to manage exceptions gracefully.
- **Compliance**: Ensure compliance with legal and ethical standards when using these tools, especially in penetration testing and OSINT.

> **Note**: Always ensure you have the necessary permissions and adhere to ethical guidelines when using these tools.
