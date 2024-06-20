from .utils import make_request
import nmap
from scapy.all import *


NMAP_SCAN_TYPES = {
    # Host discovery
    "PING": "-sn",  # Ping Scan
    "TCP_SYN_SCAN": "-sS",  # TCP SYN Scan
    "TCP_CONNECT_SCAN": "-sT",  # TCP Connect Scan
    "UDP_SCAN": "-sU",  # UDP Scan
    "ACK_SCAN": "-sA",  # TCP ACK Scan
    "WINDOW_SCAN": "-sW",  # TCP Window Scan
    "MAIMON_SCAN": "-sM",  # TCP Maimon Scan
    "TCP_NULL_SCAN": "-sN",  # TCP NULL Scan
    "FIN_SCAN": "-sF",  # TCP FIN Scan
    "XMAS_SCAN": "-sX",  # TCP XMAS Scan
    "WAF_BYPASSER": "-Pn", # Waf Bypasser

    # Service detection
    "SERVICE_VERSION": "-sV",  # Version Detection

    # OS detection
    "OS_DETECTION": "-O",  # OS Detection

    # Script scanning
    "SCRIPT_SCAN_DEFAULT": "-sC",  # Default Script Scan
    "SCRIPT_SCAN_ALL": "-sC --script all",  # All Script Scan
    "SCRIPT_SCAN_VULNERABILITY": "--script vuln",  # Vulnerability Script Scan

    # Aggressive scanning
    "AGGRESSIVE_SCAN": "-A",  # Aggressive Scan
    "OPERATING_SYSTEM_GUESS": "-O -A",  # OS and Version Detection, Aggressive

    # Web application scanning
    "HTTP_ENUMERATION": "-p80,443 --script=http-enum",  # HTTP Enumeration
    "HTTP_VULNERABILITY_SCAN": "-p80,443 --script=http-vuln*",  # HTTP Vulnerability Scan
    "HTTP_HEADERS_SCAN": "-p80,443 --script=http-headers",  # HTTP Headers Scan
    "HTTP_METHODS_SCAN": "-p80,443 --script=http-methods",  # HTTP Methods Scan
    "HTTP_ROBOTS_SCAN": "-p80,443 --script=http-robots.txt",  # HTTP Robots.txt Scan
    "HTTP_SECURITY_HEADERS_SCAN": "-p80,443 --script=http-security-headers",  # HTTP Security Headers Scan
    "HTTP_TITLE_SCAN": "-p80,443 --script=http-title",  # HTTP Title Scan

    # SSL/TLS scanning
    "SSL_VERSION_SCAN": "-p443 --script=ssl-enum-ciphers",  # SSL/TLS Version Scan
    "SSL_CERTIFICATE_SCAN": "-p443 --script=ssl-cert",  # SSL Certificate Scan
    "SSL_VULNERABILITY_SCAN": "-p443 --script=ssl-heartbleed,ssl-poodle,ssl-dh-params",  # SSL Vulnerability Scan
    "SSL_OCSP_SCAN": "-p443 --script=ssl-ocsp-stapling",  # SSL OCSP Scan

    # DNS scanning
    "DNS_ZONE_TRANSFER": "--script=dns-zone-transfer",  # DNS Zone Transfer Scan
    "DNS_ENUMERATION": "--script=dns-enum",  # DNS Enumeration

    # FTP scanning
    "FTP_BOUNCE_SCAN": "--script=ftp-bounce",  # FTP Bounce Scan

    # SMB scanning
    "SMB_ENUMERATION": "--script=smb-enum*",  # SMB Enumeration

    # SNMP scanning
    "SNMP_ENUMERATION": "--script=snmp-enum",  # SNMP Enumeration

    # SSH scanning
    "SSH_ENUMERATION": "--script=ssh-enum*",  # SSH Enumeration

    # Telnet scanning
    "TELNET_ENUMERATION": "--script=telnet-enum*",  # Telnet Enumeration

    # Nmap script scanning
    "SCRIPT_SCAN_HTTP_ENUM": "--script http-enum",  # HTTP Enumeration Script Scan
    "SCRIPT_SCAN_VULN": "--script vuln",  # Vulnerability Script Scan
    "SCRIPT_SCAN_BRUTE": "--script brute",  # Brute-force Script Scan

    # Custom TCP scanning
    "TCP_CUSTOM_SCAN": "-p{port} --script={script}",  # Custom TCP Scan

    # Custom UDP scanning
    "UDP_CUSTOM_SCAN": "-sU -p{port} --script={script}",  # Custom UDP Scan
}


def nmap_scan(target, scan_types=None, ports=None, script=None):
    try:
        scanner = nmap.PortScanner()

        # If scan_types is not specified, default to TCP_SYN_SCAN
        if not scan_types:
            scan_types = ["TCP_SYN_SCAN"]

        scan_options = []
        for scan_type in scan_types:
            if scan_type.upper() in NMAP_SCAN_TYPES:
                scan_options.append(NMAP_SCAN_TYPES[scan_type.upper()])
            else:
                return {"error": f"Invalid scan type: {scan_type}"}

        if scan_options:
            # Replace placeholders in scan_options
            if "{port}" in scan_options[0] and ports:
                scan_options[0] = scan_options[0].replace("{port}", ports)
            if "{script}" in scan_options[0] and script:
                scan_options[0] = scan_options[0].replace("{script}", script)

            # Performing the scan
            scanner.scan(hosts=target, arguments=" ".join(scan_options))

            # Extracting and parsing scan results
            parsed_results = parse_nmap_results(scanner)
            return parsed_results
        else:
            return {"error": "No valid scan types specified"}
    except Exception as e:
        return {"error": f"Nmap scan failed: {e}"}
    

def parse_nmap_results(scanner):
    parsed_results = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                service = scanner[host][proto][port]
                result = {
                    "host": host,
                    "port": port,
                    "protocol": proto,
                    "state": service["state"],
                    "name": service["name"],
                    "product": service["product"],
                    "version": service["version"],
                    "extrainfo": service["extrainfo"],
                    "reason": service["reason"],
                    "hostname": service.get("hostname", ""),
                    "http_title": service["script"]["http-title"][0] if "http-title" in service["script"] else "",
                    "http_server": service["script"]["http-server"][0] if "http-server" in service["script"] else "",
                }
                parsed_results.append(result)
    return parsed_results


def ping(target):
    target = (target)
    icmp_ping = IP(dst=target)/ICMP()
    resp = sr1(icmp_ping, timeout=2, verbose=False)
    if resp:
        print(f"{target} is reachable")
    else:
        print(f"{target} is unreachable")

       

def icmp_ping(target):
    target = (target)
    icmp_ping = IP(dst=target)/ICMP()
    resp = sr1(icmp_ping, timeout=2, verbose=False)
    if resp:
        print(f"{target} is reachable")
    else:
        print(f"{target} is unreachable")


def dns_query(target, dns_server='8.8.8.8'):
    try:
        ans = sr1(IP(dst=dns_server)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname=domain)), verbose=False)
        if ans:
            print(f"DNS query for {target} succeeded")
        else:
            print(f"DNS query for {target} failed")
    except Exception as e:
        print(f"Exception occurred: {e}")
