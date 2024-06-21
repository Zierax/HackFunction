import requests

import nmap
import random
import uuid
import socket
import dns.resolver
import whois
import ping3
import os
import geoip2.database
from bs4 import BeautifulSoup
import urllib.parse
import sublist3r
from scapy.all import *



USER_AGENT_STRINGS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36", 
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25", 
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A",
    "Mozilla/5.0 (X11; Mageia; Linux x86_64; rv:10.0.9) Gecko/20100101 Firefox/10.0.9",
    "Mozilla/5.0 (Android; U; Android; pl; rv:1.9.2.8) Gecko/20100202 Firefox/3.5.8", 
    "Avant Browser/1.2.789rel1 (http://www.avantbrowser.com)",
    "Baiduspider ( http://www.baidu.com/search/spider.htm)",
    "BlackBerry7100i/4.1.0 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/103",
    "BlackBerry7520/4.0.0 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Browser/5.0.3.3 UP.Link/5.1.2.12 (Google WAP Proxy/1.0)",
    "BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0",
    "BlackBerry8320/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/100",
    "BlackBerry8330/4.3.0 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/105",
    "BlackBerry9000/4.6.0.167 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/102",
]


def ping(target):
    try:
        result = ping3.ping(target)
        if result is not None:
            print(f"Ping to {target} successful. RTT: {result} ms")
        else:
            print(f"Ping to {target} failed.")
    except Exception as e:
        print(f"Error: {e}")

def traceroute(target):
    try:
        ans, unans = scapy_traceroute(target)
        for snd, rcv in ans:
            print(rcv.src)
    except Exception as e:
        print(f"Error performing traceroute: {e}")

def reversedns(target):
    try:
        result = socket.gethostbyaddr(target)
        print(f"Reverse DNS lookup for {target}: {result}")
    except Exception as e:
        print(f"Error: {e}")

def geoip(target):
    try:
        reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        response = reader.city(target)
        print(f"GeoIP lookup for {target}: {response.country.name}, {response.city.name}")
    except Exception as e:
        print(f"Error: {e}")

def whois_lookup(domain):
    try:
        whois_info = whois.whois(domain)
        print(f"WHOIS Lookup for {domain}:\n{whois_info.text}")
    except Exception as e:
        print(f"WHOIS lookup failed for {domain}: {e}")

def waybackurls(target):
    try:
        cdx_url = f"http://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&collapse=urlkey"
        response = requests.get(cdx_url)
        response.raise_for_status()
        if response.status_code == 200:
            results = response.json()
            links = set()
            for result in results:
                if len(result) > 0 and result[0].startswith("http"):
                    links.add(result[0])
            return list(links)
        else:
            print(f"Error fetching Wayback Machine data: Status Code {response.status_code}")
            return []
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return []
    except Exception as e:
        print(f"Error: {e}")

def dns_lookup(target):
    try:
        result = dns.resolver.resolve(target, 'A')
        for ipval in result:
            print(f"DNS lookup for {target}: {ipval.to_text()}")
    except Exception as e:
        print(f"Error: {e}")



# Define a dictionary to store Nmap scan types
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
                    "hostname": service["hostname"] if "hostname" in service else "",
                    "http_title": service["script"]["http-title"][0] if "http-title" in service["script"] else "",
                    "http_server": service["script"]["http-server"][0] if "http-server" in service["script"] else "",
                }
                parsed_results.append(result)

    return parsed_results



def make_request(url, method="get"):
    """Makes a request to the specified URL."""
    try:
        if method.lower() == "get":
            response = requests.get(url)
        elif method.lower() == "post":
            response = requests.post(url)
        else:
            raise ValueError(f"Invalid method: {method}")
        if response.status_code == 200:
            return response.content
        else:
            return None
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None



def generate_random_ipv6():
    return ":".join([format(random.randint(0, 0xffff), 'x') for _ in range(8)])

def generate_random_mac_address():
    mac = [ 0x00, 0x16, 0x3e, random.randint(0x00, 0x7f), random.randint(0x00, 0xff), random.randint(0x00, 0xff) ]
    return ':'.join(map(lambda x: "%02x" % x, mac))

def generate_random_uuid():
    return str(uuid.uuid4())

def extract_links(url):
    try:
        response = make_request(url, "get")
        if response:
            soup = BeautifulSoup(response, 'html.parser')
            links = soup.find_all('a', href=True)
            extracted_links = [link['href'] for link in links if link.get('href')]
            return extracted_links
        else:
            print("[Provide URL with parameters]")
            return []
    except Exception as e:
        print(f"Error extracting links from {url}: {e}")
        return []

def dns_lookup(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"DNS Lookup: {domain} -> {ip_address}")
        return ip_address
    except socket.gaierror as e:
        print(f"DNS Lookup failed for {domain}: {e}")
        return None

def geo_ip_lookup(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        data = response.json()
        if data['status'] == 'success':
            print(f"GeoIP Lookup: {ip_address} -> {data['country']}, {data['regionName']}, {data['city']}")
        else:
            print(f"GeoIP Lookup failed for {ip_address}: {data['message']}")
    except requests.RequestException as e:
        print(f"GeoIP Lookup failed for {ip_address}: {e}")

def port_scan(ip_address, ports=None):
    """Perform a port scan on specified or common ports."""
    if not ports:
        ports = [21, 22, 23, 25, 53, 80, 443, 3306, 8080]

    try:
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip_address, port))
                if result == 0:
                    print(f"Port {port}/tcp on {ip_address} is open")
                else:
                    print(f"Port {port}/tcp on {ip_address} is closed")
    except socket.error as e:
        print(f"Port scan failed for {ip_address}: {e}")

def smtp_check(email):
    try:
        domain = email.split('@')[1]
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(mx_records[0].exchange)
        response = os.system(f"nslookup {mx_record}")
        if response == 0:
            print(f"SMTP Server found for {email}")
        else:
            print(f"No SMTP Server found for {email}")
    except (IndexError, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
        print(f"SMTP check failed for {email}: {e}")
    except Exception as e:
        print(f"Error checking SMTP for {email}: {e}")

def whois_lookup(domain):
    """Perform a WHOIS lookup for a domain."""
    try:
        whois_info = whois.whois(domain)
        print(f"WHOIS Lookup for {domain}:\n{whois_info.text}")
    except Exception as e:
        print(f"WHOIS lookup failed for {domain}: {e}")
        

def dork_scan_sql(target, count):

    for i in search(target, stop=int(count)):
        print(i)
        pa = ["'", "2%5c", "2'><", "%52%4c%49%4b%45%25%32%30%28%53%45%4c%45%43%54%25%32%30%28%43%41%53%45%25%32%30%57%48%45%4e%25%32%30%30%78%36%31%36%34%36%64%36%39%36%65%25%32%30%45%4c%53%45%25%32%30%30%78%32%38%25%32%30%45%4e%44%29%29%25%32%30%41%4e%44%25%32%30%25%32%37%68%65%6a%61%62%25%32%37%3d%25%32%37"]
        for sql_check in pa:
            h = requests.get(i + sql_check)
            soup = BeautifulSoup(h.content, 'html.parser')
            if len(soup.find_all(text=re.compile("SQL syntax|Microsoft.+Database|Incorrect syntax|unterminated.+qoute"))) > 0:
                print("[SQL Found]=="+i)
                open("SQL-injection", "a").write("[SQL Found]=="+i+"\n")
            elif len(soup.find_all(text=re.compile("Warning"))) > 0:
                print("[SQL Found]=="+i)
                open("SQL-injection.txt", "a").write("[SQL Found]=="+i+"\n")
            else:
                print("[No SQL Found ]")
                
                
def google_dork_search(query, count=10, filter_word=None):
    try:
        urls = []
        query_encoded = urllib.parse.quote(query)
        google_url = f"https://www.google.com/search?q={query_encoded}&num={count}"
        
        # Select a random user-agent string
        user_agent = random.choice(USER_AGENT_STRINGS)
        headers = {"User-Agent": user_agent}

        response = requests.get(google_url, headers=headers)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        soup = BeautifulSoup(response.text, 'html.parser')
        search_results = soup.find_all('div', class_='BVG0Nb')

        for result in search_results:
            link = result.find('a')
            if link:
                url = link.get('href')
                if url.startswith('/url?q='):
                    url = url.split('/url?q=')[1].split('&sa=')[0]
                    if filter_word and filter_word.lower() not in url.lower():
                        continue  # Skip URLs not containing the filter word
                    urls.append(url)

        return urls

    except requests.RequestException as e:
        print(f"Error accessing Google search results: {e}")
        return []
    except Exception as e:
        print(f"Error performing Google dork search: {e}")
        return []
