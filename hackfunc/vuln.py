import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse, parse_qs, urljoin
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


class vuln:
    def __init__(self):
        self.session = requests.Session()

    def _make_request(self, url):
        try:
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

