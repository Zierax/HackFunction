
import requests
from bs4 import BeautifulSoup
from prettytable import PrettyTable

def make_request(target, request_type):
    try:
        if request_type == "get":
            response = requests.get(target)
        elif request_type == "post":
            response = requests.post(target)
        else:
            raise ValueError("Invalid request type")

        response.raise_for_status()
        return response.content
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return None

def domain_filter(domain, file):
    search_query = f"https://www.google.com/search?q=site:{domain}+filetype:{file}"
    print("[Searching Google]")
    try:
        response = requests.get(search_query)
        soup = BeautifulSoup(response.content, 'html.parser')
        links = soup.find_all("a")
        for link in links:
            print(link.get('href'))
    except requests.RequestException as e:
        print(f"Request failed: {e}")

def suid_exploit():
    print("[Fetching Potential SUID Exploits]")
    x = PrettyTable()
    x.field_names = ["File Path", "Exploit"]
    x.add_row(["/usr/bin/nmap", "https://gtfobins.github.io/gtfobins/nmap/"])
    x.add_row(["/usr/bin/find", "https://gtfobins.github.io/gtfobins/find/"])
    x.add_row(["/usr/bin/vim", "https://gtfobins.github.io/gtfobins/vim/"])
    x.add_row(["/usr/bin/bash", "https://gtfobins.github.io/gtfobins/bash/"])
    print(x)
