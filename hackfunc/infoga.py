import requests
import whois
import os
from bs4 import BeautifulSoup
import urllib.parse
import shodan
from googlesearch import search
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
import time
import logging
import censys
import builtwith
from Wappalyzer import Wappalyzer, WebPage
import theHarvester.discovery
import spyse
import hunter
import clearbit
import fullcontact
import piplapi
import requests_html
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import re
import tldextract
from tqdm import tqdm
from cryptography.fernet import Fernet
import ssl
import socket
import sublist3r
import waybackpy
from github import Github
import pastebin_scraper
from linkedin_api import Linkedin
import nmap
import dns.resolver
import socket
import ipaddress
from scapy.all import *
from bs4 import BeautifulSoup
import asyncio
import aiohttp
from aiohttp import ClientSession
import aiodns
import uvloop
from fake_useragent import UserAgent
from stem import Signal
from stem.control import Controller
import socks
import stem.process
from stem.util import term
import pydig
import dnspython
import dnstwist
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import emailhunter
import pwnedpasswords
import haveibeenpwned
import pyexifinfo
import exif
import geopy
from geopy.geocoders import Nominatim
import reverse_geocoder as rg
import folium
import shodan
import censys.certificates
import censys.ipv4
import censys.websites
from pybinaryedge import BinaryEdge
import greynoise
import virustotal_python
from OTXv2 import OTXv2
import threatcrowd
import pulsedive
from pyhunter import PyHunter
from fullcontact import FullContact
import clearbit
from spyonweb import SpyOnWeb
import builtwith
import whoxy
import passivetotal
from passivetotal.libs.dns import DnsRequest
from passivetotal.libs.whois import WhoisRequest
from passivetotal.libs.enrichment import EnrichmentRequest
import securitytrails
from securitytrails import SecurityTrails, SecurityTrailsError
import subfinder
from subfinder import subfinder
import amass
from amass import amass
import fierce
from fierce import fierce
import dnsrecon
from dnsrecon import dnsrecon
import theharvester
from theharvester import theHarvester
import metagoofil
from metagoofil import metagoofil
import maltego
from maltego import MaltegoTransform, MaltegoEntity
import recon_ng
from recon_ng import recon
import spiderfoot
from spiderfoot import SpiderFootScanner
import osint_tools
from osint_tools import *
import holehe
from holehe import core
import socialscan
from socialscan.util import Platforms, sync_execute_queries
import maigret
from maigret import search
import twint
import instaloader
import facebook_scraper
from linkedin_scraper import Person, actions
import tiktok_scraper
import reddit_scraper
from youtube_search import YoutubeSearch
import telegram_scraper
from telegram_scraper import TelegramScraper
import snapchat_scraper
from snapchat_scraper import SnapchatScraper
import whatsapp_scraper
from whatsapp_scraper import WhatsAppScraper
import skype_scraper
from skype_scraper import SkypeScraper
import zoom_scraper
from zoom_scraper import ZoomScraper
import discord_scraper
from discord_scraper import DiscordScraper
import slack_scraper
from slack_scraper import SlackScraper
import github_scraper
from github_scraper import GithubScraper
import gitlab_scraper
from gitlab_scraper import GitlabScraper
import bitbucket_scraper
from bitbucket_scraper import BitbucketScraper
import pastebin_scraper
from pastebin_scraper import PastebinScraper
import stackoverflow_scraper
from stackoverflow_scraper import StackOverflowScraper
import medium_scraper
from medium_scraper import MediumScraper
import quora_scraper
from quora_scraper import QuoraScraper
import flickr_scraper
from flickr_scraper import FlickrScraper
import pinterest_scraper
from pinterest_scraper import PinterestScraper
import tumblr_scraper
from tumblr_scraper import TumblrScraper
import vimeo_scraper
from vimeo_scraper import VimeoScraper
import dailymotion_scraper
from dailymotion_scraper import DailymotionScraper
import twitch_scraper
from twitch_scraper import TwitchScraper
import spotify_scraper
from spotify_scraper import SpotifyScraper
import soundcloud_scraper
from soundcloud_scraper import SoundCloudScraper
import behance_scraper
from behance_scraper import BehanceScraper
import dribbble_scraper
from dribbble_scraper import DribbbleScraper
import deviantart_scraper
from deviantart_scraper import DeviantArtScraper
import arxiv_scraper
from arxiv_scraper import ArxivScraper
import researchgate_scraper
from researchgate_scraper import ResearchGateScraper
import academia_scraper
from academia_scraper import AcademiaScraper
import scholar_scraper
from scholar_scraper import ScholarScraper
import patents_scraper
from patents_scraper import PatentsScraper
import crunchbase_scraper
from crunchbase_scraper import CrunchbaseScraper
import angel_scraper
from angel_scraper import AngelScraper
import producthunt_scraper
from producthunt_scraper import ProductHuntScraper
import ycombinator_scraper
from ycombinator_scraper import YCombinatorScraper
import indeed_scraper
from indeed_scraper import IndeedScraper
import glassdoor_scraper
from glassdoor_scraper import GlassdoorScraper
import monster_scraper
from monster_scraper import MonsterScraper
import careerbuilder_scraper
from careerbuilder_scraper import CareerBuilderScraper
import dice_scraper
from dice_scraper import DiceScraper
import yelp_scraper
from yelp_scraper import YelpScraper
import tripadvisor_scraper
from tripadvisor_scraper import TripAdvisorScraper
import airbnb_scraper
from airbnb_scraper import AirbnbScraper
import booking_scraper
from booking_scraper import BookingScraper
import expedia_scraper
from expedia_scraper import ExpediaScraper
import kayak_scraper
from kayak_scraper import KayakScraper
import uber_scraper
from uber_scraper import UberScraper
import lyft_scraper
from lyft_scraper import LyftScraper
import doordash_scraper
from doordash_scraper import DoorDashScraper
import grubhub_scraper
from grubhub_scraper import GrubHubScraper
import ubereats_scraper
from ubereats_scraper import UberEatsScraper
import postmates_scraper
from postmates_scraper import PostmatesScraper
import instacart_scraper
from instacart_scraper import InstacartScraper
import amazon_scraper
from amazon_scraper import AmazonScraper
import ebay_scraper
from ebay_scraper import EbayScraper
import walmart_scraper
from walmart_scraper import WalmartScraper
import target_scraper
from target_scraper import TargetScraper
import bestbuy_scraper
from bestbuy_scraper import BestBuyScraper
import homedepot_scraper
from homedepot_scraper import HomeDepotScraper
import lowes_scraper
from lowes_scraper import LowesScraper
import wayfair_scraper
from wayfair_scraper import WayfairScraper
import etsy_scraper
from etsy_scraper import EtsyScraper
import aliexpress_scraper
from aliexpress_scraper import AliExpressScraper
import wish_scraper
from wish_scraper import WishScraper
import overstock_scraper
from overstock_scraper import OverstockScraper
import newegg_scraper
from newegg_scraper import NeweggScraper
import zappos_scraper
from zappos_scraper import ZapposScraper
import nordstrom_scraper
from nordstrom_scraper import NordstromScraper
import macys_scraper
from macys_scraper import MacysScraper
import kohls_scraper
from kohls_scraper import KohlsScraper
import sephora_scraper
from sephora_scraper import SephoraScraper
import ulta_scraper
from ulta_scraper import UltaScraper
import gamestop_scraper
from gamestop_scraper import GameStopScraper
import steam_scraper
from steam_scraper import SteamScraper
import epicgames_scraper
from epicgames_scraper import EpicGamesScraper
import gog_scraper
from gog_scraper import GOGScraper
import origin_scraper
from origin_scraper import OriginScraper
import uplay_scraper
from uplay_scraper import UplayScraper
import battlenet_scraper
from battlenet_scraper import BattleNetScraper
import playstation_scraper
from playstation_scraper import PlayStationScraper
import xbox_scraper
from xbox_scraper import XboxScraper
import nintendo_scraper
from nintendo_scraper import NintendoScraper

# Set up logging with more detailed formatting
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables securely
load_dotenv()

# Securely store API keys
def encrypt_api_key(api_key):
    key = Fernet.generate_key()
    f = Fernet(key)
    return f.encrypt(api_key.encode()).decode(), key

def decrypt_api_key(encrypted_key, key):
    f = Fernet(key)
    return f.decrypt(encrypted_key.encode()).decode()

# Encrypt and store API keys
SHODAN_API_KEY, shodan_key = encrypt_api_key(os.getenv("SHODAN_API_KEY"))
CENSYS_API_ID, censys_id_key = encrypt_api_key(os.getenv("CENSYS_API_ID"))
CENSYS_API_SECRET, censys_secret_key = encrypt_api_key(os.getenv("CENSYS_API_SECRET"))
HUNTER_API_KEY, hunter_key = encrypt_api_key(os.getenv("HUNTER_API_KEY"))
CLEARBIT_API_KEY, clearbit_key = encrypt_api_key(os.getenv("CLEARBIT_API_KEY"))
FULLCONTACT_API_KEY, fullcontact_key = encrypt_api_key(os.getenv("FULLCONTACT_API_KEY"))
PIPL_API_KEY, pipl_key = encrypt_api_key(os.getenv("PIPL_API_KEY"))
VIRUSTOTAL_API_KEY, virustotal_key = encrypt_api_key(os.getenv("VIRUSTOTAL_API_KEY"))
SECURITYTRAILS_API_KEY, securitytrails_key = encrypt_api_key(os.getenv("SECURITYTRAILS_API_KEY"))
GITHUB_API_KEY, github_key = encrypt_api_key(os.getenv("GITHUB_API_KEY"))
LINKEDIN_USERNAME, linkedin_username_key = encrypt_api_key(os.getenv("LINKEDIN_USERNAME"))
LINKEDIN_PASSWORD, linkedin_password_key = encrypt_api_key(os.getenv("LINKEDIN_PASSWORD"))
BINARYEDGE_API_KEY, binaryedge_key = encrypt_api_key(os.getenv("BINARYEDGE_API_KEY"))
GREYNOISE_API_KEY, greynoise_key = encrypt_api_key(os.getenv("GREYNOISE_API_KEY"))
OTX_API_KEY, otx_key = encrypt_api_key(os.getenv("OTX_API_KEY"))
PULSEDIVE_API_KEY, pulsedive_key = encrypt_api_key(os.getenv("PULSEDIVE_API_KEY"))
SPYONWEB_API_KEY, spyonweb_key = encrypt_api_key(os.getenv("SPYONWEB_API_KEY"))
WHOXY_API_KEY, whoxy_key = encrypt_api_key(os.getenv("WHOXY_API_KEY"))
PASSIVETOTAL_API_KEY, passivetotal_key = encrypt_api_key(os.getenv("PASSIVETOTAL_API_KEY"))
SECURITYTRAILS_API_KEY, securitytrails_key = encrypt_api_key(os.getenv("SECURITYTRAILS_API_KEY"))

def advanced_whois_lookup(domain):
    """Perform an advanced WHOIS lookup with error handling, rate limiting, and multiple providers."""
    whois_results = {}
    providers = [whois, whoxy.Whoxy(decrypt_api_key(WHOXY_API_KEY, whoxy_key)), passivetotal.WhoisRequest(decrypt_api_key(PASSIVETOTAL_API_KEY, passivetotal_key))]
    
    for provider in providers:
        try:
            if isinstance(provider, whois.WhoisQuery):
                whois_info = provider.query(domain)
            elif isinstance(provider, whoxy.Whoxy):
                whois_info = provider.whois_lookup(domain)
            elif isinstance(provider, passivetotal.WhoisRequest):
                whois_info = provider.get_whois(query=domain)
            
            whois_results[provider.__class__.__name__] = whois_info
            logger.info(f"WHOIS lookup for {domain} successful using {provider.__class__.__name__}.")
            time.sleep(1)  # Rate limiting
        except Exception as e:
            logger.error(f"WHOIS lookup failed for {domain} using {provider.__class__.__name__}: {e}")
    
    return whois_results

def comprehensive_shodan_search(query):
    """Perform a comprehensive Shodan search with decryption of API key and advanced features."""
    try:
        api = shodan.Shodan(decrypt_api_key(SHODAN_API_KEY, shodan_key))
        results = api.search(query)
        
        # Additional Shodan features
        exploits = api.exploits.search(query)
        honeypots = api.honeyscore(query)
        
        logger.info(f"Comprehensive Shodan search for '{query}' successful.")
        return {
            "hosts": results['matches'],
            "exploits": exploits['matches'],
            "honeypot_score": honeypots
        }
    except Exception as e:
        logger.error(f"Comprehensive Shodan search failed: {e}")
        return {}

def multi_source_censys_search(query):
    """Perform a multi-source Censys search with decryption of API keys."""
    try:
        censys_api = censys.search.CensysHosts(
            api_id=decrypt_api_key(CENSYS_API_ID, censys_id_key),
            api_secret=decrypt_api_key(CENSYS_API_SECRET, censys_secret_key)
        )
        hosts_results = list(censys_api.search(query, per_page=100))
        
        certificates_api = censys.certificates.CensysCertificates(
            api_id=decrypt_api_key(CENSYS_API_ID, censys_id_key),
            api_secret=decrypt_api_key(CENSYS_API_SECRET, censys_secret_key)
        )
        cert_results = list(certificates_api.search(query, per_page=100))
        
        websites_api = censys.websites.CensysWebsites(
            api_id=decrypt_api_key(CENSYS_API_ID, censys_id_key),
            api_secret=decrypt_api_key(CENSYS_API_SECRET, censys_secret_key)
        )
        website_results = list(websites_api.search(query, per_page=100))
        
        logger.info(f"Multi-source Censys search for '{query}' successful.")
        return {
            "hosts": hosts_results,
            "certificates": cert_results,
            "websites": website_results
        }
    except Exception as e:
        logger.error(f"Multi-source Censys search failed: {e}")
        return {}

def advanced_google_dork_search(domain, dorks, count=10):
    """Perform Google dork searches with advanced error handling, rate limiting, and proxy rotation."""
    results = {}
    proxies = [
        'socks5://127.0.0.1:9050',  # Tor proxy
        'http://user:pass@10.10.1.10:3128',  # Example HTTP proxy
    ]
    
    for dork in dorks:
        query = f"site:{domain} {dork}"
        try:
            urls = []
            for start in range(0, count, 10):
                proxy = random.choice(proxies)
                response = requests.get(
                    f"https://www.google.com/search?q={urllib.parse.quote(query)}&start={start}",
                    headers={'User-Agent': UserAgent().random},
                    proxies={'http': proxy, 'https': proxy},
                    timeout=10
                )
                soup = BeautifulSoup(response.text, 'html.parser')
                search_results = soup.select('.yuRUbf > a')
                urls.extend([result['href'] for result in search_results])
                time.sleep(random.uniform(2, 5))  # Random delay between requests
            
            results[dork] = urls[:count]
            logger.info(f"Google dork search for '{dork}' on {domain} successful.")
        except Exception as e:
            logger.error(f"Google dork search failed for '{dork}': {e}")
            results[dork] = []
    
    return results

def comprehensive_technology_detection(url):
    """Detect technologies used by the website with extended capabilities and multiple sources."""
    try:
        results = {}
        
        # Builtwith
        results['builtwith'] = builtwith.parse(url)
        
        # Wappalyzer
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url)
        results['wappalyzer'] = wappalyzer.analyze_with_versions_and_categories(webpage)
        
        # Custom technology checks
        results['custom_checks'] = custom_technology_checks(url)
        
        # Additional sources
        results['whatcms'] = whatcms_detection(url)
        results['retire_js'] = retire_js_detection(url)
        results['httpx'] = httpx_detection(url)
        
        logger.info(f"Comprehensive technology detection for {url} successful.")
        return results
    except Exception as e:
        logger.error(f"Comprehensive technology detection failed: {e}")
        return None

def custom_technology_checks(url):
    """Perform custom technology checks."""
    custom_techs = {}
    try:
        response = requests.get(url, timeout=10)
        if 'X-Powered-By' in response.headers:
            custom_techs['X-Powered-By'] = response.headers['X-Powered-By']
        if 'Server' in response.headers:
            custom_techs['Server'] = response.headers['Server']
        if 'X-AspNet-Version' in response.headers:
            custom_techs['ASP.NET'] = response.headers['X-AspNet-Version']
        
        # Check for common JavaScript libraries
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script['src'].lower()
            if 'jquery' in src:
                custom_techs['jQuery'] = 'Detected'
            elif 'angular' in src:
                custom_techs['Angular'] = 'Detected'
            elif 'react' in src:
                custom_techs['React'] = 'Detected'
            elif 'vue' in src:
                custom_techs['Vue.js'] = 'Detected'
        
        # Check for common CMS
        if 'wp-content' in response.text:
            custom_techs['WordPress'] = 'Detected'
        elif 'Drupal.settings' in response.text:
            custom_techs['Drupal'] = 'Detected'
        elif 'Joomla!' in response.text:
            custom_techs['Joomla'] = 'Detected'
        
    except Exception as e:
        logger.error(f"Custom technology check failed: {e}")
    return custom_techs

def advanced_email_harvesting(domain):
    """Harvest email addresses associated with the domain using multiple techniques and sources."""
    try:
        emails = set()
        
        # TheHarvester
        harvester = theHarvester.discovery.TheHarvester(domain)
        harvester.process()
        emails.update(harvester.get_emails())
        
        # Hunter.io
        hunter_api = hunter.HunterApi(decrypt_api_key(HUNTER_API_KEY, hunter_key))
        hunter_results = hunter_api.domain_search(domain)
        if hunter_results and 'emails' in hunter_results:
            emails.update([email['value'] for email in hunter_results['emails']])
        
        # Clearbit
        clearbit.key = decrypt_api_key(CLEARBIT_API_KEY, clearbit_key)
        clearbit_results = clearbit.Prospector.search(domain=domain, limit=100)
        emails.update([result['email'] for result in clearbit_results if 'email' in result])
        
        # Custom email harvesting techniques
        custom_emails = custom_email_harvest(domain)
        emails.update(custom_emails)
        
        # Email verification
        verified_emails = verify_emails(list(emails))
        
        logger.info(f"Advanced email harvesting for {domain} successful.")
        return verified_emails
    except Exception as e:
        logger.error(f"Advanced email harvesting failed: {e}")
        return []

def custom_email_harvest(domain):
    """Custom email harvesting function."""
    emails = set()
    try:
        # Web scraping
        response = requests.get(f"http://{domain}", timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails.update(re.findall(email_regex, soup.text))
        
        # DNS MX record check
        mx_records = dns.resolver.resolve(domain, 'MX')
        for mx in mx_records:
            emails.add(f"postmaster@{mx.exchange.to_text().rstrip('.')}")
        
        # WHOIS data
        whois_info = whois.whois(domain)
        if whois_info.emails:
            emails.update(whois_info.emails)
        
        # Google search
        search_query = f"@{domain}"
        for url in search(search_query, num_results=20):
            response = requests.get(url, timeout=10)
            emails.update(re.findall(email_regex, response.text))
        
    except Exception as e:
        logger.error(f"Custom email harvest failed: {e}")
    return emails

def verify_emails(email_list):
    """Verify harvested email addresses."""
    verified_emails = []
    for email in email_list:
        try:
            # DNS check
            domain = email.split('@')[1]
            dns.resolver.resolve(domain, 'MX')
            
            # SMTP check (be cautious with this to avoid being blocked)
            # This is a simplified example and should be used carefully
            with smtplib.SMTP(domain) as server:
                server.ehlo()
                server.mail('')
                code, _ = server.rcpt(email)
                if code == 250:
                    verified_emails.append(email)
        except Exception:
            pass
    return verified_emails

def comprehensive_domain_info(domain):
    """Gather comprehensive domain information from multiple sources."""
    results = {}
    
    # Spyse
    try:
        client = spyse.Client()
        results['spyse'] = client.get_domain_details(domain)
        time.sleep(1)  # Rate limiting
    except Exception as e:
        logger.error(f"Spyse domain info gathering failed: {e}")
    
    # SecurityTrails
    try:
        st = SecurityTrails(decrypt_api_key(SECURITYTRAILS_API_KEY, securitytrails_key))
        results['securitytrails'] = st.domain_info(domain)
    except Exception as e:
        logger.error(f"SecurityTrails domain info gathering failed: {e}")
    
    # VirusTotal
    try:
        vt = virustotal_python.Virustotal(decrypt_api_key(VIRUSTOTAL_API_KEY, virustotal_key))
        results['virustotal'] = vt.domain_report(domain)
    except Exception as e:
        logger.error(f"VirusTotal domain info gathering failed: {e}")
    
    # RiskIQ PassiveTotal
    try:
        client = passivetotal.Client(decrypt_api_key(PASSIVETOTAL_API_KEY, passivetotal_key))
        results['passivetotal'] = client.get_enrichment(query=domain)
    except Exception as e:
        logger.error(f"PassiveTotal domain info gathering failed: {e}")
    
    logger.info(f"Comprehensive domain info gathering for {domain} completed.")
    return results

def advanced_ssl_info(domain):
    """Gather advanced SSL certificate information."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()
        
        # Additional SSL checks
        cert_details = {}
        cert_details['subject'] = dict(x[0] for x in cert['subject'])
        cert_details['issuer'] = dict(x[0] for x in cert['issuer'])
        cert_details['version'] = cert['version']
        cert_details['serialNumber'] = cert['serialNumber']
        cert_details['notBefore'] = cert['notBefore']
        cert_details['notAfter'] = cert['notAfter']
        cert_details['subjectAltName'] = cert.get('subjectAltName', [])
        cert_details['OCSP'] = cert.get('OCSP', [])
        cert_details['caIssuers'] = cert.get('caIssuers', [])
        cert_details['crlDistributionPoints'] = cert.get('crlDistributionPoints', [])
        
        # Check certificate transparency
        ct_logs = requests.get(f"https://crt.sh/?q={domain}&output=json").json()
        cert_details['certificate_transparency'] = ct_logs[:10]  # Limit to first 10 entries
        
        # Check for known vulnerabilities
        vulnerabilities = check_ssl_vulnerabilities(domain)
        cert_details['vulnerabilities'] = vulnerabilities
        
        logger.info(f"Advanced SSL info gathering for {domain} successful.")
        return cert_details
    except Exception as e:
        logger.error(f"Advanced SSL info gathering failed: {e}")
        return None

def check_ssl_vulnerabilities(domain):
    """Check for known SSL/TLS vulnerabilities."""
    vulnerabilities = []
    try:
        # Check for Heartbleed
        heartbleed = subprocess.run(['sslyze', '--heartbleed', domain], capture_output=True, text=True)
        if 'VULNERABLE' in heartbleed.stdout:
            vulnerabilities.append('Heartbleed')
        
        # Check for POODLE
        poodle = subprocess.run(['sslyze', '--fallback', domain], capture_output=True, text=True)
        if 'VULNERABLE' in poodle.stdout:
            vulnerabilities.append('POODLE')
        
        # Check for FREAK
        freak = subprocess.run(['sslyze', '--freak', domain], capture_output=True, text=True)
        if 'VULNERABLE' in freak.stdout:
            vulnerabilities.append('FREAK')
        
        # Add more vulnerability checks as needed
    except Exception as e:
        logger.error(f"SSL vulnerability check failed: {e}")
    
    return vulnerabilities

def comprehensive_subdomain_enumeration(domain):
    """Enumerate subdomains using multiple tools and techniques."""
    subdomains = set()
    
    # Sublist3r
    subdomains.update(sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None))
    
    # Amass
    amass_output = subprocess.run(['amass', 'enum', '-d', domain], capture_output=True, text=True)
    subdomains.update(amass_output.stdout.splitlines())
    
    # Subfinder
    subfinder_output = subprocess.run(['subfinder', '-d', domain], capture_output=True, text=True)
    subdomains.update(subfinder_output.stdout.splitlines())
    
    # Asynchronous DNS brute-force
    wordlist = load_subdomain_wordlist()
    brute_force_subdomains = asyncio.run(async_dns_brute_force(domain, wordlist))
    subdomains.update(brute_force_subdomains)
    
    # Censys subdomain enumeration
    censys_subdomains = censys_subdomain_enum(domain)
    subdomains.update(censys_subdomains)
    
    # Certificate Transparency logs
    ct_subdomains = certificate_transparency_enum(domain)
    subdomains.update(ct_subdomains)
    
    logger.info(f"Comprehensive subdomain enumeration for {domain} completed.")
