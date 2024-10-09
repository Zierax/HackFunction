import requests
from bs4 import BeautifulSoup
from prettytable import PrettyTable
import logging
from typing import Optional, Dict, Any
import aiohttp
import asyncio

logger = logging.getLogger(__name__)

async def make_request(target: str, request_type: str, headers: Optional[Dict[str, str]] = None, data: Optional[Dict[str, Any]] = None) -> Optional[bytes]:
    async with aiohttp.ClientSession() as session:
        try:
            if request_type.lower() == "get":
                async with session.get(target, headers=headers) as response:
                    response.raise_for_status()
                    return await response.read()
            elif request_type.lower() == "post":
                async with session.post(target, headers=headers, data=data) as response:
                    response.raise_for_status()
                    return await response.read()
            else:
                raise ValueError("Invalid request type")
        except aiohttp.ClientError as e:
            logger.error(f"Request failed: {e}")
            return None

async def domain_filter(domain: str, file_type: str) -> list:
    search_query = f"https://www.google.com/search?q=site:{domain}+filetype:{file_type}"
    logger.info(f"Searching Google for {domain} with file type {file_type}")
    try:
        content = await make_request(search_query, "get")
        if content:
            soup = BeautifulSoup(content, 'html.parser')
            links = soup.find_all("a")
            return [link.get('href') for link in links if link.get('href')]
        return []
    except Exception as e:
        logger.error(f"Domain filter failed: {e}")
        return []

def suid_exploit() -> PrettyTable:
    logger.info("Fetching Potential SUID Exploits")
    table = PrettyTable()
    table.field_names = ["File Path", "Exploit"]
    table.add_rows([
        ["/usr/bin/nmap", "https://gtfobins.github.io/gtfobins/nmap/"],
        ["/usr/bin/find", "https://gtfobins.github.io/gtfobins/find/"],
        ["/usr/bin/vim", "https://gtfobins.github.io/gtfobins/vim/"],
        ["/usr/bin/bash", "https://gtfobins.github.io/gtfobins/bash/"]
    ])
    return table

# Additional utility functions can be added here as needed for the project
