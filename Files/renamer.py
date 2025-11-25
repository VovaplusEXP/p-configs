import requests
import json
import base64
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urlparse, quote, urlunparse
import re
from parsers import Proxy, parse_proxy

# --- Configuration ---
GEO_API_URL = "http://ip-api.com/json/?fields=status,countryCode"
REQUEST_SOCKET_TIMEOUT_SECONDS = 5

def format_country_info(country_code: Optional[str]) -> str:
    """Formats a country code into a flag emoji and (XX) format."""
    if not isinstance(country_code, str) or len(country_code) != 2 or not country_code.isalpha():
        return "🌐(XX)"
    try:
        flag = chr(ord(country_code[0].upper()) - ord('A') + 0x1F1E6) + \
               chr(ord(country_code[1].upper()) - ord('A') + 0x1F1E6)
        return f"{flag}({country_code.upper()})"
    except Exception:
        return f"🌐({country_code.upper()})"

def get_geo_info(proxy_dict: Dict[str, str]) -> str:
    """Fetches country code for a given proxy configuration."""
    try:
        response = requests.get(GEO_API_URL, proxies=proxy_dict, timeout=REQUEST_SOCKET_TIMEOUT_SECONDS)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return data.get("countryCode", "N/A")
    except requests.exceptions.RequestException:
        pass
    return "N/A"

def rename_proxy(proxy: Proxy, country_code: str, used_names: Set[str]) -> str:
    """Generates a new, unique name for a proxy."""
    country_info = format_country_info(country_code)

    name_parts: List[str] = [proxy.protocol.upper()]
    if proxy.protocol in ['vless', 'vmess', 'trojan']:
        name_parts.append(proxy.transport.upper())
        if proxy.security != 'none': name_parts.append(proxy.security.upper())

    name_parts.append(country_info)
    name_parts.append(proxy.host) # Add host for more uniqueness

    base_name = "-".join(name_parts)
    new_name = base_name
    counter = 1
    while new_name in used_names:
        new_name = f"{base_name}_{counter}"
        counter += 1

    used_names.add(new_name)
    return new_name
