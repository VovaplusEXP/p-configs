import asyncio
import aiohttp
import aiofiles
import base64
import json
import re
import os
import emoji # Moved to top-level for global visibility
from urllib.parse import urlparse, parse_qs, unquote, quote, urlunparse

# --- Configuration ---
SUBSCRIPTION_LIST_FILE = "Subscription-List.txt"
OUTPUT_DIR_SPLITTED = "../Splitted-By-Protocol"
OUTPUT_FILE_ALL_SUB = "../All_Configs_Sub.txt"
GEO_API_URL = "http://ip-api.com/json/"
REQUEST_TIMEOUT = 10  # seconds
GEO_API_CONCURRENCY = 40 # Max concurrent requests
MAX_RETRIES = 3 # Max retries for Geo API

# --- Protocol Definitions & Validation Whitelists ---
VALID_SS_METHODS = {
    "aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305", "aes-256-cfb", "aes-128-cfb",
    "camellia-256-cfb", "camellia-128-cfb", "rc4-md5"
}
VALID_V_TRANSPORTS = {"tcp", "ws", "grpc", "kcp", "http"}
VALID_V_SECURITY = {"none", "tls", "reality"}
PROTOCOLS = {
    "vless": "vless://", "vmess": "vmess://", "trojan": "trojan://",
    "ss": "ss://", "ssr": "ssr://", "tuic": "tuic://", "hy2": "hy2://"
}

# --- In-memory Caches ---
geo_cache = {}

def get_flag(country_code):
    """Converts a country code to a flag emoji."""
    if not country_code or country_code == "N/A":
        return "❓"
    return emoji.emojize(f":{country_code.upper()}:")

async def get_geolocation_with_retry(session, host, semaphore):
    """Fetches geolocation with retries and exponential backoff."""
    if host in geo_cache:
        return geo_cache[host]

    async with semaphore:
        for attempt in range(MAX_RETRIES):
            try:
                async with session.get(f"{GEO_API_URL}{host}?fields=countryCode,query", timeout=REQUEST_TIMEOUT) as response:
                    if response.status == 200:
                        data = await response.json()
                        country_code = data.get("countryCode", "N/A")
                        geo_cache[host] = country_code
                        return country_code
                    # If rate-limited or other server error, prepare to retry
                    if response.status in [429, 500, 502, 503, 504]:
                        await asyncio.sleep(2 ** attempt) # Exponential backoff: 1, 2, 4s
                        continue
                    # For other client errors, don't retry
                    break
            except (aiohttp.ClientError, asyncio.TimeoutError):
                await asyncio.sleep(2 ** attempt)
    
    geo_cache[host] = "N/A" # Cache failure to avoid retrying for the same host
    return "N/A"

def parse_and_validate_config(line):
    """
    Parses, validates, and generates a unique key for a config link.
    Returns a dictionary with parsed info and the key, or None.
    """
    line = line.strip()
    if not line: return None, None

    protocol_name = next((name for name, prefix in PROTOCOLS.items() if line.startswith(prefix)), None)
    if not protocol_name: return None, None

    result = {}
    unique_key = None
    try:
        if protocol_name == "vmess":
            vmess_json_str = base64.b64decode(line[len("vmess://"):]).decode('utf-8')
            vmess_data = json.loads(vmess_json_str)
            host, port, user_id = vmess_data.get("add"), vmess_data.get("port"), vmess_data.get("id")
            transport = vmess_data.get("net", "tcp")
            
            if not all([host, port, user_id]) or transport not in VALID_V_TRANSPORTS: return None, None
            
            result = {'protocol': 'vmess', 'host': host, 'port': port, 'transport': transport, 'data': vmess_data}
            unique_key = ("vmess", str(host).lower(), port, user_id, transport, vmess_data.get("path", ""), vmess_data.get("host", ""))

        elif protocol_name in ["vless", "trojan"]:
            parsed_url = urlparse(line)
            host, port, user_id = parsed_url.hostname, parsed_url.port, parsed_url.username
            if not all([host, port, user_id]): return None, None
            
            qs = parse_qs(parsed_url.query)
            transport = qs.get("type", ["tcp"])[0]
            security = qs.get("security", ["none"])[0]
            if transport not in VALID_V_TRANSPORTS or security not in VALID_V_SECURITY: return None, None
            
            result = {'protocol': protocol_name, 'host': host, 'port': port, 'transport': transport, 'security': security, 'method': None}
            unique_key = (protocol_name, str(host).lower(), port, user_id, transport, security, qs.get("path", [""])[0], qs.get("sni", [""])[0])

        elif protocol_name == "ss":
            parsed_url = urlparse(line)
            host, port = parsed_url.hostname, parsed_url.port
            if not host or not port: return None, None
            
            try: userinfo = base64.b64decode(parsed_url.username + "==").decode('utf-8')
            except: userinfo = unquote(parsed_url.username)
            
            method, password = userinfo.split(':', 1)
            if method not in VALID_SS_METHODS: return None, None
            
            result = {'protocol': 'ss', 'host': host, 'port': port, 'transport': 'tcp', 'security': 'none', 'method': method}
            unique_key = ("ss", str(host).lower(), port, method, password)
        
        else: # Basic validation for other protocols
            parsed_url = urlparse(line)
            host, port, user_id = parsed_url.hostname, parsed_url.port, parsed_url.username
            if not all([host, port, user_id]): return None, None
            result = {'protocol': protocol_name, 'host': host, 'port': port, 'transport': 'udp', 'security': 'none', 'method': None}
            unique_key = (protocol_name, str(host).lower(), port, user_id)

    except Exception: return None, None

    if result:
        result['original_line'] = line
        return result, unique_key
    return None, None

async def fetch_subs(session, unique_configs_map):
    """Fetches configs and performs smart deduplication."""
    try:
        async with aiofiles.open(SUBSCRIPTION_LIST_FILE, mode='r', encoding='utf-8') as f:
            urls = [line.strip() for line in await f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"Warning: {SUBSCRIPTION_LIST_FILE} not found.")
        return

    async def fetch(url):
        try:
            async with session.get(url, timeout=REQUEST_TIMEOUT) as response:
                if response.status == 200:
                    content = await response.text()
                    try: lines = base64.b64decode(content).decode('utf-8').splitlines()
                    except: lines = content.splitlines()
                    
                    for line in lines:
                        parsed_config, unique_key = parse_and_validate_config(line)
                        if parsed_config and unique_key not in unique_configs_map:
                            unique_configs_map[unique_key] = parsed_config
        except Exception as e: print(f"Warning: Error fetching {url}: {e}")

    await asyncio.gather(*(fetch(url) for url in urls))

async def main():
    print("Starting config processing...")
    os.makedirs(OUTPUT_DIR_SPLITTED, exist_ok=True)
    
    unique_configs_map = {}
    async with aiohttp.ClientSession() as session:
        await fetch_subs(session, unique_configs_map)
        
        valid_configs = list(unique_configs_map.values())
        print(f"Found {len(valid_configs)} unique and valid configs. Starting geolocation...")

        semaphore = asyncio.Semaphore(GEO_API_CONCURRENCY)
        geo_tasks = [get_geolocation_with_retry(session, cfg['host'], semaphore) for cfg in valid_configs]
        geo_results = await asyncio.gather(*geo_tasks)
        print("Geolocation fetching complete.")

        processed_by_protocol = {name: [] for name in PROTOCOLS.keys()}
        all_processed_configs = []

        for i, config in enumerate(valid_configs):
            country_code = geo_results[i]
            flag = get_flag(country_code)
            
            name_parts = [config['protocol'].upper()]
            if config['protocol'] in ['vless', 'trojan']:
                name_parts.append(config['transport'].upper())
                if config['security'] != 'none': name_parts.append(config['security'].upper())
            if config['protocol'] == 'ss' and config['method']:
                name_parts.append(config['method'].replace('-ietf', '').replace('aes-256-gcm', 'A256GCM').replace('chacha20-poly1305', 'C20P'))

            name_parts.extend([flag, f"{config['host']}:{config['port']}"])
            new_name = "-".join(name_parts)
            
            # --- Correctly generate final config link ---
            if config['protocol'] == 'vmess':
                vmess_data = config['data']
                vmess_data['ps'] = new_name
                new_json_str = json.dumps(vmess_data, sort_keys=True)
                new_line = "vmess://" + base64.b64encode(new_json_str.encode('utf-8')).decode('utf-8')
            else:
                try:
                    parts = list(urlparse(config['original_line']))
                    parts[5] = quote(new_name)
                    new_line = urlunparse(parts)
                except Exception:
                    new_line = re.sub(r'#.*', '', config['original_line']) + '#' + quote(new_name)
            
            processed_by_protocol[config['protocol']].append(new_line)
            all_processed_configs.append(new_line)

    print("Writing processed configs to files...")
    for protocol_name, configs in processed_by_protocol.items():
        if configs:
            file_path = os.path.join(OUTPUT_DIR_SPLITTED, f"{protocol_name}.txt")
            async with aiofiles.open(file_path, mode='w', encoding='utf-8') as f:
                await f.write('\n'.join(configs))
            print(f"  - Wrote {len(configs)} configs to {file_path}")

    if all_processed_configs:
        async with aiofiles.open(OUTPUT_FILE_ALL_SUB, mode='w', encoding='utf-8') as f:
            combined_text = '\n'.join(all_processed_configs)
            encoded_bytes = base64.b64encode(combined_text.encode('utf-8'))
            await f.write(encoded_bytes.decode('utf-8'))
        print(f"Wrote {len(all_processed_configs)} configs to {OUTPUT_FILE_ALL_SUB} (Base64 encoded).")

    print("Processing finished successfully.")

if __name__ == "__main__":
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
