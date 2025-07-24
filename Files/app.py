import asyncio
import aiohttp
import aiofiles
import base64
import json
import re
import os
import emoji
from urllib.parse import urlparse, parse_qs, unquote, quote, urlunparse

# --- Configuration ---
SUBSCRIPTION_LIST_FILE = "Subscription-List.txt"
OUTPUT_DIR_SPLITTED = "../Splitted-By-Protocol"
OUTPUT_FILE_ALL_SUB = "../All_Configs_Sub.txt"
GEO_API_URL = "http://ip-api.com/json/"
REQUEST_TIMEOUT = 10  # seconds

# --- Protocol Definitions & Validation Whitelists ---
# Using sets for efficient lookups
VALID_SS_METHODS = {
    "aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305", 
    "xchacha20-ietf-poly1305", "aes-256-cfb", "aes-128-cfb",
    "camellia-256-cfb", "camellia-128-cfb", "rc4-md5" # rc4-md5 is old but still seen
}
VALID_V_TRANSPORTS = {"tcp", "ws", "grpc", "kcp", "http"}
PROTOCOLS = {
    "vless": "vless://", "vmess": "vmess://", "trojan": "trojan://",
    "ss": "ss://", "ssr": "ssr://", "tuic": "tuic://", "hy2": "hy2://"
}

# --- In-memory Caches ---
geo_cache = {}
config_parse_cache = {}

def get_flag(country_code):
    """Converts a country code to a flag emoji."""
    return emoji.emojize(f":{country_code.upper()}:", language='alias') if country_code and country_code != "N/A" else "❓"

async def get_geolocation(session, host):
    """Fetches geolocation for a host, using a cache."""
    if host in geo_cache:
        return geo_cache[host]
    try:
        async with session.get(f"{GEO_API_URL}{host}?fields=countryCode,query", timeout=REQUEST_TIMEOUT) as response:
            if response.status == 200:
                data = await response.json()
                country_code = data.get("countryCode", "N/A")
                geo_cache[host] = country_code
                return country_code
            geo_cache[host] = "N/A"
            return "N/A"
    except (aiohttp.ClientError, asyncio.TimeoutError):
        geo_cache[host] = "N/A"
        return "N/A"

def parse_and_validate_config(line):
    """
    Parses and validates a config link. 
    Returns a dictionary with parsed info or None if invalid.
    """
    line = line.strip()
    if not line or line in config_parse_cache:
        return config_parse_cache.get(line)

    protocol_name = next((name for name, prefix in PROTOCOLS.items() if line.startswith(prefix)), None)
    if not protocol_name:
        config_parse_cache[line] = None
        return None

    result = None
    try:
        if protocol_name == "vmess":
            decoded_json = base64.b64decode(line[len("vmess://"):]).decode('utf-8')
            vmess_data = json.loads(decoded_json)
            host = vmess_data.get("add")
            port = vmess_data.get("port")
            transport = vmess_data.get("net", "tcp")
            if not host or not port or transport not in VALID_V_TRANSPORTS:
                raise ValueError("Invalid VMess fields")
            result = {'protocol': 'vmess', 'host': host, 'port': port, 'transport': transport, 'method': None}

        elif protocol_name in ["vless", "trojan"]:
            parsed_url = urlparse(line)
            host = parsed_url.hostname
            port = parsed_url.port
            if not host or not port:
                raise ValueError("Missing host or port")
            qs = parse_qs(parsed_url.query)
            transport = qs.get("type", ["tcp"])[0]
            if transport not in VALID_V_TRANSPORTS:
                raise ValueError(f"Invalid transport: {transport}")
            result = {'protocol': protocol_name, 'host': host, 'port': port, 'transport': transport, 'method': None}

        elif protocol_name == "ss":
            parsed_url = urlparse(line)
            host = parsed_url.hostname
            port = parsed_url.port
            if not host or not port:
                raise ValueError("Missing host or port")
            
            # Userinfo can be base64 encoded or plain
            try:
                userinfo = base64.b64decode(parsed_url.username + "==").decode('utf-8')
            except:
                userinfo = unquote(parsed_url.username)

            method = userinfo.split(':', 1)[0]
            if method not in VALID_SS_METHODS:
                raise ValueError(f"Invalid SS method: {method}")
            result = {'protocol': 'ss', 'host': host, 'port': port, 'transport': 'tcp', 'method': method}
        
        elif protocol_name in ["hy2", "tuic", "ssr"]: # Basic validation for these
            parsed_url = urlparse(line)
            host = parsed_url.hostname
            port = parsed_url.port
            if not host or not port:
                raise ValueError("Missing host or port")
            result = {'protocol': protocol_name, 'host': host, 'port': port, 'transport': 'udp', 'method': None}

    except Exception:
        config_parse_cache[line] = None
        return None

    if result:
        result['original_line'] = line
        config_parse_cache[line] = result
        return result
    
    config_parse_cache[line] = None
    return None

async def fetch_subs_and_deduplicate(session, unique_configs):
    """Reads subscription list, fetches configs, and deduplicates them."""
    try:
        async with aiofiles.open(SUBSCRIPTION_LIST_FILE, mode='r', encoding='utf-8') as f:
            urls = [line.strip() for line in await f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"Warning: {SUBSCRIPTION_LIST_FILE} not found. No configs will be fetched.")
        return

    async def fetch(url):
        try:
            async with session.get(url, timeout=REQUEST_TIMEOUT) as response:
                if response.status == 200:
                    content = await response.text()
                    try:
                        decoded_content = base64.b64decode(content).decode('utf-8')
                        for config_line in decoded_content.splitlines():
                            unique_configs.add(config_line.strip())
                    except Exception:
                        for config_line in content.splitlines():
                            unique_configs.add(config_line.strip())
        except Exception as e:
            print(f"Warning: Error fetching {url}: {e}")

    await asyncio.gather(*(fetch(url) for url in urls))

async def main():
    print("Starting config processing...")
    os.makedirs(OUTPUT_DIR_SPLITTED, exist_ok=True)
    
    unique_configs_raw = set()
    async with aiohttp.ClientSession() as session:
        await fetch_subs_and_deduplicate(session, unique_configs_raw)
        print(f"Found {len(unique_configs_raw)} unique raw configs. Starting validation...")

        valid_configs = [parsed for line in unique_configs_raw if (parsed := parse_and_validate_config(line)) is not None]
        print(f"Validation complete. {len(valid_configs)} configs are valid.")

        geo_tasks = [get_geolocation(session, cfg['host']) for cfg in valid_configs]
        print(f"Fetching geolocation for {len(valid_configs)} hosts...")
        geo_results = await asyncio.gather(*geo_tasks)
        print("Geolocation fetching complete.")

        processed_by_protocol = {name: [] for name in PROTOCOLS.keys()}
        all_processed_configs = []

        for i, config in enumerate(valid_configs):
            country_code = geo_results[i]
            flag = get_flag(country_code)
            
            name_parts = [config['protocol'].upper()]
            if config['protocol'] in ['vless', 'vmess', 'trojan'] and config['transport'] != 'tcp':
                name_parts.append(config['transport'].upper())
            if config['protocol'] == 'ss' and config['method']:
                # Shorten common SS method names for clarity
                short_method = config['method'].replace('-ietf', '').replace('aes-256-gcm', 'A256GCM').replace('chacha20-poly1305', 'C20P')
                name_parts.append(short_method)

            name_parts.extend([flag, f"{config['host']}:{config['port']}"])
            new_name = "-".join(name_parts)
            
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
