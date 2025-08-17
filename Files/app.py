import asyncio
import aiohttp
import aiofiles
import base64
import json
import re
import os
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote, quote, urlunparse

# --- Configuration ---
SUBSCRIPTION_LIST_FILE = "Subscription-List.txt"
OUTPUT_DIR_SPLITTED = "../Splitted-By-Protocol"
GEO_API_BATCH_URL = "http://ip-api.com/batch"
REQUEST_TIMEOUT = 20
MAX_RETRIES = 3

# --- Protocol Definitions & Validation Whitelists ---
VALID_SS_METHODS = {
    "aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305", "aes-256-cfb", "aes-128-cfb",
    "camellia-256-cfb", "camellia-128-cfb", "rc4-md5"
}
VALID_V_TRANSPORTS = {"tcp", "ws", "grpc", "kcp", "http", "xhttp"}
VALID_V_SECURITY = {"none", "tls", "reality"}
PROTOCOLS = {
    "vless": "vless://", "vmess": "vmess://", "trojan": "trojan://",
    "ss": "ss://", "ssr": "ssr://", "tuic": "tuic://", "hy2": "hy2://"
}

def is_public_ip(host):
    """Check if the host is a public IP address."""
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_global and not ip.is_private and not ip.is_reserved and not ip.is_loopback
    except ValueError:
        return True

def format_country_info(country_code):
    """Converts a country code to a 'FLAG(CODE)' format using Unicode ordinals."""
    if not isinstance(country_code, str) or len(country_code) != 2 or not country_code.isalpha():
        return "🌐(XX)"
    
    try:
        flag = chr(ord(country_code[0].upper()) - ord('A') + 0x1F1E6) + \
               chr(ord(country_code[1].upper()) - ord('A') + 0x1F1E6)
        return f"{flag}({country_code.upper()})"
    except Exception:
        return f"🌐({country_code.upper()})"

async def get_geolocation_in_batch(session, hosts):
    """Fetches geolocation for a list of public hosts using the batch API."""
    geo_cache = {}
    public_hosts = list(set([h for h in hosts if is_public_ip(h)]))
    
    payload = [{"query": h, "fields": "query,countryCode,status"} for h in public_hosts]
    chunks = [payload[i:i + 100] for i in range(0, len(payload), 100)]

    for chunk in chunks:
        for attempt in range(MAX_RETRIES):
            try:
                async with session.post(GEO_API_BATCH_URL, json=chunk, timeout=REQUEST_TIMEOUT) as response:
                    if response.status == 200:
                        data = await response.json()
                        for item in data:
                            geo_cache[item['query']] = item.get('countryCode', 'N/A') if item.get('status') == 'success' else 'N/A'
                        break
                    await asyncio.sleep(2 ** attempt)
            except (aiohttp.ClientError, asyncio.TimeoutError):
                await asyncio.sleep(2 ** attempt)
        else:
            for item in chunk:
                if item['query'] not in geo_cache:
                    geo_cache[item['query']] = 'N/A'
    return geo_cache

def parse_and_validate_config(line):
    """Parses, validates, and generates a unique key for a config link."""
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
            security = "tls" if vmess_data.get("tls") in ["tls", True] else "none"
            
            if not all([host, port, user_id]) or transport not in VALID_V_TRANSPORTS: return None, None
            
            result = {'protocol': 'vmess', 'host': host, 'port': port, 'transport': transport, 'security': security, 'data': vmess_data}
            unique_key = ("vmess", str(host).lower(), port, user_id, transport, vmess_data.get("path", ""), vmess_data.get("host", ""), security)

        elif protocol_name in ["vless", "trojan"]:
            parsed_url = urlparse(line)
            host, port, user_id = parsed_url.hostname, parsed_url.port, parsed_url.username
            if not all([host, port, user_id]): return None, None
            
            qs = parse_qs(parsed_url.query)
            transport = qs.get("type", ["tcp"])[0]
            security = qs.get("security", ["none"])[0]
            sni = qs.get("sni", [""])[0]

            if security == 'none' and sni:
                security = 'tls'

            if transport not in VALID_V_TRANSPORTS or security not in VALID_V_SECURITY: return None, None
            
            result = {'protocol': protocol_name, 'host': host, 'port': port, 'transport': transport, 'security': security, 'method': None}
            unique_key = (protocol_name, str(host).lower(), port, user_id, transport, security, qs.get("path", [""])[0], sni)

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
        
        else:
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

        all_hosts = [cfg['host'] for cfg in valid_configs]
        geo_data = await get_geolocation_in_batch(session, all_hosts)
        print(f"Geolocation fetching complete. Successfully located {sum(1 for v in geo_data.values() if v != 'N/A')} of {len(all_hosts)} hosts.")

        processed_by_protocol = {name: [] for name in PROTOCOLS.keys()}
        
        used_names = set()

        for config in valid_configs:
            country_info = format_country_info(geo_data.get(config['host'], 'N/A'))
            
            name_parts = [config['protocol'].upper()]
            if config['protocol'] in ['vless', 'vmess', 'trojan']:
                name_parts.append(config['transport'].upper())
                if config['security'] != 'none': name_parts.append(config['security'].upper())
            if config['protocol'] == 'ss' and config['method']:
                name_parts.append(config['method'].replace('-ietf', '').replace('aes-256-gcm', 'A256GCM').replace('chacha20-poly1305', 'C20P'))

            name_parts.extend([country_info, f"{config['host']}:{config['port']}"])
            
            base_name = "-".join(name_parts)
            new_name = base_name
            counter = 1
            while new_name in used_names:
                new_name = f"{base_name}_{counter}"
                counter += 1
            used_names.add(new_name)

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
            
            if config['protocol'] not in processed_by_protocol:
                processed_by_protocol[config['protocol']] = []
            processed_by_protocol[config['protocol']].append(new_line)

    print("Writing processed configs to files...")
    for protocol_name, configs in processed_by_protocol.items():
        if configs:
            file_path_plain = os.path.join(OUTPUT_DIR_SPLITTED, f"{protocol_name}.txt")
            async with aiofiles.open(file_path_plain, mode='w', encoding='utf-8') as f:
                await f.write('\n'.join(configs))
            print(f"  - Wrote {len(configs)} configs to {file_path_plain}")

    print("Processing finished successfully.")

if __name__ == "__main__":
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())