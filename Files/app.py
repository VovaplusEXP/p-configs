import asyncio
import aiohttp
import aiofiles
import base64
import json
import os
from urllib.parse import urlparse, parse_qs, unquote

# --- Configuration ---
SUBSCRIPTION_LIST_FILE = "Subscription-List.txt"
OUTPUT_DIR_SPLITTED = "../Splitted-By-Protocol"
REQUEST_TIMEOUT = 20

# --- Protocol Definitions & Validation Whitelists ---
VALID_SS_METHODS = {
    "aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305", "aes-256-cfb", "aes-128-cfb",
    "camellia-256-cfb", "camellia-128-cfb", "rc4-md5"
}
VALID_V_TRANSPORTS = {"tcp", "ws", "grpc", "kcp", "http", "xhttp"}
PROTOCOLS = {
    "vless": "vless://", "vmess": "vmess://", "trojan": "trojan://",
    "ss": "ss://", "ssr": "ssr://", "tuic": "tuic://", "hy2": "hy2://"
}

def parse_and_validate_config(line):
    """Parses, validates, and generates a unique key for a config link."""
    line = line.strip()
    if not line:
        return None, None

    protocol_name = next((name for name, prefix in PROTOCOLS.items() if line.startswith(prefix)), None)
    if not protocol_name:
        return None, None

    unique_key = None
    try:
        if protocol_name == "vmess":
            vmess_json_str = base64.b64decode(line[len("vmess://"):]).decode('utf-8')
            vmess_data = json.loads(vmess_json_str)
            host, port, user_id = vmess_data.get("add"), vmess_data.get("port"), vmess_data.get("id")
            transport = vmess_data.get("net", "tcp")
            security = "tls" if vmess_data.get("tls") in ["tls", True] else "none"
            if not all([host, port, user_id]) or transport not in VALID_V_TRANSPORTS:
                return None, None
            unique_key = ("vmess", str(host).lower(), port, user_id, transport, vmess_data.get("path", ""), vmess_data.get("host", ""), security)

        elif protocol_name in ["vless", "trojan"]:
            parsed_url = urlparse(line)
            host, port, user_id = parsed_url.hostname, parsed_url.port, parsed_url.username
            if not all([host, port, user_id]):
                return None, None
            qs = parse_qs(parsed_url.query)
            transport = qs.get("type", ["tcp"])[0]
            security = qs.get("security", ["none"])[0]
            sni = qs.get("sni", [""])[0]
            if transport not in VALID_V_TRANSPORTS:
                return None, None
            unique_key = (protocol_name, str(host).lower(), port, user_id, transport, security, qs.get("path", [""])[0], sni)

        elif protocol_name == "ss":
            parsed_url = urlparse(line)
            host, port = parsed_url.hostname, parsed_url.port
            if not host or not port:
                return None, None
            try:
                userinfo = base64.b64decode(parsed_url.username + "==").decode('utf-8')
            except Exception:
                userinfo = unquote(parsed_url.username)
            method, password = userinfo.split(':', 1)
            if method not in VALID_SS_METHODS:
                return None, None
            unique_key = ("ss", str(host).lower(), port, method, password)
        
        else: # For tuic, hy2, etc.
            parsed_url = urlparse(line)
            host, port, user_id = parsed_url.hostname, parsed_url.port, parsed_url.username
            if not all([host, port, user_id]):
                return None, None
            unique_key = (protocol_name, str(host).lower(), port, user_id)

    except Exception:
        return None, None

    return (protocol_name, line), unique_key

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
                    try:
                        lines = base64.b64decode(content).decode('utf-8').splitlines()
                    except Exception:
                        lines = content.splitlines()
                    
                    for line in lines:
                        parsed_result, unique_key = parse_and_validate_config(line)
                        if parsed_result and unique_key not in unique_configs_map:
                            unique_configs_map[unique_key] = parsed_result
        except Exception as e:
            print(f"Warning: Error fetching {url}: {e}")

    await asyncio.gather(*(fetch(url) for url in urls))

async def main():
    print("Starting raw config fetching and deduplication...")
    os.makedirs(OUTPUT_DIR_SPLITTED, exist_ok=True)
    
    unique_configs_map = {}
    async with aiohttp.ClientSession() as session:
        await fetch_subs(session, unique_configs_map)
        
    valid_configs = list(unique_configs_map.values())
    print(f"Found {len(valid_configs)} unique and valid configs.")

    # Group configs by protocol
    processed_by_protocol = {name: [] for name in PROTOCOLS.keys()}
    for protocol_name, original_line in valid_configs:
        if protocol_name in processed_by_protocol:
            processed_by_protocol[protocol_name].append(original_line)

    print("Writing raw deduplicated configs to files...")
    for protocol_name, configs in processed_by_protocol.items():
        if configs:
            file_path_plain = os.path.join(OUTPUT_DIR_SPLITTED, f"{protocol_name}.txt")
            async with aiofiles.open(file_path_plain, mode='w', encoding='utf-8') as f:
                await f.write('\n'.join(configs))
            print(f"  - Wrote {len(configs)} configs to {file_path_plain}")

    print("Fetching finished successfully.")

if __name__ == "__main__":
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
