import os
import json
import subprocess
import time
import requests
import base64
import re
import signal
from urllib.parse import urlparse, quote, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional
from parsers import parse_proxy, Proxy

# --- Configuration ---
V2RAY_EXECUTABLE_PATH = "../xray"
SOURCE_DIR = "../Splitted-By-Protocol"
PROTOCOLS_TO_TEST = ["vless.txt", "vmess.txt", "trojan.txt", "ss.txt", "hy2.txt", "tuic.txt"]

# --- Performance & Speed Test Settings ---
MAX_WORKERS = 100
BASE_SOCKS_PORT = 10800
SPEED_THRESHOLD_MBPS = 20
TEST_FILE_URL = "https://speed.cloudflare.com/__down?bytes=10000000"  # 10MB

# --- Timeouts ---
MAX_TEST_DURATION_SECONDS = 10
REQUEST_SOCKET_TIMEOUT_SECONDS = 5
STARTUP_WAIT_SECONDS = 7.5

# --- Geo & Naming ---
GEO_API_URL = "http://ip-api.com/json/?fields=status,countryCode"

# --- Helper Functions ---
def format_country_info(country_code: Optional[str]) -> str:
    if not isinstance(country_code, str) or len(country_code) != 2 or not country_code.isalpha():
        return "🌐(XX)"
    try:
        flag = chr(ord(country_code[0].upper()) - ord('A') + 0x1F1E6) + \
               chr(ord(country_code[1].upper()) - ord('A') + 0x1F1E6)
        return f"{flag}({country_code.upper()})"
    except Exception:
        return f"🌐({country_code.upper()})"

# --- V2Ray/Xray Config Generation ---
def create_v2ray_config(proxy: Proxy, local_socks_port: int, task_id: int) -> Optional[str]:
    config_path = f"v2ray_config_task_{task_id}.json"
    outbound_config: Optional[Dict[str, Any]] = None

    try:
        stream_settings: Dict[str, Any] = {"network": proxy.transport, "security": proxy.security}
        
        if proxy.transport == "ws":
            stream_settings["wsSettings"] = {"path": proxy.ws_path or "/", "headers": {"Host": proxy.ws_host or proxy.host}}
        elif proxy.transport == "grpc":
            stream_settings["grpcSettings"] = {"serviceName": proxy.grpc_service_name or ""}

        if proxy.security == "tls":
            stream_settings["tlsSettings"] = {"serverName": proxy.sni or proxy.host, "allowInsecure": True}
        elif proxy.security == "reality":
            if not proxy.publicKey: return None
            stream_settings["realitySettings"] = {"serverName": proxy.sni or proxy.host, "publicKey": proxy.publicKey, "shortId": proxy.shortId or "", "fingerprint": proxy.fingerprint or "chrome", "allowInsecure": True}

        if proxy.protocol == "vless":
            user_obj: Dict[str, Any] = {"id": proxy.uuid, "encryption": "none", "flow": proxy.flow or "", "level": 0}
            outbound_config = {"protocol": "vless", "settings": {"vnext": [{"address": proxy.host, "port": proxy.port, "users": [user_obj]}]}, "streamSettings": stream_settings}
        elif proxy.protocol == "trojan":
            outbound_config = {"protocol": "trojan", "settings": {"servers": [{"address": proxy.host, "port": proxy.port, "password": proxy.uuid, "level": 0}]}, "streamSettings": stream_settings}
        elif proxy.protocol == "vmess":
            outbound_config = {"protocol": "vmess", "settings": {"vnext": [{"address": proxy.host, "port": proxy.port, "users": [{"id": proxy.uuid, "alterId": proxy.alterId, "security": proxy.vmess_cipher, "level": 0}]}]}, "streamSettings": stream_settings}
        elif proxy.protocol == "ss":
            outbound_config = {"protocol": "shadowsocks", "settings": {"servers": [{"address": proxy.host, "port": proxy.port, "method": proxy.method, "password": proxy.password, "level": 0}]}}
        elif proxy.protocol in ["hy2", "tuic"]:
             outbound_config = {"protocol": proxy.protocol, "settings": {"servers": [{"address": proxy.host, "port": proxy.port, "password": proxy.uuid, "level": 0}]}, "streamSettings": {"network": "udp", "security": "tls", "tlsSettings": {"serverName": proxy.sni or proxy.host, "alpn": ["h3"], "allowInsecure": True}}}
    except Exception:
        return None
    if not outbound_config: return None
    
    rate_limit_kibps = 9155

    config: Dict[str, Any] = {
        "log": {"loglevel": "error"},
        "policy": {
            "levels": {
                "0": {
                    "downlinkOnly": rate_limit_kibps
                }
            }
        },
        "inbounds": [{"listen": "127.0.0.1", "port": local_socks_port, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [outbound_config]
    }
    with open(config_path, 'w') as f: json.dump(config, f)
    return config_path

# --- Worker Functions ---
def test_proxy(proxy: Proxy, task_id: int) -> Dict[str, Any]:
    local_socks_port = BASE_SOCKS_PORT + task_id
    config_file = create_v2ray_config(proxy, local_socks_port, task_id)
    if not config_file:
        return {"status": "Malformed", "speed": 0, "proxy": proxy}

    process = subprocess.Popen([os.path.abspath(V2RAY_EXECUTABLE_PATH), "run", "-c", config_file], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, 
                               preexec_fn=os.setsid)
    
    try:
        time.sleep(STARTUP_WAIT_SECONDS)

        proxies = {'http': f'socks5h://127.0.0.1:{local_socks_port}', 'https': f'socks5h://127.0.0.1:{local_socks_port}'}
        
        exit_country = "N/A"
        try:
            geo_resp = requests.get(GEO_API_URL, proxies=proxies, timeout=REQUEST_SOCKET_TIMEOUT_SECONDS)
            if geo_resp.status_code == 200:
                geo_data = geo_resp.json()
                if geo_data.get("status") == "success":
                    exit_country = geo_data.get("countryCode", "N/A")
        except requests.exceptions.RequestException:
            pass

        start_time = time.time()
        downloaded_bytes = 0
        with requests.get(TEST_FILE_URL, proxies=proxies, stream=True, timeout=REQUEST_SOCKET_TIMEOUT_SECONDS) as response:
            response.raise_for_status()
            for chunk in response.iter_content(chunk_size=512 * 1024):
                if time.time() - start_time > MAX_TEST_DURATION_SECONDS:
                    break
                downloaded_bytes += len(chunk)

        duration = time.time() - start_time
        final_speed = (downloaded_bytes * 8) / (duration * 1024 * 1024) if duration > 0 else 0
        
        if final_speed > SPEED_THRESHOLD_MBPS:
            return {"status": "OK", "speed": final_speed, "proxy": proxy, "country": exit_country}
        else:
            return {"status": "Slow", "speed": final_speed, "proxy": proxy}

    except requests.exceptions.RequestException:
        return {"status": "Error", "speed": 0, "proxy": proxy}
    except Exception:
        return {"status": "Unknown Error", "speed": 0, "proxy": proxy}
    finally:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        
        if os.path.exists(config_file):
            os.remove(config_file)

# --- Main Execution ---
def main():
    if not os.path.exists(V2RAY_EXECUTABLE_PATH):
        print(f"Error: Xray executable not found at '{V2RAY_EXECUTABLE_PATH}'")
        return
        
    all_fast_proxies: Dict[str, List[Dict[str, Any]]] = {proto.replace('.txt', ''): [] for proto in PROTOCOLS_TO_TEST}
    
    print("Starting parallel speed test and geolocation...")
    for filename in PROTOCOLS_TO_TEST:
        source_path = os.path.join(SOURCE_DIR, filename)
        if not os.path.exists(source_path):
            print(f"\n- Source file '{source_path}' not found, skipping.")
            continue
            
        with open(source_path, 'r', encoding='utf-8') as f:
            proxies_to_test = [parse_proxy(line) for line in f if line.strip()]
        
        proxies_to_test = [p for p in proxies_to_test if p is not None]
        if not proxies_to_test:
            print(f"\n- File '{filename}' is empty or contains no valid configs, nothing to test.")
            continue
            
        print(f"\n- Processing '{filename}' with up to {MAX_WORKERS} parallel workers...")
        
        protocol_fast_proxies: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(test_proxy, proxy, i): proxy for i, proxy in enumerate(proxies_to_test)}
            for i, future in enumerate(as_completed(futures)):
                result = future.result()
                if result and result.get("status") == "OK":
                    protocol_fast_proxies.append(result)
                
                status_str = result.get('status', 'Malformed')
                speed_str = f"{result.get('speed', 0):.2f} Mbps"
                print(f"\r  - Tested {i+1}/{len(proxies_to_test)} | Status: {status_str} ({speed_str}) | Fast found: {len(protocol_fast_proxies)}   ", end="", flush=True)
        
        print()
        if protocol_fast_proxies:
            protocol_fast_proxies.sort(key=lambda x: x.get('speed', 0), reverse=True)
            proto_name = filename.replace('.txt', '')
            all_fast_proxies[proto_name] = protocol_fast_proxies
            print(f"  - Found {len(protocol_fast_proxies)} fast proxies for {proto_name}.")
        else:
            print(f"  - No fast proxies found for '{filename}'.")

    print("\nRenaming configs with real exit country and writing to files...")
    used_names: set[str] = set()
    for protocol_name, fast_proxies in all_fast_proxies.items():
        if not fast_proxies:
            open(os.path.join(SOURCE_DIR, f"{protocol_name}.txt"), 'w').close()
            continue

        renamed_proxies: List[str] = []
        for proxy_data in fast_proxies:
            proxy = proxy_data.get("proxy")
            if not isinstance(proxy, Proxy): continue

            country_info = format_country_info(proxy_data.get('country', 'N/A'))
            
            name_parts: List[str] = [proxy.protocol.upper()]
            if proxy.protocol in ['vless', 'vmess', 'trojan']:
                name_parts.append(proxy.transport.upper())
                if proxy.security != 'none': name_parts.append(proxy.security.upper())
            if proxy.protocol == 'ss' and proxy.method:
                name_parts.append(proxy.method.replace('-ietf', '').replace('aes-256-gcm', 'A256GCM').replace('chacha20-poly1305', 'C20P'))
            
            name_parts.append(country_info)
            
            base_name = "-".join(name_parts)
            new_name = base_name
            counter = 1
            while new_name in used_names:
                new_name = f"{base_name}_{counter}"
                counter += 1
            used_names.add(new_name)

            new_line = ""
            if proxy.protocol == 'vmess':
                vmess_data = proxy.vmess_data
                vmess_data['ps'] = new_name
                new_json_str = json.dumps(vmess_data, sort_keys=True)
                new_line = "vmess://" + base64.b64encode(new_json_str.encode('utf-8')).decode('utf-8')
            else:
                try:
                    parts = list(urlparse(proxy.original_line))
                    parts[5] = quote(new_name)
                    new_line = urlunparse(parts)
                except Exception:
                    new_line = re.sub(r'#.*', '', proxy.original_line) + '#' + quote(new_name)
            
            if new_line:
                renamed_proxies.append(new_line)
        
        final_path = os.path.join(SOURCE_DIR, f"{protocol_name}.txt")
        with open(final_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(renamed_proxies))
        print(f"  - Wrote {len(renamed_proxies)} renamed configs to {final_path}")

    print("\nProcessing complete.")

if __name__ == "__main__":
    main()