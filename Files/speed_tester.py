
import os
import json
import subprocess
import time
import requests
import psutil
import base64
import socket
import re
import signal
from urllib.parse import urlparse, parse_qs, unquote, quote, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

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
# Total maximum duration for the speed test part of a proxy test
MAX_TEST_DURATION_SECONDS = 10
# Socket-level timeout (for requests)
REQUEST_SOCKET_TIMEOUT_SECONDS = 5
# How long to wait for xray to start
STARTUP_WAIT_SECONDS = 7.5

# --- Geo & Naming ---
GEO_API_URL = "http://ip-api.com/json/?fields=status,countryCode"
VALID_SS_METHODS = {
    "aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305", "aes-256-cfb", "aes-128-cfb",
    "camellia-256-cfb", "camellia-128-cfb", "rc4-md5"
}
VALID_V_TRANSPORTS = {"tcp", "ws", "grpc", "kcp", "http", "xhttp"}
VALID_V_SECURITY = {"none", "tls", "reality"}

# --- Helper Functions ---
def format_country_info(country_code):
    if not isinstance(country_code, str) or len(country_code) != 2 or not country_code.isalpha():
        return "🌐(XX)"
    try:
        flag = chr(ord(country_code[0].upper()) - ord('A') + 0x1F1E6) + \
               chr(ord(country_code[1].upper()) - ord('A') + 0x1F1E6)
        return f"{flag}({country_code.upper()})"
    except Exception:
        return f"🌐({country_code.upper()})"

def parse_and_validate_config(line):
    line = line.strip()
    if not line: return None
    
    protocol_name = next((name for name, prefix in {'vless': 'vless://', 'vmess': 'vmess://', 'trojan': 'trojan://', 'ss': 'ss://', 'ssr': 'ssr://', 'tuic': 'tuic://', 'hy2': 'hy2://'}.items() if line.startswith(prefix)), None)
    if not protocol_name: return None

    result = {}
    try:
        if protocol_name == "vmess":
            vmess_json_str = base64.b64decode(line[len("vmess://"):]).decode('utf-8')
            vmess_data = json.loads(vmess_json_str)
            host, port, user_id = vmess_data.get("add"), vmess_data.get("port"), vmess_data.get("id")
            transport = vmess_data.get("net", "tcp")
            security = "tls" if vmess_data.get("tls") in ["tls", True] else "none"
            if not all([host, port, user_id]) or transport not in VALID_V_TRANSPORTS: return None
            result = {'protocol': 'vmess', 'host': host, 'port': port, 'transport': transport, 'security': security, 'data': vmess_data}
        elif protocol_name in ["vless", "trojan"]:
            parsed_url = urlparse(line)
            host, port, user_id = parsed_url.hostname, parsed_url.port, parsed_url.username
            if not all([host, port, user_id]): return None
            qs = parse_qs(parsed_url.query)
            transport = qs.get("type", ["tcp"])[0]
            security = qs.get("security", ["none"])[0]
            if security == 'none' and qs.get("sni"): security = 'tls'
            if transport not in VALID_V_TRANSPORTS or security not in VALID_V_SECURITY: return None
            result = {'protocol': protocol_name, 'host': host, 'port': port, 'transport': transport, 'security': security, 'method': None}
        elif protocol_name == "ss":
            parsed_url = urlparse(line)
            host, port = parsed_url.hostname, parsed_url.port
            if not host or not port: return None
            try: userinfo = base64.b64decode(parsed_url.username + "==").decode('utf-8')
            except: userinfo = unquote(parsed_url.username)
            method, password = userinfo.split(':', 1)
            if method not in VALID_SS_METHODS: return None
            result = {'protocol': 'ss', 'host': host, 'port': port, 'transport': 'tcp', 'security': 'none', 'method': method}
        else: # tuic, hy2
            parsed_url = urlparse(line)
            host, port, user_id = parsed_url.hostname, parsed_url.port, parsed_url.username
            if not all([host, port, user_id]): return None
            result = {'protocol': protocol_name, 'host': host, 'port': port, 'transport': 'udp', 'security': 'none', 'method': None}
    except Exception: return None
    
    if result:
        result['original_line'] = line
        return result
    return None

# --- V2Ray/Xray Config Generation ---
def create_v2ray_config(proxy_line, local_socks_port, task_id):
    protocol = proxy_line.split("://")[0]
    outbound_config = None
    config_path = f"v2ray_config_task_{task_id}.json"
    try:
        parsed_url = urlparse(proxy_line)
        qs = parse_qs(parsed_url.query)
        security = qs.get("security", ["none"])[0]
        network_type = qs.get("type", ["tcp"])[0]

        stream_settings = {"network": network_type, "security": security}
        
        if network_type == "ws":
            stream_settings["wsSettings"] = {"path": qs.get("path", ["/"])[0], "headers": {"Host": qs.get("host", [qs.get("sni", [parsed_url.hostname])[0]])[0]}}
        elif network_type == "grpc":
            stream_settings["grpcSettings"] = {"serviceName": qs.get("serviceName", [""])[0]}

        if security == "tls":
            stream_settings["tlsSettings"] = {"serverName": qs.get("sni", [parsed_url.hostname])[0], "allowInsecure": True}
        elif security == "reality":
            pbk = qs.get("pbk", [""])[0]; sid = qs.get("sid", [""])[0]
            if not pbk: return None
            stream_settings["realitySettings"] = {"serverName": qs.get("sni", [parsed_url.hostname])[0], "publicKey": pbk, "shortId": sid, "fingerprint": qs.get("fp", ["chrome"])[0], "allowInsecure": True}

        if protocol == "vless":
            user_obj = {"id": parsed_url.username, "encryption": "none", "flow": qs.get("flow", [""])[0]}
            outbound_config = {"protocol": "vless", "settings": {"vnext": [{"address": parsed_url.hostname, "port": parsed_url.port, "users": [user_obj]}]}, "streamSettings": stream_settings}
        elif protocol == "trojan":
            outbound_config = {"protocol": "trojan", "settings": {"servers": [{"address": parsed_url.hostname, "port": parsed_url.port, "password": parsed_url.username}]}, "streamSettings": stream_settings}
        elif protocol == "vmess":
            vmess_data = json.loads(base64.b64decode(proxy_line[len("vmess://"):]).decode())
            vmess_stream_settings = {"network": vmess_data.get("net", "tcp"), "security": "tls" if vmess_data.get("tls") == "tls" else "none"}
            if vmess_stream_settings["network"] == "ws":
                vmess_stream_settings["wsSettings"] = {"path": vmess_data.get("path", "/"), "headers": {"Host": vmess_data.get("host", vmess_data.get("add"))}}
            if vmess_stream_settings["security"] == "tls":
                vmess_stream_settings["tlsSettings"] = {"serverName": vmess_data.get("host", vmess_data.get("add")), "allowInsecure": True}
            outbound_config = {"protocol": "vmess", "settings": {"vnext": [{"address": vmess_data.get("add"), "port": int(vmess_data.get("port")), "users": [{"id": vmess_data.get("id"), "alterId": int(vmess_data.get("aid")), "security": vmess_data.get("scy", "auto")}]}]}, "streamSettings": vmess_stream_settings}
        elif protocol == "ss":
            userinfo = base64.b64decode(unquote(parsed_url.username) + "==").decode()
            method, password = userinfo.split(':', 1)
            outbound_config = {"protocol": "shadowsocks", "settings": {"servers": [{"address": parsed_url.hostname, "port": parsed_url.port, "method": method, "password": password}]}}
        elif protocol == "hy2" or protocol == "tuic":
             outbound_config = {"protocol": protocol, "settings": {"servers": [{"address": parsed_url.hostname, "port": parsed_url.port, "password": parsed_url.username}]}, "streamSettings": {"network": "udp", "security": "tls", "tlsSettings": {"serverName": qs.get("sni", [parsed_url.hostname])[0], "alpn": ["h3"], "allowInsecure": True}}}
    except Exception: return None
    if not outbound_config: return None
    
    config = {
        "log": {"loglevel": "error"},
        "inbounds": [{"listen": "127.0.0.1", "port": local_socks_port, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [outbound_config]
    }
    with open(config_path, 'w') as f: json.dump(config, f)
    return config_path

# --- Worker Functions ---
def test_proxy(proxy_line, task_id):
    local_socks_port = BASE_SOCKS_PORT + task_id
    config_file = create_v2ray_config(proxy_line, local_socks_port, task_id)
    if not config_file:
        return None

    process = subprocess.Popen([os.path.abspath(V2RAY_EXECUTABLE_PATH), "run", "-c", config_file], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, 
                               preexec_fn=os.setsid)
    
    try:
        # Wait for SOCKS5 server to be ready
        time.sleep(STARTUP_WAIT_SECONDS)

        proxies = {'http': f'socks5h://127.0.0.1:{local_socks_port}', 'https': f'socks5h://127.0.0.1:{local_socks_port}'}
        
        # 1. Get Exit IP Country
        exit_country = "N/A"
        try:
            geo_resp = requests.get(GEO_API_URL, proxies=proxies, timeout=REQUEST_SOCKET_TIMEOUT_SECONDS)
            if geo_resp.status_code == 200:
                geo_data = geo_resp.json()
                if geo_data.get("status") == "success":
                    exit_country = geo_data.get("countryCode", "N/A")
        except requests.exceptions.RequestException:
            pass  # Could not determine country, will use N/A

        # 2. Perform Speed Test with manual total duration timeout
        start_time = time.time()
        downloaded_bytes = 0
        with requests.get(TEST_FILE_URL, proxies=proxies, stream=True, timeout=REQUEST_SOCKET_TIMEOUT_SECONDS) as response:
            response.raise_for_status()
            for chunk in response.iter_content(chunk_size=512 * 1024): # 512KB chunks
                if time.time() - start_time > MAX_TEST_DURATION_SECONDS:
                    break # Test duration exceeded
                downloaded_bytes += len(chunk)

        duration = time.time() - start_time
        
        if duration > 0:
            final_speed = (downloaded_bytes * 8) / (duration * 1024 * 1024)
        else:
            final_speed = 0
        
        if final_speed > SPEED_THRESHOLD_MBPS:
            return {"status": "OK", "speed": final_speed, "line": proxy_line, "country": exit_country}
        else:
            return {"status": "Slow", "speed": final_speed, "line": proxy_line}

    except requests.exceptions.RequestException:
        return {"status": "Error", "speed": 0, "line": proxy_line}
    except Exception:
        return {"status": "Unknown Error", "speed": 0, "line": proxy_line}
    finally:
        # Kill the entire process group gracefully
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass # Process might have already died
        
        if os.path.exists(config_file):
            os.remove(config_file)

# --- Main Execution ---
def main():
    if not os.path.exists(V2RAY_EXECUTABLE_PATH):
        print(f"Error: Xray executable not found at '{V2RAY_EXECUTABLE_PATH}'")
        return
        
    all_fast_proxies = {proto.replace('.txt', ''): [] for proto in PROTOCOLS_TO_TEST}
    
    print("Starting parallel speed test and geolocation...")
    for filename in PROTOCOLS_TO_TEST:
        source_path = os.path.join(SOURCE_DIR, filename)
        if not os.path.exists(source_path):
            print(f"\n- Source file '{source_path}' not found, skipping.")
            continue
            
        with open(source_path, 'r', encoding='utf-8') as f:
            proxies_to_test = [line.strip() for line in f if line.strip()]
        if not proxies_to_test:
            print(f"\n- File '{filename}' is empty, nothing to test.")
            continue
            
        print(f"\n- Processing '{filename}' with up to {MAX_WORKERS} parallel workers...")
        
        protocol_fast_proxies = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Pass the global index 'i' as the task_id for unique port allocation
            futures = {executor.submit(test_proxy, proxy, i): proxy for i, proxy in enumerate(proxies_to_test)}
            for i, future in enumerate(as_completed(futures)):
                result = future.result()
                if result and result["status"] == "OK":
                    protocol_fast_proxies.append(result)
                
                status_str = result['status'] if result else 'Malformed'
                speed_str = f"{result['speed']:.2f} Mbps" if result and 'speed' in result else ''
                print(f"\r  - Tested {i+1}/{len(proxies_to_test)} | Status: {status_str} ({speed_str}) | Fast found: {len(protocol_fast_proxies)}   ", end="", flush=True)
        
        print()
        if protocol_fast_proxies:
            # Sort by speed, descending
            protocol_fast_proxies.sort(key=lambda x: x['speed'], reverse=True)
            proto_name = filename.replace('.txt', '')
            all_fast_proxies[proto_name] = protocol_fast_proxies
            print(f"  - Found {len(protocol_fast_proxies)} fast proxies for {proto_name}.")
        else:
            print(f"  - No fast proxies found for '{filename}'.")

    print("\nRenaming configs with real exit country and writing to files...")
    used_names = set()
    for protocol_name, fast_proxies in all_fast_proxies.items():
        if not fast_proxies:
            # Overwrite with empty file if no fast proxies were found
            open(os.path.join(SOURCE_DIR, f"{protocol_name}.txt"), 'w').close()
            continue

        renamed_proxies = []
        for proxy_data in fast_proxies:
            config = parse_and_validate_config(proxy_data['line'])
            if not config: continue

            country_info = format_country_info(proxy_data.get('country', 'N/A'))
            
            name_parts = [config['protocol'].upper()]
            if config['protocol'] in ['vless', 'vmess', 'trojan']:
                name_parts.append(config['transport'].upper())
                if config['security'] != 'none': name_parts.append(config['security'].upper())
            if config['protocol'] == 'ss' and config['method']:
                name_parts.append(config['method'].replace('-ietf', '').replace('aes-256-gcm', 'A256GCM').replace('chacha20-poly1305', 'C20P'))
            
            # Add speed to name
            name_parts.append(f"{proxy_data['speed']:.0f}Mbps")
            name_parts.append(country_info)
            
            base_name = "-".join(name_parts)
            new_name = base_name
            counter = 1
            while new_name in used_names:
                new_name = f"{base_name}_{counter}"
                counter += 1
            used_names.add(new_name)

            new_line = ""
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
            
            if new_line:
                renamed_proxies.append(new_line)
        
        # Overwrite the source file with the new, fast, renamed proxies
        final_path = os.path.join(SOURCE_DIR, f"{protocol_name}.txt")
        with open(final_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(renamed_proxies))
        print(f"  - Wrote {len(renamed_proxies)} renamed configs to {final_path}")

    print("\nProcessing complete.")

if __name__ == "__main__":
    main()
