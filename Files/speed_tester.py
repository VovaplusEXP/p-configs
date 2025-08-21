import os
import json
import subprocess
import time
import requests
import psutil
import base64
from urllib.parse import urlparse, parse_qs, unquote

# --- Configuration ---
V2RAY_EXECUTABLE_PATH = "../xray" 
CONFIG_TEMPLATE_PATH = "v2ray_config_template.json"
SOURCE_DIR = "../Splitted-By-Protocol"
# Expanded list of protocols to test
PROTOCOLS_TO_TEST = ["vless.txt", "vmess.txt", "trojan.txt", "ss.txt", "hy2.txt"]

# Speed test settings
TEST_FILE_URL = "https://speed.cloudflare.com/__down?bytes=25000000" # 25MB
SPEED_THRESHOLD_MBPS = 10 # Set a threshold of 10 Mbps
REQUEST_TIMEOUT_SECONDS = 20

# Local SOCKS proxy settings
LOCAL_SOCKS_HOST = "127.0.0.1"
LOCAL_SOCKS_PORT = 10808

# --- V2Ray/Xray Config Generation ---
def create_v2ray_config(proxy_line):
    """Dynamically creates a V2Ray/Xray config for a given proxy line."""
    protocol = proxy_line.split("://")[0]
    outbound_config = None

    try:
        if protocol == "vless":
            parsed_url = urlparse(proxy_line)
            qs = parse_qs(parsed_url.query)
            outbound_config = {
                "protocol": "vless",
                "settings": {"vnext": [{"address": parsed_url.hostname, "port": parsed_url.port, "users": [{"id": parsed_url.username, "flow": qs.get("flow", [""])[0]}]}]},
                "streamSettings": {"network": qs.get("type", ["tcp"])[0], "security": qs.get("security", ["none"])[0], "tlsSettings": {"serverName": qs.get("sni", [parsed_url.hostname])[0]} if qs.get("security", ["none"])[0] == "tls" else {}, "wsSettings": {"path": qs.get("path", ["/"])[0]} if qs.get("type", ["tcp"])[0] == "ws" else {}}
        
        elif protocol == "vmess":
            b64_part = proxy_line[len("vmess://"):]
            b64_part += '=' * (-len(b64_part) % 4)
            vmess_data = json.loads(base64.b64decode(b64_part).decode('utf-8'))
            outbound_config = {
                "protocol": "vmess",
                "settings": {"vnext": [{"address": vmess_data.get("add"), "port": int(vmess_data.get("port")), "users": [{"id": vmess_data.get("id"), "alterId": int(vmess_data.get("aid"))}]}]},
                "streamSettings": {"network": vmess_data.get("net"), "security": "tls" if vmess_data.get("tls") == "tls" else "none", "tlsSettings": {"serverName": vmess_data.get("host", vmess_data.get("add"))} if vmess_data.get("tls") == "tls" else {}, "wsSettings": {"path": vmess_data.get("path", "/"), "headers": {"Host": vmess_data.get("host", vmess_data.get("add"))}} if vmess_data.get("net") == "ws" else {}}
            }

        elif protocol == "trojan":
            parsed_url = urlparse(proxy_line)
            qs = parse_qs(parsed_url.query)
            outbound_config = {
                "protocol": "trojan",
                "settings": {"servers": [{"address": parsed_url.hostname, "port": parsed_url.port, "password": parsed_url.username}]},
                "streamSettings": {"network": qs.get("type", ["tcp"])[0], "security": qs.get("security", ["none"])[0], "tlsSettings": {"serverName": qs.get("sni", [parsed_url.hostname])[0]} if qs.get("security", ["none"])[0] == "tls" else {}, "wsSettings": {"path": qs.get("path", ["/"])[0]} if qs.get("type", ["tcp"])[0] == "ws" else {}}

        elif protocol == "ss":
            parsed_url = urlparse(proxy_line)
            userinfo_b64 = parsed_url.username
            userinfo_b64 += '=' * (-len(userinfo_b64) % 4)
            userinfo = base64.b64decode(userinfo_b64).decode('utf-8')
            method, password = userinfo.split(':', 1)
            outbound_config = {
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": parsed_url.hostname, "port": parsed_url.port, "method": method, "password": password}]}
            }

        elif protocol == "hy2":
            parsed_url = urlparse(proxy_line)
            qs = parse_qs(parsed_url.query)
            outbound_config = {
                "protocol": "hysteria2",
                "settings": {"servers": [{"address": parsed_url.hostname, "port": parsed_url.port, "password": parsed_url.username}]},
                "streamSettings": {"network": "udp", "security": "tls", "tlsSettings": {"serverName": qs.get("sni", [parsed_url.hostname])[0], "alpn": ["h3"]}}
            }

    except Exception as e:
        print(f" Error parsing {protocol}: {e}")
        return None

    if not outbound_config: return None

    config = {
        "inbounds": [{"listen": LOCAL_SOCKS_HOST, "port": LOCAL_SOCKS_PORT, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [outbound_config]
    }
    
    with open(CONFIG_TEMPLATE_PATH, 'w') as f:
        json.dump(config, f)
    return CONFIG_TEMPLATE_PATH

# --- Process & Speed Test Logic ---
def kill_process_and_children(proc):
    try:
        parent = psutil.Process(proc.pid)
        for child in parent.children(recursive=True): child.kill()
        parent.kill()
    except psutil.NoSuchProcess: pass

def run_speed_test():
    proxies = {'http': f'socks5h://{LOCAL_SOCKS_HOST}:{LOCAL_SOCKS_PORT}', 'https': f'socks5h://{LOCAL_SOCKS_HOST}:{LOCAL_SOCKS_PORT}'}
    start_time = time.time()
    try:
        response = requests.get(TEST_FILE_URL, proxies=proxies, stream=True, timeout=REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status()
        duration = time.time() - start_time
        file_size_bytes = int(response.headers.get('Content-Length', 25000000))
        speed_mbps = (file_size_bytes * 8) / (duration * 1024 * 1024)
        return speed_mbps
    except (requests.exceptions.RequestException, IOError):
        return 0

# --- Main Execution ---
def main():
    if not os.path.exists(V2RAY_EXECUTABLE_PATH):
        print(f"Error: Xray executable not found at '{V2RAY_EXECUTABLE_PATH}'")
        return

    print("Starting speed test for specified protocols...")
    for filename in PROTOCOLS_TO_TEST:
        source_path = os.path.join(SOURCE_DIR, filename)
        if not os.path.exists(source_path):
            print(f"  - Source file '{source_path}' not found, skipping.")
            continue

        print(f"  - Processing '{filename}'...")
        with open(source_path, 'r', encoding='utf-8') as f:
            proxies_to_test = [line.strip() for line in f if line.strip()]
        
        fast_proxies = []
        for i, proxy_line in enumerate(proxies_to_test):
            print(f"    - Testing proxy {i+1}/{len(proxies_to_test)}...", end="", flush=True)
            
            config_file = create_v2ray_config(proxy_line)
            if not config_file:
                print(" Malformed config, skipping.")
                continue

            process = subprocess.Popen([os.path.abspath(V2RAY_EXECUTABLE_PATH), "run", "-c", config_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(3)

            speed = run_speed_test()
            kill_process_and_children(process)

            if speed > SPEED_THRESHOLD_MBPS:
                print(f" OK ({speed:.2f} Mbps)")
                fast_proxies.append(proxy_line)
            else:
                print(f" SLOW ({speed:.2f} Mbps)")
        
        if fast_proxies:
            print(f"  - Found {len(fast_proxies)} fast proxies. Overwriting '{source_path}'.")
            with open(source_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(fast_proxies))
        else:
            print(f"  - No fast proxies found for '{filename}'. The file will be empty.")
            open(source_path, 'w').close()

    if os.path.exists(CONFIG_TEMPLATE_PATH):
        os.remove(CONFIG_TEMPLATE_PATH)

    print("Speed testing complete.")

if __name__ == "__main__":
    main()