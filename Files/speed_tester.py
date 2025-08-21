import os
import json
import subprocess
import time
import requests
import psutil
import base64
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Configuration ---
V2RAY_EXECUTABLE_PATH = "../xray"
SOURCE_DIR = "../Splitted-By-Protocol"
PROTOCOLS_TO_TEST = ["vless.txt", "vmess.txt", "trojan.txt", "ss.txt", "hy2.txt"]

# --- Performance & Speed Test Settings ---
MAX_WORKERS = 100  # Number of proxies to test in parallel
TEST_FILE_URL = "https://speed.cloudflare.com/__down?bytes=25000000"  # 25MB
SPEED_THRESHOLD_MBPS = 10  # Set a threshold of 10 Mbps
REQUEST_TIMEOUT_SECONDS = 20
BASE_SOCKS_PORT = 10800  # Base port for workers, e.g., 10800, 10801, ...

# --- V2Ray/Xray Config Generation ---
def create_v2ray_config(proxy_line, local_socks_port, worker_id):
    """Dynamically creates a V2Ray/Xray config for a given proxy line."""
    protocol = proxy_line.split("://")[0]
    outbound_config = None
    config_path = f"v2ray_config_worker_{worker_id}.json"

    try:
        # (The parsing logic remains the same as before)
        if protocol == "vless":
            parsed_url = urlparse(proxy_line)
            qs = parse_qs(parsed_url.query)
            outbound_config = {
                "protocol": "vless",
                "settings": {"vnext": [{"address": parsed_url.hostname, "port": parsed_url.port, "users": [{"id": parsed_url.username, "flow": qs.get("flow", [""])[0]}]}]},
                "streamSettings": {"network": qs.get("type", ["tcp"])[0], "security": qs.get("security", ["none"])[0], "tlsSettings": {"serverName": qs.get("sni", [parsed_url.hostname])[0]} if qs.get("security", ["none"])[0] == "tls" else {}, "wsSettings": {"path": qs.get("path", ["/"])[0]} if qs.get("type", ["tcp"])[0] == "ws" else {}}
            }
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
            }
        elif protocol == "ss":
            parsed_url = urlparse(proxy_line)
            userinfo_b64 = parsed_url.username
            userinfo_b64 += "=" * (-len(userinfo_b64) % 4)
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
    except Exception:
        return None

    if not outbound_config: return None

    config = {
        "inbounds": [{"listen": "127.0.0.1", "port": local_socks_port, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [outbound_config]
    }
    
    with open(config_path, 'w') as f:
        json.dump(config, f)
    return config_path

# --- Worker Function ---
def kill_process_and_children(proc):
    try:
        parent = psutil.Process(proc.pid)
        for child in parent.children(recursive=True): child.kill()
        parent.kill()
    except psutil.NoSuchProcess: pass

def test_proxy(proxy_line, worker_id):
    """The core function executed by each worker thread."""
    local_socks_port = BASE_SOCKS_PORT + worker_id
    config_file = create_v2ray_config(proxy_line, local_socks_port, worker_id)
    if not config_file:
        return None, proxy_line, "Malformed"

    process = subprocess.Popen([os.path.abspath(V2RAY_EXECUTABLE_PATH), "run", "-c", config_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)  # Wait for Xray to start

    speed = 0
    try:
        proxies = {'http': f'socks5h://127.0.0.1:{local_socks_port}', 'https': f'socks5h://127.0.0.1:{local_socks_port}'}
        start_time = time.time()
        response = requests.get(TEST_FILE_URL, proxies=proxies, stream=True, timeout=REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status()
        duration = time.time() - start_time
        file_size_bytes = int(response.headers.get('Content-Length', 25000000))
        speed = (file_size_bytes * 8) / (duration * 1024 * 1024)
    except (requests.exceptions.RequestException, IOError):
        speed = 0
    finally:
        kill_process_and_children(process)
        if os.path.exists(config_file):
            os.remove(config_file)

    if speed > SPEED_THRESHOLD_MBPS:
        return speed, proxy_line, "OK"
    else:
        return speed, proxy_line, "Slow"

# --- Main Execution ---
def main():
    if not os.path.exists(V2RAY_EXECUTABLE_PATH):
        print(f"Error: Xray executable not found at '{V2RAY_EXECUTABLE_PATH}'")
        return

    print("Starting parallel speed test...")
    for filename in PROTOCOLS_TO_TEST:
        source_path = os.path.join(SOURCE_DIR, filename)
        if not os.path.exists(source_path):
            print(f"\n- Source file '{source_path}' not found, skipping.")
            continue

        print(f"\n- Processing '{filename}' with up to {MAX_WORKERS} parallel workers...")
        with open(source_path, 'r', encoding='utf-8') as f:
            proxies_to_test = [line.strip() for line in f if line.strip()]
        
        if not proxies_to_test:
            print("  - File is empty, nothing to test.")
            continue

        fast_proxies = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(test_proxy, proxy, i % MAX_WORKERS): proxy for i, proxy in enumerate(proxies_to_test)}
            
            for i, future in enumerate(as_completed(futures)):
                speed, proxy_line, status = future.result()
                if status == "OK":
                    fast_proxies.append(proxy_line)
                
                # Simple progress indicator
                print(f"\r  - Tested {i+1}/{len(proxies_to_test)} | Status: {status} ({speed:.2f} Mbps) | Fast found: {len(fast_proxies)}", end="", flush=True)

        print() # Newline after progress bar

        if fast_proxies:
            print(f"  - Found {len(fast_proxies)} fast proxies. Overwriting '{source_path}'.")
            with open(source_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(fast_proxies))
        else:
            print(f"  - No fast proxies found for '{filename}'. The file will be empty.")
            open(source_path, 'w').close()

    print("\nSpeed testing complete.")

if __name__ == "__main__":
    main()
