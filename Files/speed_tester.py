import os
import json
import subprocess
import time
import requests
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional, Tuple
from parsers import parse_proxy, Proxy

# --- Configuration ---
XRAY_EXECUTABLE_PATH = "xray"
SOURCE_DIR = "Temp"
OUTPUT_DIR = "Temp"
# Protocols will be discovered dynamically based on files ending with '_to_test.txt'

# --- Performance & Speed Test Settings ---
MAX_WORKERS = 100
BASE_SOCKS_PORT = 10800
SPEED_THRESHOLD_MBPS = 20  # Restored threshold
TEST_FILE_URL = "https://speed.cloudflare.com/__down?bytes=10000000"  # 10MB

# --- Timeouts ---
MAX_TEST_DURATION_SECONDS = 10
REQUEST_SOCKET_TIMEOUT_SECONDS = 5
STARTUP_WAIT_SECONDS = 5.0

# --- IPv6 Test Settings ---
IPV6_TEST_URL = "https://[2606:4700:4700::1111]/" # Cloudflare's IPv6-only service
IPV6_TIMEOUT_SECONDS = 3

def test_ipv6_connectivity(proxies: Dict[str, str]) -> bool:
    """Test IPv6 connectivity through the proxy."""
    try:
        response = requests.get(IPV6_TEST_URL, proxies=proxies, timeout=IPV6_TIMEOUT_SECONDS)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

# --- Xray Config Generation ---
def create_xray_config(proxy: Proxy, local_socks_port: int, task_id: int) -> Optional[str]:
    """Creates a minimal Xray JSON config for a given proxy."""
    config_path = f"xray_config_task_{task_id}.json"
    outbound_config: Optional[Dict[str, Any]] = None

    try:
        stream_settings: Dict[str, Any] = {"network": proxy.transport, "security": proxy.security}
        
        if proxy.transport == "ws":
            stream_settings["wsSettings"] = {"path": proxy.ws_path or "/", "headers": {"Host": proxy.ws_host or proxy.host}}
        elif proxy.transport == "grpc":
            stream_settings["grpcSettings"] = {"serviceName": proxy.grpc_service_name or ""}

        if proxy.security == "tls":
            stream_settings["tlsSettings"] = {"serverName": proxy.sni or proxy.host, "allowInsecure": False}
        elif proxy.security == "reality":
            if not proxy.publicKey: return None
            stream_settings["realitySettings"] = {"serverName": proxy.sni or proxy.host, "publicKey": proxy.publicKey, "shortId": proxy.shortId or "", "fingerprint": proxy.fingerprint or "chrome"}

        if proxy.protocol == "vless":
            user_obj: Dict[str, Any] = {"id": proxy.uuid, "encryption": "none", "flow": proxy.flow or ""}
            outbound_config = {"protocol": "vless", "settings": {"vnext": [{"address": proxy.host, "port": proxy.port, "users": [user_obj]}]}, "streamSettings": stream_settings}
        elif proxy.protocol == "trojan":
            outbound_config = {"protocol": "trojan", "settings": {"servers": [{"address": proxy.host, "port": proxy.port, "password": proxy.uuid}]}}
        elif proxy.protocol == "vmess":
            outbound_config = {"protocol": "vmess", "settings": {"vnext": [{"address": proxy.host, "port": proxy.port, "users": [{"id": proxy.uuid, "alterId": proxy.alterId, "security": proxy.vmess_cipher}]}]}}
        elif proxy.protocol == "ss":
            outbound_config = {"protocol": "shadowsocks", "settings": {"servers": [{"address": proxy.host, "port": proxy.port, "method": proxy.method, "password": proxy.password}]}}
        elif proxy.protocol in ["hy2", "tuic"]:
             outbound_config = {"protocol": proxy.protocol, "settings": {"servers": [{"address": proxy.host, "port": proxy.port, "password": proxy.uuid}]}, "streamSettings": {"network": "udp", "security": "tls", "tlsSettings": {"serverName": proxy.sni or proxy.host, "alpn": ["h3"]}}}

    except Exception: return None
    if not outbound_config: return None
    
    config: Dict[str, Any] = {
        "log": {"loglevel": "warn"},
        "inbounds": [{"listen": "127.0.0.1", "port": local_socks_port, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [outbound_config]
    }
    with open(config_path, 'w') as f: json.dump(config, f)
    return config_path

# --- Worker Function ---
def test_proxy(proxy: Proxy, task_id: int) -> Tuple[bool, float, Proxy]:
    """
    Tests a single proxy configuration for IPv6 and speed.
    Returns a tuple: (has_ipv6, speed_mbps, original_proxy_object).
    """
    local_socks_port = BASE_SOCKS_PORT + task_id
    config_file = create_xray_config(proxy, local_socks_port, task_id)
    if not config_file:
        return (False, 0.0, proxy)

    process = subprocess.Popen([os.path.abspath(XRAY_EXECUTABLE_PATH), "run", "-c", config_file],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, 
                               preexec_fn=os.setsid)
    
    has_ipv6 = False
    final_speed = 0.0

    try:
        time.sleep(STARTUP_WAIT_SECONDS)
        proxies = {'http': f'socks5h://127.0.0.1:{local_socks_port}', 'https': f'socks5h://127.0.0.1:{local_socks_port}'}
        
        # Test 1: IPv6 connectivity
        has_ipv6 = test_ipv6_connectivity(proxies)
        
        # Test 2: Speed test
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

    except requests.exceptions.RequestException:
        pass # Errors are handled by speed being 0.0
    except Exception:
        pass # Catch any other errors
    finally:
        try:
            if process.poll() is None:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        if os.path.exists(config_file):
            os.remove(config_file)

    return (has_ipv6, final_speed, proxy)

# --- Main Execution ---
def main():
    if not os.path.exists(XRAY_EXECUTABLE_PATH):
        print(f"Error: Xray executable not found at '{XRAY_EXECUTABLE_PATH}'")
        return
        
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    protocols_to_test = [f for f in os.listdir(SOURCE_DIR) if f.endswith('_to_test.txt')]
    
    print("Starting parallel speed test and geolocation...")

    for filename in protocols_to_test:
        source_path = os.path.join(SOURCE_DIR, filename)
        protocol_name = filename.replace('_to_test.txt', '')
            
        with open(source_path, 'r', encoding='utf-8') as f:
            proxies_to_test = [parse_proxy(line) for line in f if line.strip()]
        
        proxies_to_test = [p for p in proxies_to_test if p is not None]
        if not proxies_to_test:
            print(f"\n- No valid configs found in '{filename}', skipping.")
            continue
            
        print(f"\n- Processing '{protocol_name}.txt' with up to {MAX_WORKERS} parallel workers...")
        
        passed_proxies: List[str] = []
        tested_count = 0
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(test_proxy, proxy, i): proxy for i, proxy in enumerate(proxies_to_test)}
            for future in as_completed(futures):
                tested_count += 1
                has_ipv6, speed_mbps, result_proxy = future.result()

                status_msg = ""
                is_ok = False

                if not has_ipv6:
                    status_msg = "No IPv6"
                elif speed_mbps < SPEED_THRESHOLD_MBPS:
                    status_msg = "Too slow"
                else:
                    status_msg = "OK"
                    is_ok = True

                if is_ok:
                    passed_proxies.append(result_proxy.original_line)
                
                print(f"\r  - Tested {tested_count}/{len(proxies_to_test)} | Status: {status_msg} ({speed_mbps:.2f} Mbps) | Fast found: {len(passed_proxies)}   ", end="", flush=True)

        print() # Newline after progress bar
        
        output_path = os.path.join(OUTPUT_DIR, f"{protocol_name}_passed.txt")
        log_display_path = f"Splitted-By-Protocol/{protocol_name}.txt"

        if passed_proxies:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(passed_proxies))
            # Restore old log format for user clarity, without breaking the script workflow
            print(f"Wrote {len(passed_proxies)} configs to {log_display_path}")
        else:
            open(output_path, 'w').close()
            print(f"  - No proxies passed for '{protocol_name}'.")

    print("\nSpeed testing complete.")

if __name__ == "__main__":
    main()
