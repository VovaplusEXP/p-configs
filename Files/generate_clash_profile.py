import os
import yaml
import base64
import json
from urllib.parse import urlparse, parse_qs, unquote

# --- Configuration ---
SOURCE_DIR_BASE = "../Splitted-By-Protocol"
SOURCE_DIR_SECURE = "../Splitted-By-Protocol-Secure"
OUTPUT_DIR = "../Clash-Profiles"

# Define which protocols to process and their source directories
PROTOCOLS_TO_PROCESS = {
    "vless": SOURCE_DIR_SECURE,
    "vmess": SOURCE_DIR_SECURE,
    "ss": SOURCE_DIR_BASE,
    "trojan": SOURCE_DIR_BASE
}

# --- Clash Profile Structure ---
BASE_PROFILE_STRUCTURE = {
    "port": 7890,
    "socks-port": 7891,
    "allow-lan": False,
    "mode": "rule",
    "log-level": "info",
    "external-controller": "0.0.0.0:9090",
    "proxies": [],
    "proxy-groups": [],
    "rules": [] # Will be populated dynamically
}

HEALTH_CHECK_CONFIG = {
    "url": "https://aistudio.google.com/prompts/new_chat",
    "interval": 1200, # 20 minutes
    "regex": "Gemini 2.5 Pro"
}

# --- Parser Functions (copied from previous version) ---
def parse_vless_trojan(line):
    try:
        parsed_url = urlparse(line)
        qs = parse_qs(parsed_url.query)
        proxy = {
            "name": unquote(parsed_url.fragment), "type": parsed_url.scheme,
            "server": parsed_url.hostname, "port": parsed_url.port,
            "uuid": parsed_url.username, "network": qs.get("type", ["tcp"])[0],
            "tls": qs.get("security", ["none"])[0] in ["tls", "reality"],
            "servername": qs.get("sni", [parsed_url.hostname])[0]
        }
        if proxy["network"] == "ws":
            proxy["ws-opts"] = {"path": qs.get("path", ["/"])[0], "headers": {"Host": proxy["servername"]}}
        if proxy["type"] == "vless":
            proxy["flow"] = qs.get("flow", [""])[0]
        return proxy
    except Exception: return None

def parse_vmess(line):
    try:
        b64_part = line[len("vmess://"):]
        b64_part += '=' * (-len(b64_part) % 4)
        vmess_data = json.loads(base64.b64decode(b64_part).decode('utf-8'))
        proxy = {
            "name": vmess_data.get("ps"), "type": "vmess",
            "server": vmess_data.get("add"), "port": int(vmess_data.get("port")),
            "uuid": vmess_data.get("id"), "alterId": int(vmess_data.get("aid")),
            "cipher": vmess_data.get("scy", "auto"), "network": vmess_data.get("net"),
            "tls": vmess_data.get("tls") == "tls"
        }
        if proxy["network"] == "ws":
            proxy["ws-opts"] = {"path": vmess_data.get("path", "/"), "headers": {"Host": vmess_data.get("host", proxy["server"])}}
        if proxy["tls"]:
            proxy["servername"] = vmess_data.get("host", proxy["server"])
        return proxy
    except Exception: return None

def parse_ss(line):
    try:
        parsed_url = urlparse(line)
        try: userinfo = base64.b64decode(parsed_url.username + "==").decode('utf-8')
        except: userinfo = unquote(parsed_url.username)
        method, password = userinfo.split(':', 1)
        proxy = {
            "name": unquote(parsed_url.fragment), "type": "ss",
            "server": parsed_url.hostname, "port": parsed_url.port,
            "cipher": method, "password": password
        }
        return proxy
    except Exception: return None

# --- Main Generation Logic ---
def generate_profiles():
    """Generates a separate Clash Meta profile for each protocol."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print("Starting Clash profile generation for each protocol...")

    for protocol, source_dir in PROTOCOLS_TO_PROCESS.items():
        source_file = os.path.join(source_dir, f"{protocol}.txt")
        output_file = os.path.join(OUTPUT_DIR, f"{protocol}.yaml")

        if not os.path.exists(source_file):
            print(f"  - Source file '{source_file}' not found. Skipping profile for {protocol}.")
            continue

        all_proxies = []
        proxy_names = []

        with open(source_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                
                proxy = None
                if protocol in ["vless", "trojan"]: proxy = parse_vless_trojan(line)
                elif protocol == "vmess": proxy = parse_vmess(line)
                elif protocol == "ss": proxy = parse_ss(line)
                
                if proxy and proxy.get("name"):
                    all_proxies.append(proxy)
                    proxy_names.append(proxy["name"])

        if not all_proxies:
            print(f"  - No valid proxies found in '{source_file}'. Skipping profile for {protocol}.")
            continue

        # Create a fresh profile structure for this protocol
        profile = BASE_PROFILE_STRUCTURE.copy()
        profile["proxies"] = all_proxies
        
        selector_name = f"📲 {protocol.upper()}-Selector"
        profile["rules"] = [f"MATCH, {selector_name}"]

        # Create smart groups for this protocol
        auto_select_group = {
            "name": f"⚡ Auto-Select-{protocol.upper()}", "type": "url-test",
            "proxies": proxy_names, **HEALTH_CHECK_CONFIG
        }
        failover_group = {
            "name": f"🔗 Auto-Failover-{protocol.upper()}", "type": "fallback",
            "proxies": proxy_names, **HEALTH_CHECK_CONFIG
        }
        main_selector = {
            "name": selector_name, "type": "select",
            "proxies": [auto_select_group["name"], failover_group["name"], *proxy_names]
        }
        profile["proxy-groups"] = [auto_select_group, failover_group, main_selector]

        # Write the final YAML file for this protocol
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(profile, f, sort_keys=False, allow_unicode=True)

        print(f"  - Successfully generated '{output_file}' with {len(all_proxies)} proxies.")

if __name__ == "__main__":
    generate_profiles()
    print("All Clash profiles generated.")