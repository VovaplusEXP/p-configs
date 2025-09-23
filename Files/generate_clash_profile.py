import os
import yaml
from typing import Dict, Any, List
from parsers import parse_proxy, to_clash_dict

# --- Configuration ---
SOURCE_DIR_BASE = "../Splitted-By-Protocol"
SOURCE_DIR_SECURE = "../Splitted-By-Protocol-Secure"
OUTPUT_DIR = "../Clash-Profiles"

# Define which protocols to process and their source directories
PROTOCOLS_TO_PROCESS: Dict[str, str] = {
    "vless": SOURCE_DIR_SECURE,
    "vmess": SOURCE_DIR_SECURE,
    "ss": SOURCE_DIR_BASE,
    "trojan": SOURCE_DIR_BASE
}

# --- Clash Profile Structure ---
BASE_PROFILE_STRUCTURE: Dict[str, Any] = {
    "port": 7890,
    "socks-port": 7891,
    "allow-lan": False,
    "mode": "rule",
    "log-level": "info",
    "external-controller": "0.0.0.0:9090",
    "dns": {
        "enable": True,
        "listen": "0.0.0.0:53",
        "default-nameserver": [
            "1.1.1.1",
            "1.0.0.1"
        ],
        "fallback": [
            "8.8.8.8",
            "8.8.4.4"
        ]
    },
    "proxies": [],
    "proxy-groups": [],
    "rule-providers": {
        "adblock": {
            "type": "http",
            "url": "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/refs/heads/master/Filters/rules.txt",
            "behavior": "domain",
            "interval": 86400
        }
    },
    "rules": [] # Will be populated dynamically
}

HEALTH_CHECK_CONFIG: Dict[str, Any] = {
    "url": "https://aistudio.google.com/prompts/new_chat",
    "interval": 1200, # 20 minutes
    "regex": "Sign in - Google Accounts"
}

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

        all_proxies: List[Dict[str, Any]] = []
        proxy_names: List[str] = []

        with open(source_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                
                proxy_obj = parse_proxy(line)
                if proxy_obj and proxy_obj.name:
                    clash_proxy = to_clash_dict(proxy_obj)
                    all_proxies.append(clash_proxy)
                    proxy_names.append(clash_proxy["name"])

        if not all_proxies:
            print(f"  - No valid proxies found in '{source_file}'. Skipping profile for {protocol}.")
            continue

        # Create a fresh profile structure for this protocol
        profile: Dict[str, Any] = BASE_PROFILE_STRUCTURE.copy()
        profile["proxies"] = all_proxies
        
        selector_name = f"📲 {protocol.upper()}-Selector"
        profile["rules"] = [
            "RULE-SET,adblock,REJECT",
            f"MATCH, {selector_name}"
        ]

        # Create smart groups for this protocol
        auto_select_group: Dict[str, Any] = {
            "name": f"⚡ Auto-Select-{protocol.upper()}", "type": "url-test",
            "proxies": proxy_names, **HEALTH_CHECK_CONFIG
        }
        failover_group: Dict[str, Any] = {
            "name": f"🔗 Auto-Failover-{protocol.upper()}", "type": "fallback",
            "proxies": proxy_names, **HEALTH_CHECK_CONFIG
        }
        main_selector: Dict[str, Any] = {
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
