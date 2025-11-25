import os
import yaml
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Set
from parsers import parse_proxy, to_clash_dict, Proxy
from renamer import get_geo_info, rename_proxy

# --- Configuration ---
SOURCE_DIR = "db"
OUTPUT_DIR = "../Clash-Profiles"
PROTOCOLS_TO_PROCESS = ["vless", "vmess", "ss", "trojan"]
SECURE_PROTOCOLS = ["vless", "vmess"]

# --- Clash Profile Structure ---
BASE_PROFILE_STRUCTURE: Dict[str, Any] = {
    "port": 7890, "socks-port": 7891, "allow-lan": False, "mode": "rule",
    "log-level": "info", "external-controller": "0.0.0.0:9090",
    "dns": {"enable": True, "listen": "0.0.0.0:53",
            "default-nameserver": ["1.1.1.1", "1.0.0.1"],
            "fallback": ["8.8.8.8", "8.8.4.4"]},
    "proxies": [], "proxy-groups": [],
    "rule-providers": {
        "adblock": {
            "type": "http", "behavior": "domain", "interval": 86400,
            "url": "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/refs/heads/master/Filters/rules.txt"
        }
    },
    "rules": []
}
HEALTH_CHECK_CONFIG: Dict[str, Any] = {
    "url": "https://www.google.com/generate_204", "interval": 180
}

def get_geo_for_proxy(proxy: Proxy) -> tuple[Proxy, str]:
    """Wrapper to fetch geo info for a single proxy."""
    country_code = get_geo_info({})
    return proxy, country_code

async def read_proxies_from_db(protocol: str) -> List[Proxy]:
    """Reads and parses proxies from both live and marked DB files."""
    proxies: List[Proxy] = []

    for state in ["live", "marked"]:
        filepath = os.path.join(SOURCE_DIR, f"{protocol}_{state}.txt")
        if not os.path.exists(filepath):
            continue

        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                proxy_obj = parse_proxy(line.strip())
                if proxy_obj:
                    # Filter for secure protocols if required
                    if protocol in SECURE_PROTOCOLS and proxy_obj.security not in ["tls", "reality"]:
                        continue
                    proxies.append(proxy_obj)
    return proxies

async def generate_profiles():
    """Generates a Clash Meta profile for each protocol using live and marked proxies."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print("Starting Clash profile generation...")

    for protocol in PROTOCOLS_TO_PROCESS:
        output_file = os.path.join(OUTPUT_DIR, f"{protocol}.yaml")

        proxies_to_process = await read_proxies_from_db(protocol)

        if not proxies_to_process:
            print(f"  - No valid proxies found for '{protocol}'. Skipping profile generation.")
            # Ensure an empty or default profile is written if it doesn't exist
            if not os.path.exists(output_file):
                with open(output_file, 'w') as f:
                    yaml.dump(BASE_PROFILE_STRUCTURE, f)
            continue

        print(f"  - Found {len(proxies_to_process)} total proxies for {protocol}. Renaming...")

        all_proxies_clash: List[Dict[str, Any]] = []
        proxy_names: List[str] = []
        used_names: Set[str] = set()

        with ThreadPoolExecutor(max_workers=50) as executor:
            loop = asyncio.get_event_loop()
            tasks = [loop.run_in_executor(executor, get_geo_for_proxy, p) for p in proxies_to_process]

            for future in asyncio.as_completed(tasks):
                proxy, country_code = await future
                new_name = rename_proxy(proxy, country_code, used_names)
                
                clash_dict = to_clash_dict(proxy)
                if clash_dict:
                    clash_dict['name'] = new_name
                    all_proxies_clash.append(clash_dict)
                    proxy_names.append(new_name)

        profile: Dict[str, Any] = BASE_PROFILE_STRUCTURE.copy()
        profile["proxies"] = all_proxies_clash
        
        selector_name = f"📲 {protocol.upper()}-Selector"
        profile["rules"] = ["RULE-SET,adblock,REJECT", f"MATCH, {selector_name}"]

        auto_select_group = {
            "name": f"⚡ Auto-{protocol.upper()}", "type": "url-test",
            "proxies": proxy_names, "lazy": False, **HEALTH_CHECK_CONFIG}
        failover_group = {
            "name": f"🔗 Failover-{protocol.upper()}", "type": "fallback",
            "proxies": proxy_names, **HEALTH_CHECK_CONFIG}
        main_selector = {
            "name": selector_name, "type": "select",
            "proxies": [auto_select_group["name"], failover_group["name"], *proxy_names]}
        profile["proxy-groups"] = [auto_select_group, failover_group, main_selector]

        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(profile, f, sort_keys=False, allow_unicode=True)

        print(f"  - Generated '{output_file}' with {len(all_proxies_clash)} proxies.")

if __name__ == "__main__":
    asyncio.run(generate_profiles())
    print("All Clash profiles generated.")
