import asyncio
import aiofiles
import os
import base64
from typing import Dict, Tuple, Any, List
from parsers import parse_proxy, PROTOCOLS, Proxy
from aiohttp import ClientSession, ClientTimeout # Explicitly import ClientSession and ClientTimeout

# --- Configuration ---
SUBSCRIPTION_LIST_FILE = "Subscription-List.txt"
OUTPUT_DIR_SPLITTED = "../Splitted-By-Protocol"
REQUEST_TIMEOUT = 20

def parse_and_validate_config(line: str) -> Tuple[Tuple[str, str], Any] | None:
    """Parses, validates, and generates a unique key for a config link."""
    proxy_obj = parse_proxy(line)
    if proxy_obj:
        return (proxy_obj.protocol, proxy_obj.original_line), proxy_obj.unique_key
    return None

async def fetch_subs(session: ClientSession, unique_configs_map: Dict[Tuple[Any, ...], Proxy]):
    """Fetches configs and performs smart deduplication."""
    try:
        async with aiofiles.open(SUBSCRIPTION_LIST_FILE, mode='r', encoding='utf-8') as f:
            urls = [line.strip() for line in await f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"Warning: {SUBSCRIPTION_LIST_FILE} not found.")
        return

    async def fetch(url: str):
        try:
            async with session.get(url, timeout=ClientTimeout(total=REQUEST_TIMEOUT)) as response:
                if response.status == 200:
                    content = await response.text()
                    try:
                        lines = base64.b64decode(content).decode('utf-8').splitlines()
                    except Exception:
                        lines = content.splitlines()
                    
                    for line in lines:
                        proxy_obj = parse_proxy(line)
                        if proxy_obj and proxy_obj.unique_key not in unique_configs_map:
                            unique_configs_map[proxy_obj.unique_key] = proxy_obj
        except Exception as e:
            print(f"Warning: Error fetching {url}: {e}")

    await asyncio.gather(*(fetch(url) for url in urls))

async def main():
    print("Starting raw config fetching and deduplication...")
    os.makedirs(OUTPUT_DIR_SPLITTED, exist_ok=True)
    
    unique_configs_map: Dict[Tuple[Any, ...], Proxy] = {}
    async with ClientSession() as session:
        await fetch_subs(session, unique_configs_map)
        
    valid_configs = list(unique_configs_map.values())
    print(f"Found {len(valid_configs)} unique and valid configs.")

    # Group configs by protocol
    processed_by_protocol: Dict[str, List[str]] = {name: [] for name in PROTOCOLS.keys()}
    for proxy_obj in valid_configs:
        if proxy_obj.protocol in processed_by_protocol:
            processed_by_protocol[proxy_obj.protocol].append(proxy_obj.original_line)

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