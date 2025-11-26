import os
import asyncio
import aiofiles
from typing import Set
from parsers import parse_proxy

# --- Configuration ---
SOURCE_DIR = "db"
DEST_DIR = "Splitted-By-Protocol-Secure"
PROTOCOLS_TO_FILTER = ["vless", "vmess"]

async def read_file_to_set(filepath: str) -> Set[str]:
    """Reads a file into a set, handling file not found errors."""
    if not os.path.exists(filepath):
        return set()
    async with aiofiles.open(filepath, mode='r', encoding='utf-8') as f:
        return {line.strip() for line in await f.readlines() if line.strip()}

async def filter_secure_configs():
    """
    Reads _live.txt and _marked.txt files from the database, combines them,
    and creates new lists containing only configs with TLS or REALITY security.
    """
    os.makedirs(DEST_DIR, exist_ok=True)
    print(f"Starting filtering for secure configs. Destination: '{DEST_DIR}'")

    for protocol in PROTOCOLS_TO_FILTER:
        live_db_path = os.path.join(SOURCE_DIR, f"{protocol}_live.txt")
        marked_db_path = os.path.join(SOURCE_DIR, f"{protocol}_marked.txt")
        dest_path = os.path.join(DEST_DIR, f"{protocol}.txt")

        # Read both live and marked files concurrently
        live_configs, marked_configs = await asyncio.gather(
            read_file_to_set(live_db_path),
            read_file_to_set(marked_db_path)
        )

        all_configs = live_configs.union(marked_configs)

        if not all_configs:
            print(f"  - No live or marked configs found for '{protocol}', skipping.")
            continue

        secure_configs: list[str] = []
        for line in all_configs:
            proxy_obj = parse_proxy(line)
            if proxy_obj and proxy_obj.security in ["tls", "reality"]:
                secure_configs.append(line)
        
        if secure_configs:
            async with aiofiles.open(dest_path, mode='w', encoding='utf-8') as f:
                await f.write('\n'.join(secure_configs))
            print(f"  - Wrote {len(secure_configs)} secure configs to '{dest_path}'")
        else:
            open(dest_path, 'w').close()
            print(f"  - No secure configs found for '{protocol}'")

async def main():
    if not os.path.exists(SOURCE_DIR):
        print(f"Warning: Source directory '{SOURCE_DIR}' not found. Skipping.")
        return
    await filter_secure_configs()

if __name__ == "__main__":
    asyncio.run(main())
    print("Filtering complete.")
