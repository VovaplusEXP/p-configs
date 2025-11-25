import os
import aiofiles
import asyncio
from typing import Set

# --- Configuration ---
DB_DIR = "db"
SPLITTED_DIR = "../Splitted-By-Protocol"
TEMP_DIR = "Temp"
PROTOCOLS_TO_PROCESS = ["vless", "vmess", "ss", "trojan", "hy2", "tuic"]

async def read_file_to_set(filepath: str) -> Set[str]:
    """Reads a file into a set, handling file not found errors."""
    if not os.path.exists(filepath):
        return set()
    async with aiofiles.open(filepath, mode='r', encoding='utf-8') as f:
        return {line.strip() for line in await f.readlines() if line.strip()}

async def main():
    """
    Merges configs from the DB (_live, _marked) and newly fetched lists
    into a single unique list for speed testing.
    """
    print("Starting merge process for speed testing...")
    os.makedirs(TEMP_DIR, exist_ok=True)

    for protocol in PROTOCOLS_TO_PROCESS:
        print(f"  - Processing protocol: {protocol}")

        # Define file paths
        live_db_path = os.path.join(DB_DIR, f"{protocol}_live.txt")
        marked_db_path = os.path.join(DB_DIR, f"{protocol}_marked.txt")
        new_configs_path = os.path.join(SPLITTED_DIR, f"{protocol}.txt")

        # Read all sources concurrently
        tasks = [
            read_file_to_set(live_db_path),
            read_file_to_set(marked_db_path),
            read_file_to_set(new_configs_path)
        ]
        results = await asyncio.gather(*tasks)

        # Union of all sets automatically handles deduplication
        all_unique_configs = results[0].union(*results[1:])

        if not all_unique_configs:
            print(f"    - No configs found for {protocol}. Skipping.")
            continue

        # Write the unique list to a temporary file for the speed tester
        output_path = os.path.join(TEMP_DIR, f"{protocol}_to_test.txt")
        async with aiofiles.open(output_path, mode='w', encoding='utf-8') as f:
            await f.write('\n'.join(sorted(list(all_unique_configs))))

        print(f"    - Wrote {len(all_unique_configs)} unique configs to {output_path}")

    print("Merge process finished successfully.")

if __name__ == "__main__":
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
