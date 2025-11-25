import os
import aiofiles
import asyncio
from typing import Set

# --- Configuration ---
DB_DIR = "db"
TEMP_DIR = "Temp"
PROTOCOLS_TO_PROCESS = ["vless", "vmess", "ss", "trojan", "hy2", "tuic"]

async def read_file_to_set(filepath: str) -> Set[str]:
    """Reads a file into a set, handling file not found errors."""
    if not os.path.exists(filepath):
        return set()
    async with aiofiles.open(filepath, mode='r', encoding='utf-8') as f:
        return {line.strip() for line in await f.readlines() if line.strip()}

async def write_set_to_file(filepath: str, data: Set[str]):
    """Writes a set to a file."""
    if not data:
        # If the set is empty, create an empty file
        open(filepath, 'w').close()
        return
    async with aiofiles.open(filepath, mode='w', encoding='utf-8') as f:
        await f.write('\n'.join(sorted(list(data))))

async def main():
    """
    Updates the database (_live.txt and _marked.txt files) based on the
    results of the speed test.
    """
    print("Starting database update process...")
    os.makedirs(DB_DIR, exist_ok=True)

    for protocol in PROTOCOLS_TO_PROCESS:
        print(f"  - Updating database for protocol: {protocol}")

        # Define file paths
        live_db_path = os.path.join(DB_DIR, f"{protocol}_live.txt")
        marked_db_path = os.path.join(DB_DIR, f"{protocol}_marked.txt")
        passed_test_path = os.path.join(TEMP_DIR, f"{protocol}_passed.txt")

        # Read all necessary files concurrently
        tasks = [
            read_file_to_set(live_db_path),
            read_file_to_set(passed_test_path)
        ]
        initial_live_servers, passed_servers = await asyncio.gather(*tasks)

        # --- Core Logic using Sets ---

        # The new list of live servers is simply all servers that passed the test.
        # This elegantly handles all cases:
        # - A new server from subscriptions passes -> it becomes live.
        # - An existing live server passes -> it remains live.
        # - A marked server passes -> it gets rehabilitated and becomes live again.
        new_live_servers = passed_servers

        # The new list of marked servers are those that WERE live but DID NOT pass the test.
        new_marked_servers = initial_live_servers - passed_servers

        # Servers that were already marked and didn't pass the test are now implicitly deleted,
        # as they are not included in either `new_live_servers` or `new_marked_servers`.

        # Write the new database files concurrently
        await asyncio.gather(
            write_set_to_file(live_db_path, new_live_servers),
            write_set_to_file(marked_db_path, new_marked_servers)
        )

        print(f"    - Live servers: {len(new_live_servers)}")
        print(f"    - Marked for next round: {len(new_marked_servers)}")
        print(f"    - Implicitly deleted: {len(initial_live_servers - passed_servers)}")

    print("Database update process finished successfully.")

if __name__ == "__main__":
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
