import os
import shutil
import base64
import glob
import asyncio
import aiofiles
from typing import Set

# --- Configuration ---
DB_DIR = "db"
PLAIN_TEXT_DIR = "Splitted-By-Protocol"
PROTOCOLS_TO_SYNC = ["vless", "vmess", "ss", "trojan", "hy2", "tuic"]
SOURCE_DIRS_FOR_ENCODING = [
    "Splitted-By-Protocol",
    "Splitted-By-Protocol-Secure"
]

async def read_file_to_set(filepath: str) -> Set[str]:
    """Reads a file into a set, handling file not found errors."""
    if not os.path.exists(filepath):
        return set()
    async with aiofiles.open(filepath, mode='r', encoding='utf-8') as f:
        return {line.strip() for line in await f.readlines() if line.strip()}

async def sync_plain_text_lists():
    """
    Copies the combined live and marked configs from the DB to the
    plain-text directory for user access and further processing.
    """
    print("Syncing live and marked configs from DB to plain-text directory...")
    os.makedirs(PLAIN_TEXT_DIR, exist_ok=True)

    for protocol in PROTOCOLS_TO_SYNC:
        live_db_path = os.path.join(DB_DIR, f"{protocol}_live.txt")
        marked_db_path = os.path.join(DB_DIR, f"{protocol}_marked.txt")
        dest_path = os.path.join(PLAIN_TEXT_DIR, f"{protocol}.txt")

        live_configs, marked_configs = await asyncio.gather(
            read_file_to_set(live_db_path),
            read_file_to_set(marked_db_path)
        )

        all_configs = live_configs.union(marked_configs)

        if all_configs:
            async with aiofiles.open(dest_path, mode='w', encoding='utf-8') as f:
                await f.write('\n'.join(sorted(list(all_configs))))
            print(f"  - Synced {len(all_configs)} configs for '{protocol}'.")
        else:
            open(dest_path, 'w').close()
            print(f"  - No live or marked configs for '{protocol}'. Created empty file.")

def encode_lists_to_base64():
    """
    Finds all .txt files in the source directories and saves them as
    Base64-encoded strings in corresponding new directories.
    """
    print("\nStarting Base64 encoding process...")

    for source_dir in SOURCE_DIRS_FOR_ENCODING:
        if not os.path.exists(source_dir):
            print(f"  - Source directory '{source_dir}' not found, skipping.")
            continue

        dest_dir = f"{source_dir}-Base64"
        os.makedirs(dest_dir, exist_ok=True)
        print(f"  - Processing directory '{source_dir}' -> '{dest_dir}'")

        source_files = glob.glob(os.path.join(source_dir, "*.txt"))

        for source_path in source_files:
            filename = os.path.basename(source_path)
            dest_path = os.path.join(dest_dir, filename)

            with open(source_path, 'r', encoding='utf-8') as f:
                content = f.read()

            if not content.strip():
                open(dest_path, 'w').close()
                print(f"    - File '{filename}' is empty, creating empty Base64 file.")
                continue

            encoded_bytes = base64.b64encode(content.encode('utf-8'))
            encoded_string = encoded_bytes.decode('utf-8')

            with open(dest_path, 'w', encoding='utf-8') as f:
                f.write(encoded_string)
            print(f"    - Successfully encoded '{filename}'")

async def main():
    await sync_plain_text_lists()
    encode_lists_to_base64()
    print("\nProcessing complete.")

if __name__ == "__main__":
    asyncio.run(main())
