import os
from parsers import parse_proxy

# --- Configuration ---
SOURCE_DIR = "../Splitted-By-Protocol"
DEST_DIR = "../Splitted-By-Protocol-Secure"
PROTOCOLS_TO_FILTER = ["vless.txt", "vmess.txt"]
# Keywords that indicate a secure connection in the config name
# SECURE_KEYWORDS = ["-TLS", "-REALITY"] # No longer needed, check proxy_obj.security directly

def filter_secure_configs():
    """
    Reads generated config files and creates new ones containing only
    configs with TLS or REALITY encryption.
    """
    if not os.path.exists(SOURCE_DIR):
        print(f"Warning: Source directory '{SOURCE_DIR}' not found. Skipping.")
        return

    os.makedirs(DEST_DIR, exist_ok=True)
    print(f"Starting filtering for secure configs. Destination: '{DEST_DIR}'")

    for filename in PROTOCOLS_TO_FILTER:
        source_path = os.path.join(SOURCE_DIR, filename)
        dest_path = os.path.join(DEST_DIR, filename)

        if not os.path.exists(source_path):
            print(f"  - Source file '{source_path}' not found, skipping.")
            continue

        secure_configs: list[str] = []
        with open(source_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                proxy_obj = parse_proxy(line)
                if proxy_obj and proxy_obj.security in ["tls", "reality"]:
                    secure_configs.append(line)
        
        if secure_configs:
            with open(dest_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(secure_configs))
            print(f"  - Wrote {len(secure_configs)} secure configs to '{dest_path}'")
        else:
            print(f"  - No secure configs found in '{source_path}'")

if __name__ == "__main__":
    filter_secure_configs()
    print("Filtering complete.")
