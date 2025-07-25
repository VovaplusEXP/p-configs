import os
import json
import base64

# --- Configuration ---
SOURCE_DIR = "../Splitted-By-Protocol"
DEST_DIR = "../Splitted-By-Protocol-Secure"
PROTOCOLS_TO_FILTER = ["vless.txt", "vmess.txt"]
# Keywords that indicate a secure connection in the config name
SECURE_KEYWORDS = ["-TLS", "-REALITY"]

def filter_secure_configs():
    """
    Reads generated config files and creates new ones containing only
    configs with TLS or REALITY encryption. It specifically handles
    the Base64-encoded nature of VMess links.
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

        secure_configs = []
        with open(source_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                is_secure = False
                # VMess requires special handling due to Base64 encoding
                if filename == "vmess.txt" and line.startswith("vmess://"):
                    try:
                        b64_part = line[len("vmess://"):]
                        # Add padding if necessary
                        b64_part += '=' * (-len(b64_part) % 4)
                        json_str = base64.b64decode(b64_part).decode('utf-8')
                        vmess_data = json.loads(json_str)
                        name = vmess_data.get("ps", "")
                        if any(keyword in name for keyword in SECURE_KEYWORDS):
                            is_secure = True
                    except Exception:
                        # Ignore malformed VMess links
                        continue
                else:
                    # For VLESS and others, a simple substring check is enough
                    if any(keyword in line for keyword in SECURE_KEYWORDS):
                        is_secure = True
                
                if is_secure:
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