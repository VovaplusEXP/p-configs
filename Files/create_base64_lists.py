import os
import base64
import glob

# --- Configuration ---
# Directories to scan for plain-text config lists
SOURCE_DIRS = [
    "../Splitted-By-Protocol",
    "../Splitted-By-Protocol-Secure"
]

def encode_lists_to_base64():
    """
    Finds all .txt files in the source directories, joins their content,
    and saves it as a Base64-encoded string in a new corresponding directory.
    """
    print("Starting Base64 encoding process...")

    for source_dir in SOURCE_DIRS:
        if not os.path.exists(source_dir):
            print(f"  - Source directory '{source_dir}' not found, skipping.")
            continue

        # Create the corresponding destination directory
        dest_dir = f"{source_dir}-Base64"
        os.makedirs(dest_dir, exist_ok=True)
        print(f"  - Processing directory '{source_dir}' -> '{dest_dir}'")

        # Find all .txt files in the source directory
        source_files = glob.glob(os.path.join(source_dir, "*.txt"))

        if not source_files:
            print(f"    - No .txt files found in '{source_dir}'.")
            continue

        for source_path in source_files:
            filename = os.path.basename(source_path)
            dest_path = os.path.join(dest_dir, filename)

            try:
                with open(source_path, 'r', encoding='utf-8') as f:
                    # Read all lines and join them into a single string
                    content = f.read()

                if not content.strip():
                    print(f"    - File '{filename}' is empty, skipping.")
                    continue
                
                # Encode the entire content string to Base64
                encoded_bytes = base64.b64encode(content.encode('utf-8'))
                encoded_string = encoded_bytes.decode('utf-8')

                with open(dest_path, 'w', encoding='utf-8') as f:
                    f.write(encoded_string)
                
                print(f"    - Successfully encoded '{filename}'")

            except Exception as e:
                print(f"    - Failed to process '{filename}'. Error: {e}")

if __name__ == "__main__":
    encode_lists_to_base64()
    print("Base64 encoding complete.")
