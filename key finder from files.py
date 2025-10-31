import re
import sys
import os
from typing import List

# Define the regular expression pattern to find strings like HUNT{...}
# This pattern looks for "HUNT{" followed by one or more characters that are NOT '}',
# followed by the closing '}'.
KEY_PATTERN = re.compile(r"(HUNT\{[^}]+\})")

def find_key_in_file(filepath: str) -> List[str]:
    """
    Scans a given file for keys matching the defined pattern.
    """
    
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}", file=sys.stderr)
        return []

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading file {filepath}: {e}", file=sys.stderr)
        return []

    # Find all matches in the file content
    matches = KEY_PATTERN.findall(content)
    
    # Return a list of unique matches found
    return list(set(matches))

def run_scanner():
    """
    Main function to handle command line arguments and execute the scan.
    """
    print("--- Key Pattern Scanner (HUNT{...}) ---")
    
    # Check if a file path was provided as an argument
    if len(sys.argv) < 2:
        print("Usage: python key_finder.py <file_or_directory_path> [file2...]")
        print("Example: python key_finder.py secrets_to_scan.txt /etc/config/app.conf")
        sys.exit(1)

    # Iterate through all provided paths (files or directories)
    for path in sys.argv[1:]:
        if os.path.isdir(path):
            print(f"Skipping directory: {path}. Please provide a file to scan.")
            continue

        print(f"\n[Scanning] -> {path}...")
        found_keys = find_key_in_file(path)

        if found_keys:
            print(f"*** FOUND {len(found_keys)} UNIQUE KEY(S) ***")
            for key in found_keys:
                print(f"  -> {key}")
        else:
            print("No keys found matching the HUNT{...} format.")

if __name__ == "__main__":
    run_scanner()
