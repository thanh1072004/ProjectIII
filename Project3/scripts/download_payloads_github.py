#!/usr/bin/env python3
"""
Download payloads from PayloadsAllTheThings GitHub repo

Reference: https://github.com/swisskyrepo/PayloadsAllTheThings
"""

import os
import sys
import io
import requests
import zipfile
import json
from collections import defaultdict

# Fix Unicode encoding on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

def download_and_extract_payloads():
    """Download PayloadsAllTheThings from GitHub and extract payloads"""

    print("=" * 80)
    print("DOWNLOADING PAYLOADS FROM PAYLOADSALLTHETHINGS GITHUB")
    print("=" * 80)

    # GitHub URL
    url = "https://github.com/swisskyrepo/PayloadsAllTheThings/archive/refs/heads/master.zip"

    print(f"\n[1] Downloading from: {url}")
    try:
        resp = requests.get(url, timeout=30)
        print(f"✓ Downloaded {len(resp.content) / 1024 / 1024:.2f} MB")
    except Exception as e:
        print(f"✗ Download failed: {e}")
        return None

    # Extract ZIP
    print(f"\n[2] Extracting payloads...")
    payloads_db = defaultdict(list)

    try:
        with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
            files = z.namelist()

            # Mapping: folder name -> attack type
            mapping = {
                'SQL Injection': 'sqli',
                'XSS': 'xss',
                'Command Injection': 'rce',
                'SSRF': 'ssrf',
                'LDAP Injection': 'ldap',
                'XXE': 'xxe',
                'CRLF': 'crlf',
                'Path Traversal': 'path_traversal',
                'SSTI': 'ssti',
                'NoSQL': 'nosql',
            }

            for file_path in files:
                # Look for .txt files (skip README, directories)
                if not file_path.endswith('.txt'):
                    continue

                # Skip meta files
                if any(skip in file_path for skip in ['.github', 'CONTRIBUTING', '.gitignore']):
                    continue

                # Determine attack type from folder name
                attack_type = None
                for folder_name, attack_key in mapping.items():
                    if folder_name in file_path:
                        attack_type = attack_key
                        break

                if not attack_type:
                    continue

                # Read payloads from file
                try:
                    with z.open(file_path) as f:
                        content = f.read().decode('utf-8', errors='ignore')

                        # Parse payloads (one per line, skip comments/markdown)
                        for line in content.split('\n'):
                            line = line.strip()

                            # Skip empty lines
                            if not line:
                                continue

                            # Skip markdown/comments
                            if line.startswith('#') or line.startswith('##') or line.startswith('-'):
                                continue

                            # Skip code blocks
                            if line.startswith('```') or line.startswith('curl') or line.startswith('wget'):
                                continue

                            # Add payload if reasonable length
                            if 3 < len(line) < 500:
                                payloads_db[attack_type].append(line)

                except Exception as e:
                    pass

    except Exception as e:
        print(f"✗ Extraction failed: {e}")
        return None

    # Deduplicate and limit
    print(f"\n[3] Processing payloads...")
    final_db = {}
    total = 0

    for attack_type, payloads in payloads_db.items():
        # Deduplicate
        unique = list(set(payloads))

        # Limit to reasonable number per type (but keep diverse)
        # Typical: 50-200 per type for training
        if len(unique) > 200:
            # Keep first 200 (or sample if too many)
            unique = unique[:200]

        final_db[attack_type] = unique
        total += len(unique)
        print(f"  {attack_type:20} | {len(unique):4} payloads")

    print(f"\nTotal payloads extracted: {total}")

    if total < 100:
        print("\n✗ Too few payloads extracted (need at least 100)")
        return None

    print("\n✓ Successfully downloaded and processed payloads from GitHub!")
    return final_db

def save_payloads_to_python(payloads_db, output_file):
    """Save payloads as Python dict for use in build script"""

    print(f"\n[4] Saving to: {output_file}")

    code = "# AUTO-GENERATED: Payloads from PayloadsAllTheThings GitHub\n"
    code += "# Reference: https://github.com/swisskyrepo/PayloadsAllTheThings\n"
    code += "# Downloaded automatically\n\n"
    code += "GITHUB_PAYLOADS_DB = {\n"

    for attack_type, payloads in sorted(payloads_db.items()):
        code += f"    '{attack_type}': [\n"
        for payload in payloads[:100]:  # Limit per type for file size
            # Escape quotes and special chars
            payload_escaped = payload.replace("'", "\\'")
            code += f"        {repr(payload)},\n"
        code += "    ],\n"

    code += "}\n"

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(code)

    print(f"✓ Saved {len(payloads_db)} attack types")
    print(f"✓ File size: {os.path.getsize(output_file) / 1024:.1f} KB")

def main():
    # Try to download
    payloads_db = download_and_extract_payloads()

    if payloads_db is None:
        print("\n" + "=" * 80)
        print("DOWNLOAD FAILED - Will use hardcoded payloads instead")
        print("=" * 80)
        return False

    # Save to file
    output_file = os.path.join(
        os.path.dirname(__file__),
        "payloads_from_github.py"
    )

    save_payloads_to_python(payloads_db, output_file)

    print("\n" + "=" * 80)
    print("SUCCESS - Payloads downloaded from GitHub!")
    print("=" * 80)
    print(f"\nPayloads file: {output_file}")
    print("You can now import this in build_enhanced_dataset.py")

    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
