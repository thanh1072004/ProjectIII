#!/usr/bin/env python3
"""
Convert CSIC Database CSV → Full Apache Log Format (with POST_BODY)

Input: csic_database.csv (~60,000+ dòng)
Output: csic_full.log (~60,000 dòng Apache format với POST_BODY support)

Logic:
- Đọc TOÀN BỘ dòng từ CSV
- Extract: Method, URL, User-Agent, classification, content (POST body)
- Nếu POST + có content: gắn vào URL như ?POST_BODY=...
- Gắn "(Simulated-Attack)" cho attack logs
- Output: Apache combined format
"""

import csv
import random
import os
import re
import sys
import io
import urllib.parse
from datetime import datetime, timedelta

# Fix Unicode encoding
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

def convert_csic_full(csv_file_path, output_log_path):
    """Convert CSIC CSV to full Apache log"""

    print("=" * 80)
    print("CONVERTING CSIC DATABASE CSV → FULL APACHE LOG (WITH POST_BODY)")
    print("=" * 80)

    print(f"\n[1] Reading CSV: {csv_file_path}")

    count_normal = 0
    count_attack = 0
    count_total = 0

    start_time = datetime(2026, 1, 1, 0, 0, 0)

    try:
        with open(csv_file_path, 'r', encoding='utf-8') as csv_file, \
             open(output_log_path, 'w', encoding='utf-8') as log_file:

            reader = csv.DictReader(csv_file)

            for row_idx, row in enumerate(reader):
                if row_idx % 10000 == 0:
                    print(f"  ... processed {row_idx} rows", end='\r')

                try:
                    # Extract fields from CSV
                    method = row.get('Method', 'GET').strip()
                    url = row.get('URL', '/').strip()
                    user_agent = row.get('User-Agent', '-').strip()
                    content = row.get('content', '').strip()

                    # Get classification (attack = '1' or 'anomalous', etc.)
                    classification_raw = row.get('classification', row.get('classificati', '0'))
                    classification = str(classification_raw).strip().lower()

                    # Remove localhost from URL
                    if "http://localhost:8080" in url:
                        url = url.replace("http://localhost:8080", "")

                    # CSIC lưu cả protocol trong trường URL (vd ".../index.jsp HTTP/1.1").
                    # Cắt bỏ để không bị LẶP HTTP/1.1 khi ghi dòng log Apache (dòng 95).
                    # Phải cắt TRƯỚC bước POST_BODY để POST_BODY được nối vào đúng chỗ.
                    url = re.sub(r'\s+HTTP/\d+\.\d+\s*$', '', url).strip()

                    # *** CRITICAL: Add POST_BODY to URL if POST + content exists ***
                    if method == 'POST' and content:
                        encoded_content = urllib.parse.quote(content)
                        if '?' in url:
                            url = f"{url}&POST_BODY={encoded_content}"
                        else:
                            url = f"{url}?POST_BODY={encoded_content}"

                    # Generate fake IP
                    ip = f"{random.randint(10, 192)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

                    # Timestamp
                    dt = start_time.strftime("%d/%b/%Y:%H:%M:%S +0700")
                    start_time += timedelta(seconds=random.randint(1, 5))

                    # Status and size
                    status = 200
                    size = random.randint(500, 5000)

                    # Add attack marker if needed
                    is_attack = classification in ['1', 'anomalous', 'anomaly', 'true', 'attack']
                    if is_attack:
                        user_agent = f"{user_agent} (Simulated-Attack)"
                        count_attack += 1
                    else:
                        count_normal += 1

                    # Write Apache combined log format
                    log_line = f'{ip} - - [{dt}] "{method} {url} HTTP/1.1" {status} {size} "-" "{user_agent}"\n'
                    log_file.write(log_line)
                    count_total += 1

                except Exception as e:
                    continue

        print(f"\n\n[2] Conversion Complete!")
        print(f"  Total logs:  {count_total:,}")
        print(f"  Attack logs: {count_attack:,}")
        print(f"  Clean logs:  {count_normal:,}")
        print(f"  Attack ratio: {count_attack/count_total*100:.2f}%")

        print(f"\n[3] Output saved: {output_log_path}")
        print(f"  File size: {os.path.getsize(output_log_path) / 1024 / 1024:.2f} MB")

        return count_total, count_attack, count_normal

    except Exception as e:
        print(f"\n✗ Error: {e}")
        return 0, 0, 0

if __name__ == "__main__":
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    datasets_dir = os.path.join(PROJECT_ROOT, "datasets")

    csv_input = os.path.join(datasets_dir, "csic_database.csv")
    log_output = os.path.join(datasets_dir, "csic_full.log")

    if not os.path.exists(csv_input):
        print(f"Error: {csv_input} not found!")
        sys.exit(1)

    convert_csic_full(csv_input, log_output)

    print("\n" + "=" * 80)
    print("✓ CSIC CONVERSION COMPLETE - READY FOR NEXT STEPS")
    print("=" * 80)
