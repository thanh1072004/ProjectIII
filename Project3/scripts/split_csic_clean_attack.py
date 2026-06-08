#!/usr/bin/env python3
"""
Split csic_full.log into:
- csic_clean.log (36,000 clean logs)
- csic_attack.log (25,065 attack logs)

Clean logs: không có "(Simulated-Attack)" marker
Attack logs: có "(Simulated-Attack)" marker
"""

import os
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

def split_csic():
    """Split CSIC full log into clean and attack"""

    print("=" * 80)
    print("SPLITTING CSIC FULL LOG INTO CLEAN & ATTACK")
    print("=" * 80)

    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    datasets_dir = os.path.join(PROJECT_ROOT, "datasets")

    input_file = os.path.join(datasets_dir, "csic_full.log")
    clean_file = os.path.join(datasets_dir, "csic_clean.log")
    attack_file = os.path.join(datasets_dir, "csic_attack.log")

    print(f"\n[1] Reading from: {input_file}")

    clean_count = 0
    attack_count = 0

    with open(input_file, 'r', errors='ignore') as f_in:
        with open(clean_file, 'w', encoding='utf-8') as f_clean:
            with open(attack_file, 'w', encoding='utf-8') as f_attack:

                for i, line in enumerate(f_in):
                    if i % 10000 == 0:
                        print(f"  ... processed {i} logs", end='\r')

                    line = line.strip()
                    if not line:
                        continue

                    if "(Simulated-Attack)" in line:
                        f_attack.write(line + '\n')
                        attack_count += 1
                    else:
                        f_clean.write(line + '\n')
                        clean_count += 1

    print(f"\n\n[2] Split Complete!")
    print(f"  Clean logs:  {clean_count:,} → {clean_file}")
    print(f"  Attack logs: {attack_count:,} → {attack_file}")

    print(f"\n[3] File Sizes:")
    print(f"  csic_clean.log:  {os.path.getsize(clean_file) / 1024 / 1024:.2f} MB")
    print(f"  csic_attack.log: {os.path.getsize(attack_file) / 1024 / 1024:.2f} MB")

    print("\n" + "=" * 80)
    print("✓ SPLIT COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    split_csic()
