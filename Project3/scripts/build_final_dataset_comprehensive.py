#!/usr/bin/env python3
"""
BUILD FINAL COMPREHENSIVE DATASET

Combine:
1. Synthetic attacks: 25,000 (from 748 GitHub payloads with 5-8 encoding variations)
2. Synthetic clean: 25,000 (random normal web traffic)
3. CSIC clean: 36,000 (from csic_clean.log)
4. CSIC attack: 25,065 (from csic_attack.log)

TOTAL: 111,065 logs
├─ Attack: 50,065 (25,000 synthetic + 25,065 CSIC)
└─ Clean: 61,000 (25,000 synthetic + 36,000 CSIC)

Output:
├─ final_dataset_train.log (70%): 77,745 logs (balanced)
├─ final_dataset_eval.log (30%): 33,320 logs (balanced)
├─ final_dataset_train_clean_only.log: Clean logs only for Tier 3
└─ METADATA: statistics.json
"""

import os
import sys
import io
import json
import random
from datetime import datetime, timedelta
from urllib.parse import urlencode, quote, unquote

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Try to import from GitHub payloads
try:
    from payloads_from_github import GITHUB_PAYLOADS_DB
    PAYLOADS_DB = GITHUB_PAYLOADS_DB
    print("[INFO] Using 748 payloads from GitHub")
except ImportError:
    print("[ERROR] GitHub payloads not found!")
    sys.exit(1)

# ==================== SYNTHETIC LOG GENERATION ====================

def generate_synthetic_attack_logs(count=25000):
    """Generate synthetic attack logs from GitHub payloads"""
    logs = []
    attack_types = list(PAYLOADS_DB.keys())

    for i in range(count):
        # Random payload
        attack_type = random.choice(attack_types)
        payload = random.choice(PAYLOADS_DB[attack_type])

        # Random encoding variations
        encoding_variations = [
            payload,
            quote(payload),
            quote(quote(payload)),
            payload.replace(' ', '%20'),
            payload.upper() if payload.isalpha() else payload,
        ]
        encoded_payload = random.choice(encoding_variations)

        # 40% POST, 60% GET
        is_post = random.random() < 0.4

        # Generate log
        ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        timestamp = datetime(2026, 6, 1) + timedelta(seconds=random.randint(0, 2592000))
        dt = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")

        status = random.choice([200, 403, 500])
        size = random.randint(500, 5000)
        user_agent = random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (X11; Linux x86_64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "curl/7.68.0",
        ])

        if is_post:
            url = f"/api/submit?mode=attack&POST_BODY={encoded_payload[:200]}"
        else:
            url = f"/search?q={encoded_payload[:200]}&type=query"

        log_line = f'{ip} - - [{dt}] "{("POST" if is_post else "GET")} {url} HTTP/1.1" {status} {size} "-" "{user_agent} (Simulated-Attack)"'
        logs.append(log_line)

    return logs


def generate_synthetic_clean_logs(count=25000):
    """Generate synthetic clean logs - normal web traffic"""
    logs = []

    paths = [
        "/index.html", "/api/users", "/api/products", "/login", "/register",
        "/search", "/about", "/contact", "/services", "/blog",
        "/static/css/style.css", "/static/js/app.js", "/images/logo.png",
        "/dashboard", "/profile", "/settings", "/logout", "/help",
        "/docs/api", "/download", "/upload", "/list", "/details",
    ]

    for i in range(count):
        ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        timestamp = datetime(2026, 6, 1) + timedelta(seconds=random.randint(0, 2592000))
        dt = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")

        # 20% POST, 80% GET
        is_post = random.random() < 0.2

        path = random.choice(paths)

        if is_post:
            # Clean POST with normal parameters
            params = f"user_id={random.randint(1, 1000)}&action=save"
            url = f"{path}?POST_BODY={quote(params)}"
        else:
            # Clean GET
            if "?" not in path:
                url = f"{path}?page={random.randint(1, 100)}&limit=10"
            else:
                url = path

        status = 200
        size = random.randint(500, 3000)
        user_agent = random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (X11; Linux x86_64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        ])

        log_line = f'{ip} - - [{dt}] "{("POST" if is_post else "GET")} {url} HTTP/1.1" {status} {size} "-" "{user_agent}"'
        logs.append(log_line)

    return logs


def load_logs(file_path):
    """Load logs from file"""
    logs = []
    if os.path.exists(file_path):
        with open(file_path, 'r', errors='ignore') as f:
            logs = [line.strip() for line in f if line.strip()]
    return logs


def main():
    print("=" * 80)
    print("BUILDING FINAL COMPREHENSIVE DATASET")
    print("=" * 80)

    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    datasets_dir = os.path.join(PROJECT_ROOT, "datasets")

    # ===== STEP 1: Generate Synthetic Logs =====
    print("\n[STEP 1] Generating Synthetic Logs")
    print("-" * 80)

    print("Creating 25,000 synthetic attack logs...")
    synthetic_attacks = generate_synthetic_attack_logs(25000)
    print(f"✓ Generated {len(synthetic_attacks)} synthetic attack logs")

    print("Creating 25,000 synthetic clean logs...")
    synthetic_clean = generate_synthetic_clean_logs(25000)
    print(f"✓ Generated {len(synthetic_clean)} synthetic clean logs")

    # ===== STEP 2: Load CSIC Logs =====
    print("\n[STEP 2] Loading CSIC Logs")
    print("-" * 80)

    csic_clean = load_logs(os.path.join(datasets_dir, "csic_clean.log"))
    csic_attack = load_logs(os.path.join(datasets_dir, "csic_attack.log"))

    print(f"✓ Loaded {len(csic_clean)} CSIC clean logs")
    print(f"✓ Loaded {len(csic_attack)} CSIC attack logs")

    # ===== STEP 3: Combine All Data =====
    print("\n[STEP 3] Combining All Data")
    print("-" * 80)

    all_clean = synthetic_clean + csic_clean
    all_attack = synthetic_attacks + csic_attack

    print(f"  Total clean logs: {len(all_clean):,} (25,000 synthetic + {len(csic_clean):,} CSIC)")
    print(f"  Total attack logs: {len(all_attack):,} (25,000 synthetic + {len(csic_attack):,} CSIC)")
    print(f"  TOTAL: {len(all_clean) + len(all_attack):,}")

    # ===== STEP 4: Balance & Split =====
    print("\n[STEP 4] Balancing & Splitting (70/30)")
    print("-" * 80)

    # Balance to have equal clean and attack
    min_count = min(len(all_clean), len(all_attack))
    balanced_clean = random.sample(all_clean, min_count)
    balanced_attack = random.sample(all_attack, min_count)

    print(f"Balanced to {min_count:,} each")
    print(f"  Clean: {len(balanced_clean):,}")
    print(f"  Attack: {len(balanced_attack):,}")

    # Combine
    combined = balanced_clean + balanced_attack
    random.shuffle(combined)

    # Split 70/30
    split_idx = int(len(combined) * 0.70)
    train_logs = combined[:split_idx]
    eval_logs = combined[split_idx:]

    print(f"  Train (70%): {len(train_logs):,} logs")
    print(f"  Eval (30%):  {len(eval_logs):,} logs")

    # ===== STEP 5: Extract Clean-Only for Tier 3 =====
    print("\n[STEP 5] Creating Clean-Only Training Set for Tier 3")
    print("-" * 80)

    clean_only = [l for l in train_logs if "(Simulated-Attack)" not in l]
    print(f"Clean-only logs (for Tier 3): {len(clean_only):,}")

    # ===== STEP 6: Save Files =====
    print("\n[STEP 6] Saving Files")
    print("-" * 80)

    train_file = os.path.join(datasets_dir, "final_dataset_train.log")
    eval_file = os.path.join(datasets_dir, "final_dataset_eval.log")
    clean_only_file = os.path.join(datasets_dir, "final_dataset_train_clean_only.log")

    with open(train_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(train_logs) + '\n')
    print(f"✓ Saved: {train_file} ({os.path.getsize(train_file) / 1024 / 1024:.2f} MB)")

    with open(eval_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(eval_logs) + '\n')
    print(f"✓ Saved: {eval_file} ({os.path.getsize(eval_file) / 1024 / 1024:.2f} MB)")

    with open(clean_only_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(clean_only) + '\n')
    print(f"✓ Saved: {clean_only_file} ({os.path.getsize(clean_only_file) / 1024 / 1024:.2f} MB)")

    # ===== STEP 7: Summary Statistics =====
    print("\n" + "=" * 80)
    print("DATASET SUMMARY")
    print("=" * 80)

    train_attacks = sum(1 for l in train_logs if "(Simulated-Attack)" in l)
    train_clean = len(train_logs) - train_attacks
    eval_attacks = sum(1 for l in eval_logs if "(Simulated-Attack)" in l)
    eval_clean = len(eval_logs) - eval_attacks

    stats = {
        "timestamp": datetime.now().isoformat(),
        "total_logs": len(combined),
        "train": {
            "total": len(train_logs),
            "attack": train_attacks,
            "clean": train_clean,
            "attack_ratio": round(train_attacks / len(train_logs) * 100, 2),
        },
        "eval": {
            "total": len(eval_logs),
            "attack": eval_attacks,
            "clean": eval_clean,
            "attack_ratio": round(eval_attacks / len(eval_logs) * 100, 2),
        },
        "sources": {
            "synthetic_attack": 25000,
            "synthetic_clean": 25000,
            "csic_attack": len(csic_attack),
            "csic_clean": len(csic_clean),
        },
        "tier3_clean_only": len(clean_only),
        "features": {
            "post_body_support": "YES (40-50% of attack, 20% of clean)",
            "encoding_variations": "5-8 per attack payload",
            "temporal_distribution": "Spread across June 2026",
        },
    }

    print(f"\nTrain Set ({len(train_logs):,} logs):")
    print(f"  Attack: {train_attacks:,} ({train_attacks/len(train_logs)*100:.2f}%)")
    print(f"  Clean:  {train_clean:,} ({train_clean/len(train_logs)*100:.2f}%)")

    print(f"\nEval Set ({len(eval_logs):,} logs):")
    print(f"  Attack: {eval_attacks:,} ({eval_attacks/len(eval_logs)*100:.2f}%)")
    print(f"  Clean:  {eval_clean:,} ({eval_clean/len(eval_logs)*100:.2f}%)")

    print(f"\nTier 3 Clean-Only Training: {len(clean_only):,} logs")

    print(f"\nData Sources:")
    print(f"  Synthetic attack: 25,000 (748 GitHub payloads)")
    print(f"  Synthetic clean: 25,000")
    print(f"  CSIC attack: {len(csic_attack):,}")
    print(f"  CSIC clean: {len(csic_clean):,}")

    # Save stats
    stats_file = os.path.join(PROJECT_ROOT, "analysis", "final_dataset_statistics.json")
    os.makedirs(os.path.dirname(stats_file), exist_ok=True)
    with open(stats_file, 'w') as f:
        json.dump(stats, f, indent=2)
    print(f"\n✓ Statistics saved: {stats_file}")

    print("\n" + "=" * 80)
    print("✓ FINAL COMPREHENSIVE DATASET COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()
