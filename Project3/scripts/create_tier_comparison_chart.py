#!/usr/bin/env python3
import json
import matplotlib.pyplot as plt
import numpy as np
import os
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Load results from tier_and_hybrid_results.json
results_path = os.path.join(os.path.dirname(__file__), '..', 'analysis', 'tier_and_hybrid_results.json')
with open(results_path, 'r') as f:
    results = json.load(f)

# Extract data
tiers = results['tiers_and_hybrid']
tier_names = [t['name'] for t in tiers]
colors_list = ['#FF6B6B', '#2E86AB', '#06A77D', '#F18F01', '#A23B72']

# Create 2x2 subplot figure
fig, axes = plt.subplots(2, 2, figsize=(18, 12))
fig.suptitle('IDS System: Tier & Hybrid Configuration Comparison\n(Dataset: 111,065 logs, 47.43% attack rate)',
             fontsize=16, fontweight='bold', y=0.995)

x_pos = np.arange(len(tier_names))
width = 0.6

# 1. Precision
ax = axes[0, 0]
precisions = [t['precision'] for t in tiers]
bars = ax.bar(x_pos, precisions, width, color=colors_list)
ax.set_ylabel('Precision (%)', fontsize=12, fontweight='bold')
ax.set_title('Precision: False Positive Rate (Lower FP = Higher Precision)', fontsize=13, fontweight='bold')
ax.set_xticks(x_pos)
ax.set_xticklabels(tier_names, rotation=30, ha='right', fontsize=10)
ax.set_ylim(0, 105)
ax.axhline(y=90, color='green', linestyle='--', alpha=0.3, linewidth=2)
ax.text(len(tier_names)-0.5, 92, '90% threshold', fontsize=9, color='green', alpha=0.7)
for i, (bar, val) in enumerate(zip(bars, precisions)):
    ax.text(bar.get_x() + bar.get_width()/2, val + 1, f'{val:.1f}%',
            ha='center', va='bottom', fontsize=11, fontweight='bold')
ax.grid(axis='y', alpha=0.3)

# 2. Recall
ax = axes[0, 1]
recalls = [t['recall'] for t in tiers]
bars = ax.bar(x_pos, recalls, width, color=colors_list)
ax.set_ylabel('Recall (%)', fontsize=12, fontweight='bold')
ax.set_title('Recall: Detection Rate (Higher Recall = Fewer Missed Attacks)', fontsize=13, fontweight='bold')
ax.set_xticks(x_pos)
ax.set_xticklabels(tier_names, rotation=30, ha='right', fontsize=10)
ax.set_ylim(0, 105)
ax.axhline(y=90, color='green', linestyle='--', alpha=0.3, linewidth=2)
ax.text(len(tier_names)-0.5, 92, '90% threshold', fontsize=9, color='green', alpha=0.7)
for i, (bar, val) in enumerate(zip(bars, recalls)):
    ax.text(bar.get_x() + bar.get_width()/2, val + 1, f'{val:.1f}%',
            ha='center', va='bottom', fontsize=11, fontweight='bold')
ax.grid(axis='y', alpha=0.3)

# 3. F1-Score
ax = axes[1, 0]
f1_scores = [t['f1'] for t in tiers]
bars = ax.bar(x_pos, f1_scores, width, color=colors_list)
ax.set_ylabel('F1-Score (%)', fontsize=12, fontweight='bold')
ax.set_title('F1-Score: Balance (Precision + Recall)', fontsize=13, fontweight='bold')
ax.set_xticks(x_pos)
ax.set_xticklabels(tier_names, rotation=30, ha='right', fontsize=10)
ax.set_ylim(0, 105)
ax.axhline(y=90, color='green', linestyle='--', alpha=0.3, linewidth=2)
ax.text(len(tier_names)-0.5, 92, '90% threshold', fontsize=9, color='green', alpha=0.7)
for i, (bar, val) in enumerate(zip(bars, f1_scores)):
    ax.text(bar.get_x() + bar.get_width()/2, val + 1, f'{val:.1f}%',
            ha='center', va='bottom', fontsize=11, fontweight='bold')
ax.grid(axis='y', alpha=0.3)

# 4. F2-Score (IDS-Standard)
ax = axes[1, 1]
f2_scores = [t['f2'] for t in tiers]
bars = ax.bar(x_pos, f2_scores, width, color=colors_list)
ax.set_ylabel('F2-Score (%)', fontsize=12, fontweight='bold')
ax.set_title('F2-Score: IDS-Standard (Recall × 2)', fontsize=13, fontweight='bold')
ax.set_xticks(x_pos)
ax.set_xticklabels(tier_names, rotation=30, ha='right', fontsize=10)
ax.set_ylim(0, 105)
ax.axhline(y=90, color='green', linestyle='--', alpha=0.3, linewidth=2)
ax.text(len(tier_names)-0.5, 92, '90% threshold', fontsize=9, color='green', alpha=0.7)
for i, (bar, val) in enumerate(zip(bars, f2_scores)):
    ax.text(bar.get_x() + bar.get_width()/2, val + 1, f'{val:.1f}%',
            ha='center', va='bottom', fontsize=11, fontweight='bold')
ax.grid(axis='y', alpha=0.3)

plt.tight_layout()

# Save figure
output_path = os.path.join(os.path.dirname(__file__), '..', 'analysis', 'charts', 'model_comparison.png')
os.makedirs(os.path.dirname(output_path), exist_ok=True)
plt.savefig(output_path, dpi=150, bbox_inches='tight')
print(f"✅ Updated: {output_path}")

# Print summary table
print("\n" + "="*100)
print("TIER & HYBRID CONFIGURATION COMPARISON (Final Dataset Results)")
print("="*100)
print(f"{'Configuration':<40} {'Precision':<12} {'Recall':<12} {'F1-Score':<12} {'F2-Score':<12}")
print("-"*100)
for tier in tiers:
    print(f"{tier['name']:<40} {tier['precision']:>10.2f}% {tier['recall']:>10.2f}% {tier['f1']:>10.2f}% {tier['f2']:>10.2f}%")
print("="*100)

print(f"\n✅ Legend:")
print(f"   Tier 1 (Red):       Regex Rules - Baseline (too conservative)")
print(f"   Tier 2 (Blue):      RandomForest - Best standalone")
print(f"   Tier 3 (Green):     Local Outlier Factor - Anomaly detection")
print(f"   Smart Hybrid (Orange): RF 70% + LOF 30% - Recommended for production")
print(f"   Voting Hybrid (Purple): T1 OR T2 OR T3 - Alternative high-sensitivity")

print(f"\n✅ Dataset: 111,065 total logs (47.43% attack rate)")
print(f"✅ Chart saved to: analysis/charts/model_comparison.png")
