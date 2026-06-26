#!/usr/bin/env python3
"""
Generate the Random Forest (Tier 2) feature-importance chart for the thesis.

Reads trained_models/rf_final.pkl and the canonical 22-feature names from
models/ai_detector.py (FEATURE_NAMES), then draws a horizontal bar chart of
the Gini importances ranked from highest to lowest. Saves to
analysis/charts/feature_importance.png (copy it into the thesis Figure/ folder
alongside the other charts).

Run:  python scripts/generate_feature_importance.py
"""
import os
import sys
import io
import joblib
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "models"))
sys.path.insert(0, PROJECT_ROOT)

from ai_detector import LogAnomalyDetector  # noqa: E402

CHARTS_DIR = os.path.join(PROJECT_ROOT, "analysis", "charts")
MODEL_PATH = os.path.join(PROJECT_ROOT, "trained_models", "rf_final.pkl")


def main():
    names = LogAnomalyDetector(model_type="if").FEATURE_NAMES
    rf = joblib.load(MODEL_PATH)
    imp = np.asarray(rf.feature_importances_, dtype=float) * 100.0  # percent

    if len(names) != len(imp):
        raise SystemExit(f"Feature-name/importance mismatch: {len(names)} vs {len(imp)}")

    # Sort ascending so the most important bar sits at the TOP of the chart.
    order = np.argsort(imp)
    sorted_names = [names[i] for i in order]
    sorted_imp = imp[order]

    # Colour by magnitude: dominant (>=10%), supporting (1-10%), marginal (<1%).
    def colour(v):
        if v >= 10.0:
            return "#1B7837"   # green  - dominant
        if v >= 1.0:
            return "#2E86AB"   # blue   - supporting
        return "#B0B0B0"       # grey   - marginal / near-zero

    colours = [colour(v) for v in sorted_imp]

    fig, ax = plt.subplots(figsize=(11, 9))
    ypos = np.arange(len(sorted_names))
    bars = ax.barh(ypos, sorted_imp, color=colours)
    ax.set_yticks(ypos)
    ax.set_yticklabels(sorted_names, fontsize=10)
    ax.set_xlabel("Gini importance (%)", fontsize=12, fontweight="bold")
    ax.set_title("Random Forest (Tier 2) Feature Importance — 22-feature vector",
                 fontsize=14, fontweight="bold")
    ax.set_xlim(0, max(sorted_imp) * 1.18)
    for bar, v in zip(bars, sorted_imp):
        ax.text(bar.get_width() + max(sorted_imp) * 0.01,
                bar.get_y() + bar.get_height() / 2,
                f"{v:.1f}%", va="center", ha="left", fontsize=9)
    ax.grid(axis="x", alpha=0.3)

    # Legend explaining the colour bands.
    from matplotlib.patches import Patch
    ax.legend(handles=[
        Patch(color="#1B7837", label="Dominant (≥ 10%)"),
        Patch(color="#2E86AB", label="Supporting (1–10%)"),
        Patch(color="#B0B0B0", label="Marginal (< 1%)"),
    ], loc="lower right", fontsize=10, framealpha=0.9)

    plt.tight_layout()
    os.makedirs(CHARTS_DIR, exist_ok=True)
    out_path = os.path.join(CHARTS_DIR, "feature_importance.png")
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    print(f"✅ Saved: {out_path}")

    # Console ranking (high -> low) for cross-checking the thesis table.
    print("\n" + "=" * 60)
    print(f"{'rank':<5}{'feature':<32}{'importance':>10}{'  cumulative':>12}")
    print("-" * 60)
    cum = 0.0
    for r, i in enumerate(np.argsort(imp)[::-1], 1):
        cum += imp[i]
        print(f"{r:<5}{names[i]:<32}{imp[i]:>9.2f}%{cum:>11.1f}%")
    print("=" * 60)


if __name__ == "__main__":
    main()
