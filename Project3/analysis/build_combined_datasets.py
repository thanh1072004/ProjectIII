"""
Trộn các nguồn data có sẵn thành 2 dataset tổng hợp cho training cuối cùng:

  1) datasets/combined_train_clean.log  — UNSUPERVISED (chỉ data sạch)
       = csic_train_clean.log  (20K, CSIC e-commerce)
       + generate_logs/training_clean.log  (10K, web app generic)
     => Vocab + LOF/IF/OCSVM học được cả 2 phong cách traffic.

  2) datasets/combined_labeled.log  — SUPERVISED (cần nhãn)
       NORMALS:
         - csic_train_clean.log  (20K)
         - generate_logs/training_clean.log  (10K)
         - các dòng KHÔNG có "(Simulated-Attack)" trong csic_test.log (16K)
         - các dòng KHÔNG có "(Simulated-Attack)" trong dataset_evaluated.log (2K)
       ATTACKS (dòng có "(Simulated-Attack)" trong UA):
         - csic_test.log attacks (25K)
         - dataset_evaluated.log attacks (2K)

     Tổng ~75K, ~36% attack — cân bằng vừa phải cho supervised.
     Sau đó stratified split 80/20 train/eval.
"""
import os
import sys
import random

random.seed(42)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SOURCES = {
    "csic_clean":   os.path.join(ROOT, "datasets",      "csic_train_clean.log"),
    "csic_mixed":   os.path.join(ROOT, "datasets",      "csic_test.log"),
    "gen_clean":    os.path.join(ROOT, "generate_logs", "training_clean.log"),
    "gen_mixed":    os.path.join(ROOT, "generate_logs", "dataset_evaluated.log"),
}

OUT_UNSUP        = os.path.join(ROOT, "datasets", "combined_train_clean.log")
OUT_LABELED      = os.path.join(ROOT, "datasets", "combined_labeled.log")
OUT_LABEL_TRAIN  = os.path.join(ROOT, "datasets", "combined_labeled_train.log")
OUT_LABEL_EVAL   = os.path.join(ROOT, "datasets", "combined_labeled_eval.log")

ATTACK_TAG = "(Simulated-Attack)"


def read_lines(path):
    if not os.path.exists(path):
        print(f"[WARN] missing: {path}")
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return [ln for ln in f if ln.strip()]


def split_by_label(lines):
    attacks, normals = [], []
    for ln in lines:
        (attacks if ATTACK_TAG in ln else normals).append(ln)
    return attacks, normals


def main():
    print("\n=== Đọc các nguồn data ===")
    raw = {k: read_lines(v) for k, v in SOURCES.items()}
    for k, lines in raw.items():
        a, n = split_by_label(lines)
        print(f"  {k:<12}: {len(lines):>6} dòng ({len(n)} normal, {len(a)} attack)")

    # ----- 1) Combined CLEAN cho unsupervised -----
    csic_clean = raw["csic_clean"]
    gen_clean  = raw["gen_clean"]
    unsup_lines = csic_clean + gen_clean
    random.shuffle(unsup_lines)
    with open(OUT_UNSUP, "w", encoding="utf-8") as f:
        f.writelines(unsup_lines)
    print(f"\n[OK] UNSUPERVISED training set:")
    print(f"     {OUT_UNSUP}")
    print(f"     {len(unsup_lines)} dòng sạch (CSIC + generic web app)")

    # ----- 2) Combined LABELED cho supervised -----
    # Normals
    csic_mixed_attacks, csic_mixed_normals = split_by_label(raw["csic_mixed"])
    gen_mixed_attacks,  gen_mixed_normals  = split_by_label(raw["gen_mixed"])

    all_normals = csic_clean + gen_clean + csic_mixed_normals + gen_mixed_normals
    all_attacks = csic_mixed_attacks + gen_mixed_attacks

    print(f"\n  TOTAL NORMALS: {len(all_normals)}")
    print(f"  TOTAL ATTACKS: {len(all_attacks)}")
    print(f"  ATTACK RATIO:  {len(all_attacks) / (len(all_normals) + len(all_attacks)) * 100:.1f}%")

    labeled = all_normals + all_attacks
    random.shuffle(labeled)
    with open(OUT_LABELED, "w", encoding="utf-8") as f:
        f.writelines(labeled)
    print(f"\n[OK] LABELED dataset (đã shuffle):")
    print(f"     {OUT_LABELED}")
    print(f"     {len(labeled)} dòng tổng cộng")

    # Stratified 80/20 split
    random.shuffle(all_normals)
    random.shuffle(all_attacks)
    n_norm_train = int(len(all_normals) * 0.80)
    n_atk_train  = int(len(all_attacks) * 0.80)
    train = all_normals[:n_norm_train] + all_attacks[:n_atk_train]
    eval_ = all_normals[n_norm_train:] + all_attacks[n_atk_train:]
    random.shuffle(train)
    random.shuffle(eval_)
    with open(OUT_LABEL_TRAIN, "w", encoding="utf-8") as f:
        f.writelines(train)
    with open(OUT_LABEL_EVAL, "w", encoding="utf-8") as f:
        f.writelines(eval_)
    print(f"\n[OK] Stratified 80/20 split:")
    print(f"     TRAIN: {OUT_LABEL_TRAIN}  ({n_norm_train} normal + {n_atk_train} attack = {len(train)})")
    print(f"     EVAL : {OUT_LABEL_EVAL}   ({len(all_normals)-n_norm_train} normal + {len(all_attacks)-n_atk_train} attack = {len(eval_)})")


if __name__ == "__main__":
    main()
