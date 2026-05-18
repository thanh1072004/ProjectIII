"""
Stratified split of csic_test.log into a 70/30 train/eval pair, preserving
the attack ratio. Used so that:
  - supervised models train on the 70% split
  - both supervised AND unsupervised models are evaluated on the SAME 30% split
    (fair head-to-head comparison)
"""
import sys
import os
import random

random.seed(42)

def split(in_path, out_train, out_eval, ratio=0.70):
    attacks, normals = [], []
    with open(in_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            (attacks if "(Simulated-Attack)" in line else normals).append(line)

    random.shuffle(attacks)
    random.shuffle(normals)

    n_attack_train = int(len(attacks) * ratio)
    n_normal_train = int(len(normals) * ratio)

    train_lines = attacks[:n_attack_train] + normals[:n_normal_train]
    eval_lines  = attacks[n_attack_train:] + normals[n_normal_train:]

    random.shuffle(train_lines)
    random.shuffle(eval_lines)

    with open(out_train, "w", encoding="utf-8") as f:
        f.writelines(train_lines)
    with open(out_eval, "w", encoding="utf-8") as f:
        f.writelines(eval_lines)

    print(f"Input:     {in_path}  ({len(attacks)} attacks + {len(normals)} normals)")
    print(f"Train 70%: {out_train}  ({n_attack_train} attacks + {n_normal_train} normals)")
    print(f"Eval  30%: {out_eval}  ({len(attacks)-n_attack_train} attacks + {len(normals)-n_normal_train} normals)")

if __name__ == "__main__":
    base = "datasets/csic_test.log"
    out_train = "datasets/csic_test_train.log"
    out_eval  = "datasets/csic_test_eval.log"
    if len(sys.argv) > 1:
        base = sys.argv[1]
    if len(sys.argv) > 2:
        out_train = sys.argv[2]
    if len(sys.argv) > 3:
        out_eval = sys.argv[3]
    split(base, out_train, out_eval)
