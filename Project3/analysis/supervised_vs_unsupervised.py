"""
Train supervised classifiers on csic_test_train.log (70% labeled split) and
evaluate against unsupervised IF/OCSVM/LOF on the SAME eval split
(csic_test_eval.log, 30%). Reports a single head-to-head table.

Two evaluation modes for the unsupervised side:
  (a) AI-only          — raw model prediction, no regex/vocab rules
  (b) Hybrid (current) — regex rules OR AI prediction OR PARAM_TAMPERING

Supervised models are AI-only (no regex). This is the apples-to-apples
comparison the user asked for.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apachelogs import LogParser
import apache_log
from apache_log import (
    LOG_FORMAT_COMBINED, LOG_FORMAT_COMMON,
    parse_log_entry, build_training_item,
    detect_rule_based, is_ai_whitelisted,
)
from models.ai_detector import LogAnomalyDetector
from models.supervised_detector import SupervisedDetector


def load_labeled(path):
    """Returns (list_of_training_items, list_of_labels_0_or_1)."""
    parser_combined = LogParser(LOG_FORMAT_COMBINED)
    parser_common = LogParser(LOG_FORMAT_COMMON)
    items, labels = [], []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = parser_combined.parse(line)
            except Exception:
                try:
                    entry = parser_common.parse(line)
                except Exception:
                    continue
            pd = parse_log_entry(entry)
            items.append(build_training_item(pd))
            labels.append(1 if "(Simulated-Attack)" in pd["user_agent"] else 0)
    return items, labels


def metrics(tp, fp, tn, fn):
    total = tp + fp + tn + fn
    acc  = (tp + tn) / total * 100 if total else 0
    prec = tp / (tp + fp) * 100 if (tp + fp) else 0
    rec  = tp / (tp + fn) * 100 if (tp + fn) else 0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    return acc, prec, rec, f1


def eval_unsupervised(model_type, eval_items, eval_labels, hybrid=False):
    ai = LogAnomalyDetector(model_type=model_type)
    if not ai.load_model():
        print(f"[ERR] Could not load {model_type}")
        return None
    if hybrid:
        apache_log.PATH_PARAM_VOCAB = ai.path_param_vocab or {}

    tp = fp = tn = fn = 0
    for item, y in zip(eval_items, eval_labels):
        ai_hit = ai.predict(
            item["path"], item["query"], item["method"], item["status"],
            item.get("user_agent", ""), item.get("referer", "")
        )
        if ai_hit and is_ai_whitelisted(item):
            ai_hit = False
        if hybrid:
            # synthesize a "parsed_data"-ish dict for detect_rule_based
            parsed_data = {
                "path": item["path"], "query": item["query"], "method": item["method"],
                "status": item["status"], "user_agent": item.get("user_agent", ""),
                "params": {},
            }
            try:
                from urllib.parse import parse_qs
                parsed_data["params"] = parse_qs(item["query"])
            except Exception:
                pass
            rule_hit = len(detect_rule_based(parsed_data)) > 0
        else:
            rule_hit = False
        detected = rule_hit or ai_hit
        if y == 1 and detected: tp += 1
        elif y == 0 and not detected: tn += 1
        elif y == 0 and detected: fp += 1
        else: fn += 1
    return tp, fp, tn, fn


def eval_supervised(algo, eval_items, eval_labels):
    sup = SupervisedDetector(algo=algo)
    if not sup.load_model():
        print(f"[ERR] Could not load supervised {algo}")
        return None
    r = sup.evaluate_batch(eval_items, eval_labels)
    return r["tp"], r["fp"], r["tn"], r["fn"]


def main():
    train_log = "datasets/csic_test_train.log"
    eval_log  = "datasets/csic_test_eval.log"

    print(f"[*] Loading train split: {train_log}")
    train_items, train_labels = load_labeled(train_log)
    print(f"    {len(train_items)} samples ({sum(train_labels)} attacks, "
          f"{len(train_labels) - sum(train_labels)} normals)")

    print(f"[*] Loading eval split:  {eval_log}")
    eval_items, eval_labels = load_labeled(eval_log)
    print(f"    {len(eval_items)} samples ({sum(eval_labels)} attacks, "
          f"{len(eval_labels) - sum(eval_labels)} normals)")

    # --- Train supervised models on the train split ---
    print("\n" + "="*70 + "\n  TRAINING SUPERVISED MODELS\n" + "="*70)
    for algo in ("rf", "lr"):
        sup = SupervisedDetector(algo=algo)
        sup.train(train_items, train_labels)

    # --- Evaluate everything on the SAME eval split ---
    rows = []

    print("\n" + "="*70 + "\n  EVALUATION (csic_test_eval.log, 30% holdout)\n" + "="*70)

    print("\n[1/3] Unsupervised AI-only (no regex/vocab rules)")
    for mt in ("if", "ocsvm", "lof"):
        res = eval_unsupervised(mt, eval_items, eval_labels, hybrid=False)
        if res:
            tp, fp, tn, fn = res
            acc, prec, rec, f1 = metrics(tp, fp, tn, fn)
            rows.append((f"Unsup {mt.upper()} (AI only)", tp, fp, tn, fn, acc, prec, rec, f1))

    print("\n[2/3] Unsupervised HYBRID (regex + vocab + method-tamper + AI)")
    for mt in ("if", "ocsvm", "lof"):
        res = eval_unsupervised(mt, eval_items, eval_labels, hybrid=True)
        if res:
            tp, fp, tn, fn = res
            acc, prec, rec, f1 = metrics(tp, fp, tn, fn)
            rows.append((f"Unsup {mt.upper()} (hybrid)", tp, fp, tn, fn, acc, prec, rec, f1))

    print("\n[3/3] Supervised (no regex)")
    for algo in ("rf", "lr"):
        res = eval_supervised(algo, eval_items, eval_labels)
        if res:
            tp, fp, tn, fn = res
            acc, prec, rec, f1 = metrics(tp, fp, tn, fn)
            rows.append((f"Sup   {algo.upper()}", tp, fp, tn, fn, acc, prec, rec, f1))

    # --- Pretty table ---
    print("\n" + "="*98)
    print(f"  HEAD-TO-HEAD on csic_test_eval.log "
          f"({len(eval_labels)} samples, {sum(eval_labels)} attacks)")
    print("="*98)
    print(f"{'Model':<28} {'TP':>6} {'FP':>5} {'TN':>6} {'FN':>6} "
          f"{'Acc':>7} {'Prec':>7} {'Rec':>7} {'F1':>7}")
    print("-"*98)
    for name, tp, fp, tn, fn, acc, prec, rec, f1 in rows:
        print(f"{name:<28} {tp:>6} {fp:>5} {tn:>6} {fn:>6} "
              f"{acc:>6.2f}% {prec:>6.2f}% {rec:>6.2f}% {f1:>6.2f}")
    print("="*98)


if __name__ == "__main__":
    main()
