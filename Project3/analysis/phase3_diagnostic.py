"""
Phase 3 diagnostic: separate regex contribution from AI contribution,
and sample what's being missed (False Negatives).
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collections import Counter
from apachelogs import LogParser
import apache_log
from apache_log import (
    LOG_FORMAT_COMBINED, LOG_FORMAT_COMMON,
    parse_log_entry, build_training_item,
    detect_rule_based, is_ai_whitelisted,
)
from models.ai_detector import LogAnomalyDetector


def diagnose(test_log, model_type):
    print(f"\n{'='*70}\n  DIAGNOSTIC: {model_type.upper()}\n{'='*70}")
    ai = LogAnomalyDetector(model_type=model_type)
    if not ai.load_model():
        print(f"[ERR] Could not load {model_type} model.")
        return
    # Hydrate PATH_PARAM_VOCAB so PARAM_TAMPERING rule fires
    apache_log.PATH_PARAM_VOCAB = ai.path_param_vocab or {}
    print(f"[RULES] PARAM_TAMPERING vocab loaded: {len(apache_log.PATH_PARAM_VOCAB)} paths")

    parser_combined = LogParser(LOG_FORMAT_COMBINED)
    parser_common = LogParser(LOG_FORMAT_COMMON)

    # Confusion matrix split by detector
    counts = Counter()
    # Sample False Negatives
    fn_samples = []
    # Sample AI-unique catches (caught by AI but missed by regex)
    ai_unique_tp_samples = []

    total = 0
    for line in open(test_log, "r", encoding="utf-8", errors="replace"):
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

        total += 1
        parsed = parse_log_entry(entry)
        ua = parsed["user_agent"]
        is_attack = "(Simulated-Attack)" in ua

        regex_hit = len(detect_rule_based(parsed)) > 0

        item = build_training_item(parsed)
        ai_hit = ai.predict(item["path"], item["query"], item["method"],
                            item["status"], item["user_agent"], item["referer"])
        if ai_hit and is_ai_whitelisted(item):
            ai_hit = False

        # Independent contribution tracking
        if is_attack:
            if regex_hit and ai_hit:
                counts["TP_both"] += 1
            elif regex_hit:
                counts["TP_regex_only"] += 1
            elif ai_hit:
                counts["TP_ai_only"] += 1
                if len(ai_unique_tp_samples) < 8:
                    ai_unique_tp_samples.append(parsed["raw_url"][:140])
            else:
                counts["FN"] += 1
                if len(fn_samples) < 15:
                    fn_samples.append(f"{parsed['method']} {parsed['raw_url'][:140]}")
        else:
            if regex_hit and ai_hit:
                counts["FP_both"] += 1
            elif regex_hit:
                counts["FP_regex_only"] += 1
            elif ai_hit:
                counts["FP_ai_only"] += 1
            else:
                counts["TN"] += 1

    print(f"Total lines parsed: {total}")
    print(f"\n--- Attack catch breakdown ---")
    print(f"  Caught by BOTH regex+AI:  {counts['TP_both']}")
    print(f"  Caught by REGEX only:     {counts['TP_regex_only']}")
    print(f"  Caught by AI only:        {counts['TP_ai_only']}  <-- AI's unique contribution")
    print(f"  Missed by BOTH (FN):      {counts['FN']}")

    total_attacks = counts['TP_both'] + counts['TP_regex_only'] + counts['TP_ai_only'] + counts['FN']
    regex_recall = (counts['TP_both'] + counts['TP_regex_only']) / total_attacks * 100
    ai_recall = (counts['TP_both'] + counts['TP_ai_only']) / total_attacks * 100
    print(f"\n  Regex-alone recall: {regex_recall:.2f}%")
    print(f"  AI-alone recall:    {ai_recall:.2f}%")

    print(f"\n--- False-positive breakdown ---")
    print(f"  Flagged by BOTH:    {counts['FP_both']}")
    print(f"  Flagged by REGEX:   {counts['FP_regex_only']}")
    print(f"  Flagged by AI only: {counts['FP_ai_only']}  <-- AI false alarms")

    print(f"\n--- Sample False Negatives (attacks both layers missed) ---")
    for s in fn_samples:
        print(f"  > {s}")

    if ai_unique_tp_samples:
        print(f"\n--- Attacks AI uniquely caught (regex missed) ---")
        for s in ai_unique_tp_samples:
            print(f"  > {s}")


if __name__ == "__main__":
    test_log = sys.argv[1] if len(sys.argv) > 1 else "datasets/csic_test.log"
    for mt in ("if", "lof", "ocsvm"):
        diagnose(test_log, mt)
