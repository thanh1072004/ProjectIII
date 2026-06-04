import re
import json
import sys
import os
from collections import Counter, defaultdict
from urllib.parse import unquote, urlparse, parse_qs
from apachelogs import LogParser
from datetime import datetime
import matplotlib.pyplot as plt
import urllib

# Phase 3.1 (B as hard rule): module-level vocab — populated from the loaded
# AI engine in main(). detect_rule_based() uses this to flag requests whose
# param names don't match anything seen during training for that endpoint.
PATH_PARAM_VOCAB = {}

# Output JSONL được ghi vào runtime/ (cấu trúc mới). Tự tạo thư mục khi cần.
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
_RUNTIME_DIR  = os.environ.get("IDS_RUNTIME_DIR",
                               os.path.join(_PROJECT_ROOT, "runtime"))
os.makedirs(_RUNTIME_DIR, exist_ok=True)

def _runtime_path(name):
    return os.path.join(_RUNTIME_DIR, name)

# --- CONFIGURATION & REGEX ---

# SQLi -- Phase 3.1 (C): broadened to cover quoted-no-space tautologies like
# 'OR'a'='a (very common in CSIC). Old pattern required digit-on-both-sides
# AND whitespace between OR/AND and the next token, missing the majority of
# CSIC SQLi payloads.
SQLI_RE = re.compile(
    r"(?i)("
    r"\bunion\s+(all\s+)?select\b"
    r"|\bselect\s+.*\bfrom\b"
    r"|\binsert\s+into\b"
    r"|\bupdate\s+\w+\s+set\b"
    r"|\bdelete\s+from\b"
    r"|\bdrop\s+(table|database|schema)\b"
    r"|\balter\s+table\b"
    r"|\btruncate\s+table\b"
    # quoted tautology with letters or digits, no spaces required:
    #   'OR'a'='a , 'OR'a='a , 'or'1'='1 , 'or"1"="1
    # NOTE: second quote (before '=') is OPTIONAL — CSIC decodes to 'OR'a='a.
    r"|['\"][^'\"]{0,4}(or|and)[^'\"]{0,4}['\"]\s*\w+\s*['\"]?\s*=\s*['\"]?\s*\w+"
    # bare/spaced tautology: OR 1=1, OR a=a, AND 1=1
    r"|\b(or|and)\s+['\"]?\s*\w{1,15}\s*['\"]?\s*=\s*['\"]?\s*\w{1,15}"
    # paren-prefixed: ') or ('1'='1
    r"|\)\s*(or|and)\s*\("
    r"|--\s|#\s|/\*"
    r"|\bexec(ute)?\s*[\(\s]"
    r"|\bxp_cmdshell\b"
    r")"
)
# XSS: Giữ nguyên
XSS_RE = re.compile(r'(?i)(<script\b|javascript:|onerror\s*=|onload\s*=|eval\(|<img\s+src|alert\()')

# LFI/Path Traversal
LFI_RE = re.compile(r'(?i)(\.\./|\.\.\\|/etc/passwd|/proc/self|C:\\Windows|win\.ini)')

# Command Injection
CMD_INJ_RE = re.compile(r'(?i)('
                        r'(;|\||&&|\$|\>)\s*(rm|ls|cat|whoami|ping|tail|head)\b'
                        r'|'
                        r'\b(wget|curl|netcat|nc|bash|sh|python|perl)\b'
                        r'|'
                        r'`.*`'
                        r')')

# Sensitive Files
SENSITIVE_FILE_RE = re.compile(r'(?i)(\.env|\.git/config|config\.php|wp-config\.php|\.bak|\.sql|/cgi-bin/|test-cgi|/backup/|phpinfo\.php)')

# Scanner User-Agent
SCANNER_UA_RE = re.compile(r'(?i)(sqlmap|nikto|masscan|nessus|nmap|dirbuster|gobuster|acunetix|hydra)')

# LOG_FORMAT = '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"'
LOG_FORMAT_COMBINED = '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"'
LOG_FORMAT_COMMON = '%h %l %u %t "%r" %>s %b'
    
# --- DETECTION FUNCTIONS ---

def check_sqli(payload):
    if SQLI_RE.search(payload):
        return {"id": "SQL_INJECTION", "desc": "Payload contains SQL Injection patterns"}
    return None

def check_xss(payload):
    if XSS_RE.search(payload):
        return {"id": "XSS", "desc": "Payload contains XSS patterns"}
    return None

def check_lfi(payload):
    if LFI_RE.search(payload):
        return {"id": "LFI_PATH_TRAVERSAL", "desc": "Attempt to traverse directories or access system files"}
    return None

def check_cmd_injection(payload):
    if CMD_INJ_RE.search(payload):
        return {"id": "COMMAND_INJECTION", "desc": "System command injection attempt detected"}
    return None

def check_sensitive_files(path):
    if SENSITIVE_FILE_RE.search(path):
        return {"id": "SENSITIVE_FILE_ACCESS", "desc": "Accessing sensitive configuration or backup files"}
    return None

def check_rfi(params):
    for key, values in params.items():
        for v in values:
            if v.lower().startswith(('http://', 'https://', 'ftp://')):
                 return {"id": "RFI", "desc": f"Remote File Inclusion candidate in param '{key}'"}
    return None

def check_scanner_ua(user_agent):
    if not user_agent: return None
    if SCANNER_UA_RE.search(user_agent):
        return {"id": "SCANNER_TOOL", "desc": f"User-Agent indicates a scanning tool: {user_agent}"}
    return None

# Phase 3.1 (E): HTTP method tampering as a hard rule.
# Many CSIC attacks just swap the HTTP method (PUT/DELETE/PATCH/TRACE/CONNECT)
# on a resource that normally only handles GET/POST. We allow these methods on
# obvious API endpoints; everything else is treated as an attack.
_API_PATH_HINTS = ('/api/', '/rest/', '/v1/', '/v2/', '/v3/', '/graphql', '/_api/')
_TAMPER_METHODS = frozenset({'PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT'})

def check_method_tampering(method, path):
    if not method:
        return None
    if method.upper() not in _TAMPER_METHODS:
        return None
    path_lower = (path or '').lower()
    if any(hint in path_lower for hint in _API_PATH_HINTS):
        return None
    return {
        "id": "HTTP_METHOD_TAMPERING",
        "desc": f"Unusual HTTP method '{method}' on non-API path '{path}'"
    }

# Phase 3.1 (B as hard rule): flag a request whose param names don't match
# the vocabulary learned during training for this exact path. This catches
# CSIC's frequent paramName-tampering attacks: modoA vs modo, B1A vs B1,
# precioA vs precio, etc. Only fires when vocab is loaded.
def check_param_tampering(path, query, vocab):
    if not vocab or not query:
        return None
    if path not in vocab:
        # Path itself is novel — separately flagged below. Don't double-fire.
        return None
    try:
        params = parse_qs(query, keep_blank_values=True)
    except Exception:
        return None
    if not params:
        return None
    known = vocab[path]
    unknown = [k for k in params.keys() if k not in known]
    if not unknown:
        return None
    return {
        "id": "PARAM_TAMPERING",
        "desc": f"Unknown param name(s) on {path}: {unknown}"
    }

# --- MAIN ANALYSIS ---

def analyze_log(path_log, ai_engine, supervised_engine=None,
                path_out_alerts=None,
                path_out_results=None,
                mode="scan"):
    # Default output paths -> runtime/
    if path_out_alerts is None:
        path_out_alerts = _runtime_path("alerts.jsonl")
    if path_out_results is None:
        path_out_results = _runtime_path("scan_results.jsonl")
    """
    Hai chế độ:
      - mode="train": chỉ thu thập dữ liệu để train (ai_engine.train được gọi sau)
      - mode="scan" : chạy đầy đủ 3-tier (regex + supervised RF + unsup LOF),
                      ghi 2 file output:
                        * scan_results.jsonl : 1 dòng/log_line, có verdict + chi tiết
                                              (phân biệt rõ attack/clean cho từng dòng)
                        * alerts.jsonl       : chỉ những dòng được kết luận là attack
                                              (giữ format cũ để tương thích)
    """
    parser_combined = LogParser(LOG_FORMAT_COMBINED)
    parser_common = LogParser(LOG_FORMAT_COMMON)
    alerts = []

    # Thống kê
    ip_activity = defaultdict(int)
    ip_paths = defaultdict(set)
    ip_401_counts = defaultdict(int)

    # Cho mode train: chỉ thu data
    training_data = []

    # Cho mode scan: lưu (line_no, parsed_data, regex_matches)
    scan_inputs = []

    print(f"[*] Starting {mode} on {path_log}...")

    with open(path_log, "r", encoding="utf-8", errors="replace") as f_in:
        for line_no, line in enumerate(f_in, start=1):
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

            parsed_data = parse_log_entry(entry)
            training_item = build_training_item(parsed_data)
            training_data.append(training_item)

            if mode == "train":
                continue

            # ===== Tier 1: Rule-based detection =====
            matches = detect_rule_based(parsed_data)
            update_behavior_stats(parsed_data, ip_activity, ip_paths, ip_401_counts)

            scan_inputs.append((line_no, parsed_data, training_item, matches))

    # ----- mode TRAIN -----
    if mode == "train":
        print(f"[*] Training AI model ({ai_engine.model_type.upper()}) with {len(training_data)} entries...")
        if os.path.exists(ai_engine.model_path):
            os.remove(ai_engine.model_path)
        if os.path.exists(ai_engine.scaler_path):
            os.remove(ai_engine.scaler_path)
        ai_engine.train(training_data)
        return

    # ----- mode SCAN: chạy đầy đủ 3-tier -----
    has_unsup = ai_engine.load_model() if ai_engine else False
    has_sup = supervised_engine is not None and getattr(supervised_engine, 'model', None) is not None

    print(f"\n[SCAN] Tier 1 (regex+vocab+method-tamper) ALWAYS ON")
    print(f"[SCAN] Tier 2 (supervised RF) {'LOADED' if has_sup else 'DISABLED'}")
    print(f"[SCAN] Tier 3 (unsupervised {ai_engine.model_type.upper() if ai_engine else '-'}) {'LOADED' if has_unsup else 'DISABLED'}")
    print(f"[SCAN] Output: {path_out_results} (mọi dòng) + {path_out_alerts} (chỉ attack)")

    # Truncate output files
    open(path_out_results, "w", encoding="utf-8").close()

    n_attack = n_clean = 0
    bucket_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0}

    with open(path_out_results, "a", encoding="utf-8") as f_results:
        for line_no, parsed_data, item, rule_matches in scan_inputs:
            rule_ids = sorted({m["id"] for m in rule_matches})
            whitelisted = is_ai_whitelisted(item)

            # Tier 2: supervised RF probability
            sup_hit = False
            sup_prob = 0.0
            if has_sup and not whitelisted:
                try:
                    sup_prob = supervised_engine.predict_proba(
                        item["path"], item["query"], item["method"], item["status"],
                        item.get("user_agent", ""), item.get("referer", "")
                    )
                    sup_hit = sup_prob >= 0.5
                except Exception:
                    sup_hit, sup_prob = False, 0.0

            # Tier 3: unsupervised tripwire
            unsup_hit = False
            if has_unsup and not whitelisted:
                try:
                    unsup_hit = ai_engine.predict(
                        item["path"], item["query"], item["method"], item["status"],
                        item.get("user_agent", ""), item.get("referer", "")
                    )
                except Exception:
                    unsup_hit = False

            # Weighted score + Smart Hybrid Consensus (giảm FP của LOF khi RF không đồng ý)
            score = 0.0
            if rule_ids:
                score += 0.45
            if sup_hit:
                score += 0.40 * sup_prob
            if unsup_hit:
                score += 0.20

            # Decision: Smart Hybrid Consensus
            #   attack = regex_hit OR sup>=0.5 OR (lof_hit AND sup>=0.3)
            is_attack = bool(rule_ids) or sup_hit or (unsup_hit and sup_prob >= 0.3)

            if not is_attack:
                level = "CLEAN"
            elif score >= 0.75:
                level = "CRITICAL"
            elif score >= 0.45:
                level = "HIGH"
            elif score >= 0.25:
                level = "MEDIUM"
            else:
                level = "LOW"
            bucket_counts[level] += 1
            if is_attack:
                n_attack += 1
            else:
                n_clean += 1

            sources = []
            if rule_ids:
                sources.append(f"REGEX({','.join(rule_ids)})")
            if sup_hit:
                sources.append(f"SUPERVISED({supervised_engine.algo.upper()},p={sup_prob:.2f})")
            if unsup_hit:
                sources.append(f"UNSUPERVISED({ai_engine.model_type.upper()})")

            # Ghi từng dòng vào scan_results.jsonl (CẢ attack lẫn clean)
            rec = {
                "line_no":   line_no,
                "client_ip": parsed_data["client_ip"],
                "method":    parsed_data["method"],
                "raw_url":   parsed_data["raw_url"],
                "status":    parsed_data["status"],
                "is_attack": is_attack,
                "level":     level,
                "score":     round(score, 3),
                "tiers":     sources,
                "rule_ids":  rule_ids,
                "sup_prob":  round(sup_prob, 3) if has_sup else None,
                "lof_hit":   bool(unsup_hit),
                "whitelisted": whitelisted,
            }
            f_results.write(json.dumps(rec, ensure_ascii=False) + "\n")

            # Ngoài ra: nếu là attack -> thêm vào alerts.jsonl (format cũ)
            if is_attack:
                alerts.append({
                    "line_no": line_no,
                    "client_ip": parsed_data["client_ip"],
                    "level": level,
                    "score": round(score, 3),
                    "tiers": sources,
                    "matches": rule_matches if rule_matches else [{"id": "AI_DETECTED", "desc": "Detected by AI tier(s)"}],
                    "detail": f"{parsed_data['method']} {parsed_data['raw_url']}"
                })

    # ===== Behavior analysis (giữ logic cũ) =====
    behavior_alerts = analyze_behavior(ip_paths)
    alerts.extend(behavior_alerts)

    # ===== Save alerts.jsonl =====
    save_alerts(alerts, path_out_alerts)

    # ===== Tóm tắt =====
    total = n_attack + n_clean
    print(f"\n{'='*60}")
    print(f"  SCAN SUMMARY")
    print(f"{'='*60}")
    print(f"  Tổng số dòng đã quét:  {total}")
    print(f"  ✓ Sạch (clean):        {n_clean}  ({n_clean/total*100:.1f}%)")
    print(f"  ✗ Tấn công (attack):   {n_attack}  ({n_attack/total*100:.1f}%)")
    print(f"  ----- chi tiết theo mức độ ----")
    print(f"     🔴 CRITICAL: {bucket_counts['CRITICAL']}")
    print(f"     🟠 HIGH    : {bucket_counts['HIGH']}")
    print(f"     🟡 MEDIUM  : {bucket_counts['MEDIUM']}")
    print(f"     🔵 LOW     : {bucket_counts['LOW']}")
    print(f"{'='*60}")
    print(f"[DONE] Saved {n_attack} alerts to {path_out_alerts}")
    print(f"[DONE] Saved {total} scan records to {path_out_results}")

# ============================================================
# HÀM 3: EVALUATE — đánh giá đa-mô hình + vẽ biểu đồ so sánh
# ============================================================

def _safe_metrics(tp, fp, tn, fn):
    """Tính accuracy/precision/recall/F1/F2 (%, an toàn khi chia cho 0).

    F2-score = 5*P*R / (4P + R) — biến thể của F-score nhân hệ số 2 vào recall.
    Đây là metric chuẩn cho IDS vì miss-attack (FN) tệ hơn false-alarm (FP)
    rất nhiều: bỏ lọt 1 attack có thể là data breach, còn báo nhầm 1 request
    chỉ tốn analyst vài phút điều tra.
    """
    total = tp + fp + tn + fn
    acc  = (tp + tn) / total * 100 if total else 0
    prec = tp / (tp + fp) * 100 if (tp + fp) else 0
    rec  = tp / (tp + fn) * 100 if (tp + fn) else 0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    f2   = 5 * prec * rec / (4 * prec + rec) if (4 * prec + rec) else 0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "accuracy": acc, "precision": prec, "recall": rec,
            "f1": f1, "f2": f2}


def _load_labeled_log(path_log):
    """Đọc log có nhãn, trả về (items, labels, regex_hits_per_item)."""
    parser_combined = LogParser(LOG_FORMAT_COMBINED)
    parser_common   = LogParser(LOG_FORMAT_COMMON)
    items, labels, regex_hits, whitelisted = [], [], [], []
    n_total = 0
    with open(path_log, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            n_total += 1
            if n_total % 5000 == 0:
                print(f"    đã đọc {n_total} dòng...", end="\r")
            try:
                entry = parser_combined.parse(line)
            except Exception:
                try:
                    entry = parser_common.parse(line)
                except Exception:
                    continue
            parsed = parse_log_entry(entry)
            item = build_training_item(parsed)
            items.append(item)
            labels.append(1 if "(Simulated-Attack)" in parsed["user_agent"] else 0)
            regex_hits.append(len(detect_rule_based(parsed)) > 0)
            whitelisted.append(is_ai_whitelisted(item))
    print(f"    Đã đọc xong {n_total} dòng                ")
    return items, labels, regex_hits, whitelisted


def _confusion(predictions, labels):
    tp = fp = tn = fn = 0
    for p, y in zip(predictions, labels):
        if   y == 1 and p == 1: tp += 1
        elif y == 0 and p == 0: tn += 1
        elif y == 0 and p == 1: fp += 1
        elif y == 1 and p == 0: fn += 1
    return tp, fp, tn, fn


def _eval_unsup_hybrid(model_type, items, labels, regex_hits, whitelisted):
    """Đánh giá hybrid: regex hit OR (AI tier1 hit và không whitelisted)."""
    from models.ai_detector import LogAnomalyDetector
    ai = LogAnomalyDetector(model_type=model_type)
    if not ai.load_model():
        return None
    # Hydrate vocab để rule-tier hoạt động
    apache_log_vocab_backup = PATH_PARAM_VOCAB.copy() if isinstance(PATH_PARAM_VOCAB, dict) else {}
    globals()['PATH_PARAM_VOCAB'] = ai.path_param_vocab or {}
    try:
        preds = []
        for item, rhit, wl in zip(items, regex_hits, whitelisted):
            ai_hit = False
            if not wl:
                ai_hit = ai.predict(item["path"], item["query"], item["method"],
                                    item["status"], item.get("user_agent", ""),
                                    item.get("referer", ""))
            preds.append(1 if (rhit or ai_hit) else 0)
        tp, fp, tn, fn = _confusion(preds, labels)
        return _safe_metrics(tp, fp, tn, fn)
    finally:
        globals()['PATH_PARAM_VOCAB'] = apache_log_vocab_backup


def _eval_regex_only(regex_hits, labels):
    preds = [1 if r else 0 for r in regex_hits]
    tp, fp, tn, fn = _confusion(preds, labels)
    return _safe_metrics(tp, fp, tn, fn)


def _eval_supervised(algo, items, labels):
    """Đánh giá supervised model (RF hoặc LR) — không kèm regex."""
    from models.supervised_detector import SupervisedDetector
    sup = SupervisedDetector(algo=algo)
    if not sup.load_model():
        return None
    r = sup.evaluate_batch(items, labels)
    return _safe_metrics(r["tp"], r["fp"], r["tn"], r["fn"])


def _predict_all_tiers(items, regex_hits, whitelisted):
    """
    Chạy 3 tier 1 lần, cache kết quả (sup_prob, lof_hit) cho mỗi item.
    Trả về list of dict {regex_hit, sup_prob, lof_hit, whitelisted}.
    """
    from models.ai_detector import LogAnomalyDetector
    from models.supervised_detector import SupervisedDetector
    rf = SupervisedDetector(algo="rf")
    lof = LogAnomalyDetector(model_type="lof")
    if not rf.load_model() or not lof.load_model():
        return None
    apache_log_vocab_backup = PATH_PARAM_VOCAB.copy() if isinstance(PATH_PARAM_VOCAB, dict) else {}
    globals()['PATH_PARAM_VOCAB'] = lof.path_param_vocab or {}
    try:
        cache = []
        for item, rhit, wl in zip(items, regex_hits, whitelisted):
            sup_prob = 0.0; lof_hit = False
            if not wl:
                try:
                    sup_prob = rf.predict_proba(item["path"], item["query"], item["method"],
                                                item["status"], item.get("user_agent", ""),
                                                item.get("referer", ""))
                except Exception: pass
                try:
                    lof_hit = lof.predict(item["path"], item["query"], item["method"],
                                          item["status"], item.get("user_agent", ""),
                                          item.get("referer", ""))
                except Exception: pass
            cache.append({"regex": rhit, "sup_prob": sup_prob, "lof": lof_hit, "wl": wl})
        return cache
    finally:
        globals()['PATH_PARAM_VOCAB'] = apache_log_vocab_backup


def _eval_full_hybrid(items, labels, regex_hits, whitelisted, cache=None):
    """Naive Full Hybrid: regex OR (RF prob>=0.5) OR LOF — mọi tier OR với nhau."""
    if cache is None:
        cache = _predict_all_tiers(items, regex_hits, whitelisted)
    if cache is None:
        return None
    preds = [1 if (c["regex"] or c["sup_prob"] >= 0.5 or c["lof"]) else 0 for c in cache]
    tp, fp, tn, fn = _confusion(preds, labels)
    return _safe_metrics(tp, fp, tn, fn)


def _eval_smart_hybrid_voted(items, labels, regex_hits, whitelisted, cache=None):
    """
    Smart Hybrid — Majority voting (≥2 trong 3 tier đồng ý).
    Mỗi tier 1 phiếu:
      - regex_hit -> 1 phiếu
      - sup_prob >= 0.5 -> 1 phiếu
      - lof_hit -> 1 phiếu
    Cộng dồn, cần >=2 phiếu mới flag.
    => regex CHỈ 1 mình cũng không flag (tránh regex 0.86% FP nhân lên),
       LOF 1 mình không flag (tránh 1266 FP của LOF),
       phải có ≥ 2 tier đồng thuận.
    """
    if cache is None:
        cache = _predict_all_tiers(items, regex_hits, whitelisted)
    if cache is None:
        return None
    preds = []
    for c in cache:
        votes = (1 if c["regex"] else 0) + (1 if c["sup_prob"] >= 0.5 else 0) + (1 if c["lof"] else 0)
        preds.append(1 if votes >= 2 else 0)
    tp, fp, tn, fn = _confusion(preds, labels)
    return _safe_metrics(tp, fp, tn, fn)


def _eval_smart_hybrid_weighted(items, labels, regex_hits, whitelisted, cache=None):
    """
    Smart Hybrid — Weighted scoring với threshold đã calibrate.

    Score = 0.50 * regex_hit + 0.45 * sup_prob + 0.20 * lof_hit
    Threshold = 0.40

    Logic:
      - regex_hit (0.50)                 -> luôn fire (trust 99% precision)
      - sup_prob >= 0.89 (0.40 alone)    -> RF tự fire khi confidence rất cao
      - sup_prob >= 0.44 + lof (0.40)    -> RF trung bình + LOF -> fire (đồng thuận)
      - regex + sup low (>=0.50)         -> fire
      - lof_hit alone (0.20)             -> KHÔNG fire (giảm 1266 FP)
      - sup_prob alone 0.5-0.88          -> KHÔNG fire (giảm RF false alarms vùng xám)
    => Giữ recall của hybrid nhưng tăng precision rõ rệt.
    """
    if cache is None:
        cache = _predict_all_tiers(items, regex_hits, whitelisted)
    if cache is None:
        return None
    preds = []
    for c in cache:
        score = (0.50 if c["regex"] else 0.0) + 0.45 * c["sup_prob"] + (0.20 if c["lof"] else 0.0)
        preds.append(1 if score >= 0.40 else 0)
    tp, fp, tn, fn = _confusion(preds, labels)
    return _safe_metrics(tp, fp, tn, fn)


def _eval_smart_hybrid_consensus(items, labels, regex_hits, whitelisted, cache=None):
    """
    Smart Hybrid — Consensus: regex hoặc RF tự fire, LOF chỉ là tripwire
    cần xác nhận bởi tier khác.

      flag = regex_hit
          OR sup_prob >= 0.5
          OR (lof_hit AND sup_prob >= 0.3)   # LOF chỉ được tin khi RF cũng nghi ngờ
    """
    if cache is None:
        cache = _predict_all_tiers(items, regex_hits, whitelisted)
    if cache is None:
        return None
    preds = []
    for c in cache:
        flag = c["regex"] or (c["sup_prob"] >= 0.5) or (c["lof"] and c["sup_prob"] >= 0.3)
        preds.append(1 if flag else 0)
    tp, fp, tn, fn = _confusion(preds, labels)
    return _safe_metrics(tp, fp, tn, fn)


def _plot_comparison(results, out_dir="analysis/charts", title_suffix=""):
    """Vẽ grouped bar chart so sánh tất cả model trên 5 metric (thêm F2)."""
    import numpy as np
    os.makedirs(out_dir, exist_ok=True)
    valid = [(n, r) for n, r in results if r is not None]
    models = [n for n, _ in valid]
    accs   = [r["accuracy"]  for _, r in valid]
    precs  = [r["precision"] for _, r in valid]
    recs   = [r["recall"]    for _, r in valid]
    f1s    = [r["f1"]        for _, r in valid]
    f2s    = [r["f2"]        for _, r in valid]

    # Xác định winner theo từng metric để highlight
    def _argmax(vals):
        return max(range(len(vals)), key=lambda i: vals[i])
    winner_f1 = _argmax(f1s)
    winner_f2 = _argmax(f2s)

    x = np.arange(len(models))
    width = 0.16
    fig, ax = plt.subplots(figsize=(17, 8))
    bars_acc  = ax.bar(x - 2*width, accs,  width, label='Accuracy',  color='#4C72B0')
    bars_prec = ax.bar(x - 1*width, precs, width, label='Precision', color='#55A868')
    bars_rec  = ax.bar(x + 0*width, recs,  width, label='Recall',    color='#C44E52')
    bars_f1   = ax.bar(x + 1*width, f1s,   width, label='F1-Score',  color='#8172B2')
    bars_f2   = ax.bar(x + 2*width, f2s,   width, label='F2-Score (IDS)', color='#CCB974')

    ax.set_xlabel('Cấu hình mô hình', fontsize=12)
    ax.set_ylabel('Tỷ lệ (%)', fontsize=12)
    ax.set_title(f'So sánh hiệu năng các mô hình IDS{title_suffix}', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(models, rotation=22, ha='right', fontsize=9)
    ax.legend(loc='lower right', fontsize=9, ncol=5)
    ax.set_ylim(0, 115)
    ax.grid(axis='y', linestyle='--', alpha=0.4)

    # Số trên đầu mỗi cột
    for bars, vals in [(bars_acc, accs), (bars_prec, precs), (bars_rec, recs),
                       (bars_f1, f1s), (bars_f2, f2s)]:
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width()/2, v + 1.0,
                    f"{v:.1f}", ha='center', fontsize=7, rotation=0)

    # Đánh dấu winner F1 và F2
    ax.annotate('** F1 best **', xy=(winner_f1 + 1*width, f1s[winner_f1] + 4),
                ha='center', fontsize=9, color='#8172B2', fontweight='bold')
    if winner_f2 != winner_f1:
        ax.annotate('** F2 best **', xy=(winner_f2 + 2*width, f2s[winner_f2] + 7),
                    ha='center', fontsize=9, color='#7A5A00', fontweight='bold')

    plt.tight_layout()
    out_path = os.path.join(out_dir, "model_comparison.png")
    plt.savefig(out_path, dpi=150, bbox_inches='tight')
    print(f"[CHART] Đã lưu biểu đồ: {out_path}")
    try:
        plt.show()
    except Exception:
        pass


def _plot_confusion_grid(results, out_dir="analysis/charts"):
    """Vẽ subplot confusion matrix cho từng mô hình."""
    import numpy as np
    os.makedirs(out_dir, exist_ok=True)
    valid = [(n, r) for n, r in results if r is not None]
    n = len(valid)
    cols = 4
    rows = (n + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(4*cols, 3.2*rows))
    axes = axes.flatten() if n > 1 else [axes]
    for i, (name, r) in enumerate(valid):
        ax = axes[i]
        cm = np.array([[r["tn"], r["fp"]], [r["fn"], r["tp"]]])
        im = ax.imshow(cm, cmap='Blues')
        ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
        ax.set_xticklabels(['Pred Clean', 'Pred Attack'], fontsize=9)
        ax.set_yticklabels(['True Clean', 'True Attack'], fontsize=9)
        ax.set_title(f"{name}\nF1={r['f1']:.1f}  F2={r['f2']:.1f}", fontsize=9)
        for ii in range(2):
            for jj in range(2):
                txt_color = 'white' if cm[ii, jj] > cm.max() * 0.5 else 'black'
                ax.text(jj, ii, f"{cm[ii, jj]}", ha='center', va='center',
                        color=txt_color, fontsize=11, fontweight='bold')
    for j in range(n, len(axes)):
        axes[j].axis('off')
    plt.tight_layout()
    out_path = os.path.join(out_dir, "confusion_matrices.png")
    plt.savefig(out_path, dpi=150, bbox_inches='tight')
    print(f"[CHART] Đã lưu biểu đồ: {out_path}")
    try:
        plt.show()
    except Exception:
        pass


def evaluate_all_models(path_log):
    """
    Đánh giá nhiều cấu hình mô hình cùng lúc trên file log có nhãn:
      1. Regex only       (Tier 1 baseline)
      2. Hybrid IF        (regex + Isolation Forest)
      3. Hybrid OCSVM     (regex + One-Class SVM)
      4. Hybrid LOF       (regex + Local Outlier Factor)
      5. Supervised RF    (không regex, chỉ Random Forest)
      6. Supervised LR    (không regex, chỉ Logistic Regression)
      7. Full Hybrid      (regex + RF + LOF — production stack)

    In bảng kết quả + lưu biểu đồ PNG.
    """
    print(f"\n[*] Đánh giá toàn bộ hệ thống trên: {path_log}")
    items, labels, regex_hits, whitelisted = _load_labeled_log(path_log)
    n_total = len(labels)
    n_attack = sum(labels)
    n_clean  = n_total - n_attack
    print(f"    {n_total} dòng | {n_attack} attack ({n_attack/n_total*100:.1f}%) | {n_clean} clean")

    results = []
    print("\n[1/10] Regex only ...");          results.append(("Regex only",  _eval_regex_only(regex_hits, labels)))
    print("[2/10] Hybrid IF ...");             results.append(("Hybrid IF",    _eval_unsup_hybrid("if",    items, labels, regex_hits, whitelisted)))
    print("[3/10] Hybrid OCSVM ...");          results.append(("Hybrid OCSVM", _eval_unsup_hybrid("ocsvm", items, labels, regex_hits, whitelisted)))
    print("[4/10] Hybrid LOF ...");            results.append(("Hybrid LOF",   _eval_unsup_hybrid("lof",   items, labels, regex_hits, whitelisted)))
    print("[5/10] Supervised RF ...");         results.append(("Supervised RF", _eval_supervised("rf", items, labels)))
    print("[6/10] Supervised LR ...");         results.append(("Supervised LR", _eval_supervised("lr", items, labels)))

    # Chia sẻ cache giữa 4 fusion configurations cuối để khỏi predict lại 4x
    print("[7-10/10] Computing tier cache for fusion configs ...")
    fusion_cache = _predict_all_tiers(items, regex_hits, whitelisted)

    print("[7/10] Full Hybrid (R OR RF OR LOF) — naive OR ...")
    results.append(("Full Hybrid (R OR RF OR LOF)", _eval_full_hybrid(items, labels, regex_hits, whitelisted, cache=fusion_cache)))
    print("[8/10] Smart Hybrid — Voted (≥2 tiers) ...")
    results.append(("Smart Hybrid (Voted ≥2)", _eval_smart_hybrid_voted(items, labels, regex_hits, whitelisted, cache=fusion_cache)))
    print("[9/10] Smart Hybrid — Weighted score ...")
    results.append(("Smart Hybrid (Weighted)", _eval_smart_hybrid_weighted(items, labels, regex_hits, whitelisted, cache=fusion_cache)))
    print("[10/10] Smart Hybrid — Consensus (LOF cần RF xác nhận) ...")
    results.append(("Smart Hybrid (Consensus)", _eval_smart_hybrid_consensus(items, labels, regex_hits, whitelisted, cache=fusion_cache)))

    # ==== Bảng kết quả ====
    width = 108
    print("\n" + "=" * width)
    print(f"  KẾT QUẢ ĐÁNH GIÁ TỔNG HỢP — {os.path.basename(path_log)}")
    print(f"  ({n_total} dòng, {n_attack} attack, {n_clean} clean)")
    print("=" * width)
    print(f"  {'Cấu hình':<32} {'TP':>5} {'FP':>5} {'TN':>5} {'FN':>5} "
          f"{'Acc':>7} {'Prec':>7} {'Rec':>7} {'F1':>7} {'F2*':>7}")
    print("-" * width)
    for name, r in results:
        if r is None:
            print(f"  {name:<32} [LỖI: model chưa được train hoặc không load được]")
            continue
        print(f"  {name:<32} {r['tp']:>5} {r['fp']:>5} {r['tn']:>5} {r['fn']:>5} "
              f"{r['accuracy']:>6.2f}% {r['precision']:>6.2f}% {r['recall']:>6.2f}% "
              f"{r['f1']:>6.2f} {r['f2']:>6.2f}")
    print("=" * width)
    print("  * F2 = 5·P·R / (4P + R) — chuẩn IDS, nhân hệ số 2 vào recall vì miss-attack")
    print("    nguy hiểm hơn false-alarm rất nhiều.")

    # ==== Lưu JSON cho post-process ====
    os.makedirs("analysis/charts", exist_ok=True)
    json_path = "analysis/charts/evaluation_results.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "file": path_log,
            "n_total": n_total, "n_attack": n_attack, "n_clean": n_clean,
            "results": [{"model": n, "metrics": r} for n, r in results],
        }, f, ensure_ascii=False, indent=2)
    print(f"\n[JSON] Đã lưu kết quả: {json_path}")

    # ==== Vẽ biểu đồ so sánh ====
    suffix = f"\n({os.path.basename(path_log)} — {n_attack} attacks, {n_clean} clean)"
    _plot_comparison(results, title_suffix=suffix)
    _plot_confusion_grid(results)


def monitor_realtime(ai_engine, supervised_engine=None, jsonl_path=None):
    if jsonl_path is None:
        jsonl_path = _runtime_path("monitor_alerts.jsonl")
    """
    3-tier hybrid real-time monitor.

      Tier 1 — Regex/rules (signatures + PARAM_TAMPERING + HTTP_METHOD_TAMPERING)
               High precision (~99.8%), fires on known attack patterns.
      Tier 2 — Supervised classifier (RandomForest, 22 features)
               High recall on attack types seen during training (~95% on CSIC).
      Tier 3 — Unsupervised anomaly model (LOF by default)
               Tripwire for novel anomalies the supervised model wasn't trained on.

    Threat scoring (weighted, 0.0 - 1.0):
        regex hit         -> +0.45   (most trusted signal)
        supervised hit    -> +0.40 * p_attack
        unsupervised hit  -> +0.20
    Bucketing:
        CRITICAL >= 0.75 ; HIGH >= 0.45 ; MEDIUM >= 0.25 ; LOW > 0
    """
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    has_sup = supervised_engine is not None and getattr(supervised_engine, 'model', None) is not None
    has_unsup = ai_engine is not None and getattr(ai_engine, 'model', None) is not None

    print(f"{CYAN}" + "=" * 76)
    print(" 🛡️  HYBRID REAL-TIME WEB IDS (3-TIER)")
    print(f" [TIER 1 REGEX]      ALWAYS ON ({len(PATH_PARAM_VOCAB)} learned paths in vocab)")
    print(f" [TIER 2 SUPERVISED] {'LOADED ('+supervised_engine.algo.upper()+')' if has_sup else 'NOT LOADED'}")
    print(f" [TIER 3 UNSUPERV.]  {'LOADED ('+ai_engine.model_type.upper()+')' if has_unsup else 'NOT LOADED'}")
    print(f" [INPUT]             stdin   (one log line per row, Ctrl+C to stop)")
    print(f" [ALERT LOG]         {jsonl_path or '(disabled)'}")
    print("=" * 76 + f"{RESET}\n")

    # Truncate previous alert log so the dashboard sees only this session's alerts.
    # Comment out the next 3 lines if you'd rather append across sessions.
    if jsonl_path:
        with open(jsonl_path, "w", encoding="utf-8") as _f:
            pass

    parser_combined = LogParser(LOG_FORMAT_COMBINED)
    parser_common = LogParser(LOG_FORMAT_COMMON)

    n_total = n_alerts = 0
    bucket_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            n_total += 1

            try:
                entry = parser_combined.parse(line)
            except Exception:
                try:
                    entry = parser_common.parse(line)
                except Exception:
                    continue

            parsed_data = parse_log_entry(entry)
            training_item = build_training_item(parsed_data)
            client_ip = parsed_data["client_ip"]
            method    = parsed_data["method"]
            raw_url   = parsed_data["raw_url"]

            whitelisted = is_ai_whitelisted(training_item)

            # ---------- Tier 1: regex / vocab / method tampering ----------
            rule_matches = detect_rule_based(parsed_data)
            rule_ids = sorted({m["id"] for m in rule_matches})

            # ---------- Tier 2: supervised classifier ----------
            sup_hit = False
            sup_prob = 0.0
            if has_sup and not whitelisted:
                try:
                    sup_prob = supervised_engine.predict_proba(
                        training_item["path"], training_item["query"],
                        training_item["method"], training_item["status"],
                        training_item.get("user_agent", ""), training_item.get("referer", "")
                    )
                    sup_hit = sup_prob >= 0.5
                except Exception:
                    sup_hit, sup_prob = False, 0.0

            # ---------- Tier 3: unsupervised tripwire ----------
            unsup_hit = False
            if has_unsup and not whitelisted:
                try:
                    unsup_hit = ai_engine.predict(
                        training_item["path"], training_item["query"],
                        training_item["method"], training_item["status"],
                        training_item.get("user_agent", ""), training_item.get("referer", "")
                    )
                except Exception:
                    unsup_hit = False

            # ---------- Threat score (weighted) + Smart Hybrid Consensus fusion ----------
            # Score chỉ dùng để hiển thị mức độ; quyết định alert vẫn theo logic Smart Hybrid
            # Consensus (F1=90.5, F2=92.8 trên benchmark):
            #   alert = regex_hit OR (sup_prob >= 0.5) OR (lof_hit AND sup_prob >= 0.3)
            # => Bỏ trường hợp "LOF alone không có RF nghi ngờ" — đã giảm 1266 FP của LOF
            #    xuống còn ~776 trên combined_labeled_eval.log.
            score = 0.0
            if rule_ids:
                score += 0.45
            if sup_hit:
                score += 0.40 * sup_prob
            if unsup_hit:
                score += 0.20

            # Smart Hybrid Consensus quyết định có emit alert hay không
            should_alert = bool(rule_ids) or sup_hit or (unsup_hit and sup_prob >= 0.3)
            if not should_alert:
                continue  # LOF một mình + RF p<0.3 -> không tin tưởng, bỏ qua

            if score >= 0.75:
                level, color = "CRITICAL", RED
            elif score >= 0.45:
                level, color = "HIGH", RED
            elif score >= 0.25:
                level, color = "MEDIUM", YELLOW
            else:
                level, color = "LOW", CYAN

            n_alerts += 1
            bucket_counts[level] += 1

            sources = []
            if rule_ids:
                sources.append(f"REGEX({','.join(rule_ids)})")
            if sup_hit:
                sources.append(f"SUPERVISED({supervised_engine.algo.upper()},p={sup_prob:.2f})")
            if unsup_hit:
                sources.append(f"UNSUPERVISED({ai_engine.model_type.upper()})")

            now = datetime.now()
            timestamp = now.strftime("%H:%M:%S")
            print(f"{color}[{level}]{RESET} {timestamp} | IP: {client_ip} "
                  f"| Threat {BOLD}{score:.2f}{RESET}")
            print(f"   {MAGENTA}Tiers:{RESET}   {' + '.join(sources)}")
            print(f"   {YELLOW}Request:{RESET} {method} {raw_url}")
            print(f"   {DIM}line #{n_total}{RESET}")
            print("-" * 76, flush=True)

            # Structured JSONL output for the Streamlit dashboard
            if jsonl_path:
                rec = {
                    "ts":         now.isoformat(timespec="seconds"),
                    "level":      level,
                    "score":      round(score, 3),
                    "client_ip":  client_ip,
                    "method":     method,
                    "raw_url":    raw_url,
                    "tiers":      sources,
                    "rule_ids":   rule_ids,
                    "sup_prob":   round(sup_prob, 3) if has_sup else None,
                    "lof_hit":    bool(unsup_hit),
                    "line_no":    n_total,
                }
                try:
                    with open(jsonl_path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(rec) + "\n")
                except Exception:
                    pass  # never let dashboard logging break the monitor

    except KeyboardInterrupt:
        pass

    # ---- summary ----
    print(f"\n{GREEN}[STOP] Monitoring finished.{RESET}")
    print(f"  Lines processed: {n_total}")
    print(f"  Alerts:          {n_alerts} "
          f"(CRITICAL={bucket_counts['CRITICAL']}, HIGH={bucket_counts['HIGH']}, "
          f"MEDIUM={bucket_counts['MEDIUM']}, LOW={bucket_counts['LOW']})")


def parse_log_entry(entry):
    """
    Parse một dòng Apache log thành dạng chuẩn dùng chung cho toàn hệ thống
    """

    try:
        request_line = entry.request_line
    except Exception:
        request_line = ""

    # ===== Parse request line =====
    method, raw_url, protocol = "", "", ""
    parts = request_line.split()
    if len(parts) >= 3:
        method = parts[0]
        protocol = parts[-1]
        raw_url = " ".join(parts[1:-1])  # giữ nguyên URL có space
    elif len(parts) == 2:
        method, raw_url = parts
    elif len(parts) == 1:
        raw_url = parts[0]

    # ===== Decode URL =====
    try:
        decoded_url = urllib.parse.unquote(raw_url)
    except Exception:
        decoded_url = raw_url

    # ===== Parse path + query =====
    try:
        parsed_url = urllib.parse.urlparse(decoded_url)
        path = parsed_url.path or "/"
        query = parsed_url.query or ""
        params = urllib.parse.parse_qs(query)
    except Exception:
        path = decoded_url
        query = ""
        params = {}

    # ===== Lấy User-Agent =====
    ua = ""
    try:
        ua = entry.headers_in.get("User-Agent", "")
    except Exception:
        ua = ""

    # ===== Lấy Referer (cho Phase 3 feature) =====
    referer = ""
    try:
        referer = entry.headers_in.get("Referer", "") or ""
    except Exception:
        referer = ""

    # ===== Trả về dict chuẩn =====
    return {
        "client_ip": getattr(entry, "remote_host", ""),
        "status": getattr(entry, "final_status", 0),
        "method": method,
        "raw_url": raw_url,
        "decoded_url": decoded_url,
        "path": path or "/",
        "query": query,
        "params": params,
        "user_agent": ua,
        "referer": referer
    }

def build_training_item(parsed_data):
    """
    Chuẩn hóa dữ liệu đầu vào cho AI detector.
    Phase 3: bổ sung user_agent + referer phục vụ feature extraction.
    """
    return {
        "path": parsed_data["path"],
        "query": parsed_data["query"],
        "method": parsed_data["method"],
        "status": parsed_data["status"],
        "user_agent": parsed_data.get("user_agent", ""),
        "referer": parsed_data.get("referer", "")
    }

# ===== DETECTION HELPERS =====

def detect_rule_based(parsed_data):
    """
    Chạy toàn bộ luật phát hiện tấn công dựa trên regex/signature.
    Trả về danh sách matches.
    """
    path = parsed_data["path"]
    query = parsed_data["query"]
    params = parsed_data["params"]
    ua = parsed_data["user_agent"]
    method = parsed_data.get("method", "")

    matches = []

    # Phase 3.1 (B-side, defensive): URL-decode the payload before the regex
    # pass so that triple-encoded SQLi like %2527OR%2527a%253D%2527a (-> 'OR'a'='a)
    # actually gets matched by SQLI_RE.
    decoded_layer = f"{path} {query}"
    for _ in range(3):
        nxt = unquote(decoded_layer)
        if nxt == decoded_layer:
            break
        decoded_layer = nxt
    payload_to_check = decoded_layer

    if res := check_sqli(payload_to_check):
        matches.append(res)

    if res := check_xss(payload_to_check):
        matches.append(res)

    if res := check_lfi(payload_to_check):
        matches.append(res)

    if res := check_cmd_injection(payload_to_check):
        matches.append(res)

    if res := check_rfi(params):
        matches.append(res)

    if res := check_sensitive_files(path):
        matches.append(res)

    if res := check_scanner_ua(ua):
        matches.append(res)

    # Phase 3.1 (E): hard rule for unusual HTTP methods
    if res := check_method_tampering(method, path):
        matches.append(res)

    # Phase 3.1 (B as hard rule): unknown param names per endpoint
    if res := check_param_tampering(path, query, PATH_PARAM_VOCAB):
        matches.append(res)

    return matches

def is_ai_whitelisted(item):
    """
    Trả về True nếu request là tài nguyên tĩnh "vô hại" — bỏ qua tầng AI để giảm noise.

    LƯU Ý: phải dùng endswith() chứ không phải substring,
    nếu không '.jsp' (JavaServer Pages) sẽ chứa '.js' và bị whitelist nhầm.
    """
    path = str(item.get("path", "")).lower()
    status = str(item.get("status", ""))

    static_extensions = (
        ".css", ".js", ".mjs",
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
        ".woff", ".woff2", ".ttf", ".eot",
        ".map",
    )
    if any(path.endswith(ext) for ext in static_extensions):
        return True

    well_known = ("favicon.ico", "robots.txt", "sitemap.xml", "apple-touch-icon")
    if any(wk in path for wk in well_known):
        return True

    if status == "408":
        return True

    return False

def should_debug_ai_item(item):
    """
    Xác định request có cần in debug AI hay không.
    """
    full_url_check = str(item.get("path", "")) + str(item.get("query", ""))
    decoded_check = unquote(full_url_check).lower()

    keywords = ["rm ", "wget", "union", "'1'='1", "sleep", "cat "]
    return any(k in decoded_check for k in keywords)

def print_ai_debug(ai_engine, line_no, item):
    """
    In thông tin debug cho các payload nghi ngờ quan trọng.
    """
    full_url_check = str(item.get("path", "")) + str(item.get("query", ""))
    decoded_check = unquote(full_url_check)

    print(f"\n[DEBUG] Line {line_no} Payload: {decoded_check}")
    feats = ai_engine.extract_features(
        item["path"],
        item["query"],
        item["method"],
        item["status"],
        item.get("user_agent", ""),
        item.get("referer", "")
    )
    print(f"[DEBUG] Vector đặc trưng: {feats}")

# ===== BEHAVIOR HELPERS =====

def update_behavior_stats(parsed_data, ip_activity, ip_paths, ip_401_counts):
    """
    Cập nhật thống kê hành vi theo IP.
    """
    client_ip = parsed_data["client_ip"]
    path = parsed_data["path"]
    status = parsed_data["status"]

    ip_activity[client_ip] += 1
    ip_paths[client_ip].add(path)

    if status in (401, 403):
        ip_401_counts[client_ip] += 1

def analyze_behavior(ip_paths):
    """
    Phân tích hành vi scan theo số lượng path khác nhau mà mỗi IP truy cập.
    Trả về danh sách alert hành vi.
    """
    behavior_alerts = []

    print("\n[BEHAVIOR MODULE] Analyzing traffic patterns...")
    for ip, paths in ip_paths.items():
        if len(paths) >= 10:
            print(f"[BEHAVIOR] IP {ip} scan {len(paths)} paths -> DETECTED!")
            behavior_alerts.append(build_behavior_alert(ip, len(paths)))

    return behavior_alerts

# ===== ALERT HELPERS =====

def build_alert(line_no, client_ip, matches, detail):
    """
    Tạo alert theo format chuẩn.
    """
    return {
        "line_no": line_no,
        "client_ip": client_ip,
        "matches": matches,
        "detail": detail
    }


def build_ai_alert(line_no, detail, client_ip="Check_Log"):
    """
    Tạo alert cho tầng AI anomaly detection.
    """
    return {
        "line_no": line_no,
        "client_ip": client_ip,
        "matches": [{
            "id": "AI_ANOMALY",
            "desc": "Abnormal request structure detected by ML"
        }],
        "detail": detail
    }

def build_behavior_alert(client_ip, unique_path_count):
    """
    Tạo alert cho hành vi quét diện rộng.
    """
    return {
        "line_no": "SUMMARY",
        "client_ip": client_ip,
        "matches": [{
            "id": "BEHAVIOR_SCANNING",
            "desc": f"Suspicious behavior: Accessed {unique_path_count} unique paths (Port/Dir Scan suspected)"
        }],
        "detail": "Summary Report"
    }

def save_alerts(alerts, path_out_alerts):
    """
    Ghi toàn bộ alerts ra file jsonl.
    """
    with open(path_out_alerts, "w", encoding="utf-8") as f:
        for alert in alerts:
            f.write(json.dumps(alert) + "\n")


if __name__ == "__main__":
    from models.ai_detector import LogAnomalyDetector

    if len(sys.argv) < 3:
        print("Usage: python apache_log.py [train|scan|monitor|evaluate] [logfile] [model_type]")
        print("model_type: if, ocsvm, lof (Mặc định: if)")
        sys.exit(1)

    mode = sys.argv[1]
    log_file = sys.argv[2]
    
    # Lấy model_type từ cli
    model_type = sys.argv[3] if len(sys.argv) >= 4 else "if"
    
    print(f"\n[*] KHỞI TẠO HỆ THỐNG VỚI MÔ HÌNH AI: {model_type.upper()}")
    ai_engine = LogAnomalyDetector(model_type=model_type)

    # Phase 3.1 (B as hard rule): on scan/evaluate/monitor, load the trained
    # vocab into the module-level dict so detect_rule_based() can use it for
    # the PARAM_TAMPERING rule. (train mode builds vocab itself.)
    def _hydrate_vocab():
        global PATH_PARAM_VOCAB
        if ai_engine.path_param_vocab:
            PATH_PARAM_VOCAB = ai_engine.path_param_vocab
            print(f"[RULES] PARAM_TAMPERING rule loaded ({len(PATH_PARAM_VOCAB)} paths)")

    if mode == "train":
        # Truyền ai_engine vào hàm analyze_log
        analyze_log(log_file, ai_engine=ai_engine, mode="train")

    elif mode == "scan":
        # Auto-load supervised RF nếu có để scan dùng đủ 3-tier.
        # ai_engine (unsupervised) sẽ được load bên trong analyze_log.
        if ai_engine.load_model():
            _hydrate_vocab()
        sup_engine_scan = None
        try:
            from models.supervised_detector import SupervisedDetector
            cand = SupervisedDetector(algo="rf")
            if cand.load_model():
                sup_engine_scan = cand
            else:
                print("⚠️  Supervised RF chưa được train — scan chạy 2-tier (regex + unsupervised).")
        except Exception as e:
            print(f"⚠️  Không load được supervised RF: {e}")
        analyze_log(log_file, ai_engine=ai_engine,
                    supervised_engine=sup_engine_scan, mode="scan")

    elif mode == "monitor":
        # In hybrid monitor mode the positional ai_engine is the unsupervised
        # tripwire (default: LOF — best unsupervised on CSIC). On top of that
        # we try to auto-load a supervised RF (Tier 2). If neither is present
        # we still run Tier 1 regex/vocab/method-tamper rules.
        if model_type == "if":  # the CLI default isn't great for monitor — promote to lof
            print("[*] Monitor mode: promoting tripwire model from IF -> LOF (more sensitive).")
            ai_engine = LogAnomalyDetector(model_type="lof")

        unsup_loaded = ai_engine.load_model()
        if unsup_loaded:
            _hydrate_vocab()
        else:
            print("⚠️  Tier 3 unsupervised model not found — running with regex + supervised only.")

        # Try to attach the supervised RF as Tier 2
        sup_engine = None
        try:
            from models.supervised_detector import SupervisedDetector
            sup_candidate = SupervisedDetector(algo="rf")
            if sup_candidate.load_model():
                sup_engine = sup_candidate
                # NOTE: deliberately do NOT replace PATH_PARAM_VOCAB with the
                # supervised vocab — the supervised model was trained on a mix
                # of normal AND attack lines, so its vocab[path] includes
                # attack-generated param names (e.g. precioA, modoA, B1A).
                # The Tier 1 PARAM_TAMPERING rule must stay anchored to the
                # CLEAN unsupervised vocab (built from attack-free training
                # data) so it can still flag those exact tamperings.
            else:
                print("⚠️  Tier 2 supervised model not found — running with regex + unsupervised only.")
        except Exception as e:
            print(f"⚠️  Could not load supervised model: {e}")

        if not unsup_loaded and sup_engine is None:
            print("[FATAL] No AI tier available. Please run train (and analysis/supervised_vs_unsupervised.py) first.")
            sys.exit(1)

        monitor_realtime(ai_engine if unsup_loaded else None, supervised_engine=sup_engine)

    elif mode == "evaluate":
        # Đa-mô hình: không cần truyền model_type, hàm sẽ tự load tất cả model có sẵn
        # và đánh giá song song để in bảng + vẽ biểu đồ so sánh.
        evaluate_all_models(log_file)