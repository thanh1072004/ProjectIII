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

def analyze_log(path_log, ai_engine, path_out_alerts="alerts.jsonl", mode="scan"):
    parser_combined = LogParser(LOG_FORMAT_COMBINED)
    parser_common = LogParser(LOG_FORMAT_COMMON)
    alerts = []

    # Thống kê
    ip_activity = defaultdict(int)
    ip_paths = defaultdict(set)
    ip_401_counts = defaultdict(int)
    training_data = []

    print(f"[*] Starting {mode} on {path_log}...")
            
    with open(path_log, "r", encoding="utf-8", errors="replace") as f_in:
        for line_no, line in enumerate(f_in, start=1):
            line = line.strip()
            if not line:
                continue

            # NÂNG CẤP: Fallback Parsing
            try:
                # Thử parse chuẩn Combined (có User-Agent) trước
                entry = parser_combined.parse(line)
            except Exception:
                try:
                    # Nếu lỗi, thử parse chuẩn Common (NASA 1995)
                    entry = parser_common.parse(line)
                except Exception:
                    # Nếu vẫn lỗi thì mới bỏ qua dòng này
                    continue

            # ===== Parse chung =====
            parsed_data = parse_log_entry(entry)
            
            # ===== Build training item chung =====
            training_item = build_training_item(parsed_data)
            training_data.append(training_item)

            # Nếu đang mode train thì chỉ thu thập dữ liệu
            if mode == "train":
                continue

            # ===== Rule-based detection chung =====
            matches = detect_rule_based(parsed_data)

            # ===== Behavior stats chung =====
            update_behavior_stats(parsed_data, ip_activity, ip_paths, ip_401_counts)

            if matches:
                alert = build_alert(
                    line_no=line_no,
                    client_ip=parsed_data["client_ip"],
                    matches=matches,
                    detail=f"{parsed_data['method']} {parsed_data['raw_url']}"
                )
                alerts.append(alert)
                print(f"[REGEX] Line {line_no} | {matches[0]['id']}")

    if mode == "train":
        print(f"[*] Training AI model ({ai_engine.model_type.upper()}) with {len(training_data)} entries...")
        
        # Xóa file model cũ nếu tồn tại (dùng tên file linh hoạt theo model_type)
        if os.path.exists(ai_engine.model_path):
            os.remove(ai_engine.model_path)
            
        # Xóa file scaler cũ nếu tồn tại
        if os.path.exists(ai_engine.scaler_path):
            os.remove(ai_engine.scaler_path)
            
        ai_engine.train(training_data)
        return

    if mode == "scan":
        if ai_engine.load_model():
            print("\n[AI MODULE] Scanning for anomalies...")
            ai_alerts = 0

            for idx, item in enumerate(training_data, start=1):
                is_anomaly = ai_engine.predict(
                    item["path"],
                    item["query"],
                    item["method"],
                    item["status"],
                    item.get("user_agent", ""),
                    item.get("referer", "")
                )

                if should_debug_ai_item(item):
                    print_ai_debug(ai_engine, idx, item)

                if is_anomaly:
                    # Whitelist chung
                    if is_ai_whitelisted(item):
                        continue

                    print(f"[AI] Line {idx} -> Anomaly Detected: {item['method']} {item['path']}")
                    alerts.append(
                        build_ai_alert(
                            line_no=idx,
                            detail=f"{item['method']} {item['path']}?{item['query']}"
                        )
                    )
                    ai_alerts += 1

            print(f"[AI] Finished. Found {ai_alerts} anomalies missed by Regex.")
        else:
            print("[AI] No model found. Run 'train' mode first.")

    # ===== Behavior analysis chung =====
    behavior_alerts = analyze_behavior(ip_paths)
    alerts.extend(behavior_alerts)

    # ===== Save alerts chung =====
    save_alerts(alerts, path_out_alerts)
    print(f"\n[DONE] Saved {len(alerts)} alerts to {path_out_alerts}")

# --- HÀM 3: EVALUATE MODEL (Chấm điểm hiệu năng trên Dataset có nhãn) ---
def evaluate_model(path_log, ai_engine):
    print(f"\n[*] Đang chấm điểm hệ thống trên file: {path_log}")

    # Load model
    if not ai_engine.load_model():
        print("[LỖI] Cần train model trước khi evaluate!")
        return

    parser_combined = LogParser(LOG_FORMAT_COMBINED)
    parser_common = LogParser(LOG_FORMAT_COMMON)

    # Ma trận nhầm lẫn
    TP = 0  # Attack thật -> Bắt được
    TN = 0  # Log sạch -> Bỏ qua
    FP = 0  # Log sạch -> Báo nhầm
    FN = 0  # Attack thật -> Bỏ sót

    total_lines = 0

    for line_no, line in enumerate(open(path_log, "r", encoding="utf-8", errors="replace"), start=1):
        # Loại bỏ khoảng trắng/xuống dòng dư thừa
        line = line.strip()
        if not line:
            continue
            
        total_lines += 1
        if total_lines % 500 == 0:
            print(f"    Processing line {total_lines}...", end="\r")

        # NÂNG CẤP 2: Logic Fallback Parsing
        try:
            # Thử chuẩn Combined trước
            entry = parser_combined.parse(line)
        except Exception:
            try:
                # Nếu lỗi, thử chuẩn Common
                entry = parser_common.parse(line)
            except Exception:
                # Cả 2 đều lỗi thì bỏ qua dòng log hỏng này
                continue

        # ===== Parse chung =====
        parsed_data = parse_log_entry(entry)

        # ===== Ground truth =====
        ua = parsed_data["user_agent"]
        is_actual_attack = "(Simulated-Attack)" in ua

        # ===== Rule-based detection chung =====
        matches = detect_rule_based(parsed_data)
        regex_hit = len(matches) > 0

        # ===== AI detection =====
        training_item = build_training_item(parsed_data)
        ai_hit = ai_engine.predict(
            training_item["path"],
            training_item["query"],
            training_item["method"],
            training_item["status"],
            training_item.get("user_agent", ""),
            training_item.get("referer", "")
        )

        # ===== AI whitelist chung =====
        if ai_hit and is_ai_whitelisted(training_item):
            ai_hit = False

        # ===== Fusion =====
        system_detected = regex_hit or ai_hit

        # ===== Cập nhật confusion matrix =====
        if is_actual_attack and system_detected:
            TP += 1
        elif not is_actual_attack and not system_detected:
            TN += 1
        elif not is_actual_attack and system_detected:
            FP += 1
        elif is_actual_attack and not system_detected:
            FN += 1

    # ===== Báo cáo kết quả =====
    print("\n" + "=" * 50)
    print("   KẾT QUẢ ĐÁNH GIÁ HIỆU NĂNG (PERFORMANCE REPORT)")
    print("=" * 50)
    print(f"Tổng số dòng log: {total_lines}")
    print(f"Thực tế Tấn công: {TP + FN}")
    print(f"Thực tế Sạch:     {TN + FP}")
    print("-" * 30)

    print(f"✅ True Positives (Bắt đúng tấn công): {TP}")
    print(f"❌ False Negatives (Bỏ sót tấn công):  {FN}")
    print(f"🛡️  True Negatives (Bỏ qua log sạch):   {TN}")
    print(f"⚠️  False Positives (Báo nhầm sạch):    {FP}")
    print("-" * 30)

    accuracy = 0
    precision = 0
    recall = 0
    f1_score = 0

    try:
        accuracy = (TP + TN) / total_lines * 100 if total_lines > 0 else 0
        precision = TP / (TP + FP) * 100 if (TP + FP) > 0 else 0
        recall = TP / (TP + FN) * 100 if (TP + FN) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        print(f"📊 ĐỘ CHÍNH XÁC (ACCURACY):  {accuracy:.2f}%")
        print(f"🎯 PRECISION (Độ tin cậy):   {precision:.2f}%")
        print(f"🔍 RECALL (Tỷ lệ phát hiện): {recall:.2f}%")
        print(f"⭐ F1-SCORE:                 {f1_score:.2f}")
    except Exception:
        print("Lỗi tính toán (chia cho 0). Kiểm tra lại dữ liệu.")

    print("=" * 50)

    # ===== Visualization for report =====
    metrics = {
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1-Score": f1_score
    }

    names = list(metrics.keys())
    values = list(metrics.values())

    plt.figure(figsize=(8, 5))
    plt.bar(names, values)
    plt.ylim(0, 100)
    plt.title("IDS Performance Evaluation")
    plt.ylabel("Percentage (%)")
    plt.xlabel("Metric")

    for i, v in enumerate(values):
        plt.text(i, v + 1, f"{v:.2f}%", ha="center", fontsize=10)

    plt.tight_layout()
    plt.show()


def monitor_realtime(ai_engine, supervised_engine=None, jsonl_path="monitor_alerts.jsonl"):
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

            # ---------- Threat score + bucket ----------
            score = 0.0
            if rule_ids:
                score += 0.45
            if sup_hit:
                score += 0.40 * sup_prob
            if unsup_hit:
                score += 0.20

            if score >= 0.75:
                level, color = "CRITICAL", RED
            elif score >= 0.45:
                level, color = "HIGH", RED
            elif score >= 0.25:
                level, color = "MEDIUM", YELLOW
            elif score > 0:
                level, color = "LOW", CYAN
            else:
                continue  # nothing fired

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
    Kiểm tra request có nên bỏ qua ở tầng AI hay không.
    Trả về True nếu nên bỏ qua.
    """
    path = str(item.get("path", ""))
    status = str(item.get("status", ""))

    static_keywords = [
        "favicon.ico", "robots.txt",
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".ico", ".woff", ".woff2", ".ttf"
    ]

    if any(x in path for x in static_keywords):
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
         if ai_engine.load_model():
             _hydrate_vocab()
         analyze_log(log_file, ai_engine=ai_engine, mode="scan")

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
        if not ai_engine.load_model():
            print("⚠️  AI model not found. Please run train first.")
            sys.exit(1)
        _hydrate_vocab()
        evaluate_model(log_file, ai_engine)