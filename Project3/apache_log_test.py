import re
import json
import sys
import os
from datetime import datetime
from collections import Counter, defaultdict
from urllib.parse import unquote, urlparse, parse_qs
from apachelogs import LogParser

# --- CONFIGURATION & REGEX (FINAL VERSION) ---

# SQLi: Bổ sung bắt '1'='1, union all, drop table
SQLI_RE = re.compile(r'(?i)(\bunion\s+(all\s+)?select\b|\bselect\s+.*\bfrom\b|\binsert\s+into\b|\bupdate\s+.*\bset\b|\bdelete\s+from\b|\bdrop\s+(table|database)\b|\balter\s+table\b|\btruncate\s+table\b|[\'"]\s*(or|and)\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+|\b(or|and)\s+\d+\s*=\s*\d+|--|\/\*)')

# XSS
XSS_RE = re.compile(r'(?i)(<script\b|javascript:|onerror\s*=|onload\s*=|eval\(|<img\s+src|alert\()')

# LFI
LFI_RE = re.compile(r'(?i)(\.\./|\.\.\\|/etc/passwd|/proc/self|C:\\Windows|win\.ini)')

# Command Injection (Bắt wget/curl không cần dấu ngăn cách)
CMD_INJ_RE = re.compile(r'(?i)('
                        r'(;|\||&&|\$|\>)\s*(rm|ls|cat|whoami|ping|tail|head)\b'
                        r'|'
                        r'\b(wget|curl|netcat|nc|bash|sh|python|perl)\b'
                        r'|'
                        r'`.*`'
                        r')')

# Sensitive Files
SENSITIVE_FILE_RE = re.compile(r'(?i)(\.env|\.git/config|config\.php|wp-config\.php|\.bak|\.sql|/cgi-bin/|test-cgi|/backup/|phpinfo\.php)')

# Scanner UA
SCANNER_UA_RE = re.compile(r'(?i)(sqlmap|nikto|masscan|nessus|nmap|dirbuster|gobuster|acunetix|hydra)')

LOG_FORMAT = '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"'

# --- DETECTION FUNCTIONS ---

def check_sqli(payload):
    if SQLI_RE.search(payload): return {"id": "SQL_INJECTION", "desc": "Payload contains SQL Injection patterns"}
    return None

def check_xss(payload):
    if XSS_RE.search(payload): return {"id": "XSS", "desc": "Payload contains XSS patterns"}
    return None

def check_lfi(payload):
    if LFI_RE.search(payload): return {"id": "LFI_PATH_TRAVERSAL", "desc": "Path traversal attempt"}
    return None

def check_cmd_injection(payload):
    if CMD_INJ_RE.search(payload): return {"id": "COMMAND_INJECTION", "desc": "System command injection attempt"}
    return None

def check_sensitive_files(path):
    if SENSITIVE_FILE_RE.search(path): return {"id": "SENSITIVE_FILE_ACCESS", "desc": "Accessing sensitive files"}
    return None

def check_rfi(params):
    for key, values in params.items():
        for v in values:
            if v.lower().startswith(('http://', 'https://', 'ftp://')):
                 return {"id": "RFI", "desc": f"RFI candidate in param '{key}'"}
    return None

def check_scanner_ua(user_agent):
    if not user_agent: return None
    if SCANNER_UA_RE.search(user_agent): return {"id": "SCANNER_TOOL", "desc": f"Scanner tool: {user_agent}"}
    return None

# --- HÀM 1: ANALYZE LOG (Dùng cho TRAIN và SCAN file tĩnh) ---
def analyze_log(path_log, path_out_alerts="alerts.jsonl", mode="scan"):
    parser = LogParser(LOG_FORMAT)
    alerts = []
    ip_activity = defaultdict(int)
    ip_paths = defaultdict(set)
    training_data = []

    print(f"[*] Starting {mode} on {path_log}...")
    
    with open(path_log, "r", encoding="utf-8", errors="replace") as f_in:
        for line_no, line in enumerate(f_in, start=1):
            try:
                entry = parser.parse(line)
            except: continue

            client_ip = entry.remote_host
            status = entry.final_status
            
            # Logic parse URL chuẩn
            req_line_str = entry.request_line if entry.request_line else ""
            parts = req_line_str.split()
            if len(parts) >= 3:
                method = parts[0]
                raw_url = " ".join(parts[1:-1]) 
            elif len(parts) == 2:
                method = parts[0]
                raw_url = parts[1]
            else:
                method = ""
                raw_url = ""

            ua = entry.headers_in.get("User-Agent", "") if entry.headers_in else ""
            
            decoded_url = unquote(raw_url)
            try:
                parsed = urlparse(decoded_url)
                path = parsed.path
                query = parsed.query
            except:
                path = decoded_url
                query = ""
            params = parse_qs(query)

            # Thu thập dữ liệu
            training_data.append({"path": path, "query": query, "method": method, "status": status})

            if mode == "train": continue

            # --- Detection Logic (Regex) ---
            matches = []
            payload_to_check = f"{path} {query}"

            if res := check_sqli(payload_to_check): matches.append(res)
            if res := check_xss(payload_to_check): matches.append(res)
            if res := check_lfi(payload_to_check): matches.append(res)
            if res := check_cmd_injection(payload_to_check): matches.append(res)
            if res := check_rfi(params): matches.append(res)
            if res := check_sensitive_files(path): matches.append(res)
            if res := check_scanner_ua(ua): matches.append(res)

            ip_paths[client_ip].add(path)

            if matches:
                alerts.append({"line_no": line_no, "client_ip": client_ip, "matches": matches, "detail": f"{method} {raw_url}"})
                print(f"[REGEX] Line {line_no} | {matches[0]['id']}")

    # --- AI Module ---
    from ai_detector import LogAnomalyDetector
    ai_engine = LogAnomalyDetector()

    if mode == "train":
        print(f"[*] Training AI model with {len(training_data)} entries...")
        if os.path.exists("ad_model.pkl"): os.remove("ad_model.pkl")
        ai_engine.train(training_data)
        return

    if mode == "scan":
        if ai_engine.load_model():
            print("\n[AI MODULE] Scanning for anomalies...")
            ai_alerts = 0
            for idx, item in enumerate(training_data, start=1):
                # Debug block
                full_url_check = str(item['path']) + str(item['query'])
                decoded_check = unquote(full_url_check)
                if any(k in decoded_check.lower() for k in ["rm ", "wget", "union", "'1'='1"]):
                    print(f"\n[DEBUG] Line {idx} Payload: {decoded_check}")
                    feats = ai_engine.extract_features(item['path'], item['query'], item['method'], item['status'])
                    print(f"[DEBUG] Vector: {feats}")

                is_anomaly = ai_engine.predict(item['path'], item['query'], item['method'], item['status'])
                
                if is_anomaly:
                    # Whitelist
                    is_safe = False
                    if any(x in item['path'] for x in ["favicon.ico", "robots.txt", ".css", ".js", ".png", ".jpg"]): is_safe = True
                    if str(item['status']) == "408": is_safe = True
                    if "login.php" in item['path'] and item['method'] == "POST": is_safe = True
                    if item['path'] == "/" and item['method'] == "GET": is_safe = True

                    if not is_safe:
                        # Logic báo lỗi AI (Test mode: luôn báo để check)
                        if True: 
                            print(f"[AI] Line {idx} -> Anomaly Detected: {item['method']} {item['path']}")
                            alerts.append({
                                "line_no": idx,
                                "client_ip": "Check_Log",
                                "matches": [{"id": "AI_ANOMALY", "desc": "Abnormal request structure detected by ML"}],
                                "detail": f"{item['method']} {item['path']}"
                            })
                            ai_alerts += 1
            print(f"[AI] Finished. Found {ai_alerts} anomalies.")
        else:
            print("[AI] No model found. Run 'train' mode first.")

    # Ghi file alert
    with open(path_out_alerts, "w", encoding="utf-8") as f:
        for a in alerts: f.write(json.dumps(a) + "\n")
    print(f"\n[DONE] Saved {len(alerts)} alerts to {path_out_alerts}")


# --- HÀM 2: MONITOR REAL-TIME (Dùng cho chế độ PIPE | TAIL -F) ---
def monitor_realtime(ai_engine):
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    BOLD = "\033[1m"

    print(f"{CYAN}" + "="*60)
    print(f"  🛡️  HỆ THỐNG GIÁM SÁT TẤN CÔNG WEB (REAL-TIME NIDS)  🛡️")
    print(f"  [AI MODEL]: {'Đã nạp thành công' if ai_engine.model else 'Chưa có model!'}")
    print(f"  [STATUS]:   Đang lắng nghe log từ Server...")
    print("="*60 + f"{RESET}\n")

    parser = LogParser(LOG_FORMAT)

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line: continue
            
            try:
                entry = parser.parse(line)
            except: continue

            client_ip = entry.remote_host
            status = entry.final_status
            
            req_line_str = entry.request_line if entry.request_line else ""
            parts = req_line_str.split()
            if len(parts) >= 3:
                method = parts[0]
                raw_url = " ".join(parts[1:-1])
            elif len(parts) == 2:
                method = parts[0]
                raw_url = parts[1]
            else:
                method = ""
                raw_url = ""

            ua = entry.headers_in.get("User-Agent", "") if entry.headers_in else ""
            decoded_url = unquote(raw_url)
            try:
                parsed = urlparse(decoded_url)
                path = parsed.path
                query = parsed.query
            except:
                path = decoded_url
                query = ""
            params = parse_qs(query)
            payload_to_check = f"{path} {query}"

            matches = []
            if res := check_sqli(payload_to_check): matches.append(res)
            if res := check_xss(payload_to_check): matches.append(res)
            if res := check_lfi(payload_to_check): matches.append(res)
            if res := check_cmd_injection(payload_to_check): matches.append(res)
            if res := check_rfi(params): matches.append(res)
            if res := check_sensitive_files(path): matches.append(res)
            if res := check_scanner_ua(ua): matches.append(res)

            is_anomaly = ai_engine.predict(path, query, method, status)
            if is_anomaly:
                is_safe = False
                if any(x in path for x in ["favicon.ico", "robots.txt", ".css", ".js", ".png", ".jpg"]): is_safe = True
                if str(status) == "408": is_safe = True
                
                if not is_safe:
                    matches.append({"id": "AI_ANOMALY", "desc": "Machine Learning detected abnormal behavior"})

            if matches:
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"{RED}[ALERT] {timestamp} | IP: {client_ip} {RESET}")
                seen_types = set()
                for m in matches:
                    if m['id'] not in seen_types:
                        icon = "🤖" if m['id'] == "AI_ANOMALY" else "🔥"
                        print(f"   {icon} {BOLD}{m['id']}{RESET}: {m['desc']}")
                        seen_types.add(m['id'])
                print(f"   Payload: {YELLOW}{method} {raw_url}{RESET}")
                print(f"{CYAN}-{RESET}" * 60, flush=True)

    except KeyboardInterrupt:
        print(f"\n{GREEN}[STOP] Đã dừng hệ thống giám sát.{RESET}")

# --- MAIN BLOCK ---
if __name__ == "__main__":
    from ai_detector import LogAnomalyDetector

    if len(sys.argv) < 2:
        print("Usage: python apache_log.py [train|scan|monitor] [logfile]")
        sys.exit(1)

    mode = sys.argv[1]
    ai_engine = LogAnomalyDetector()

    if mode == "train":
        if len(sys.argv) < 3:
            print("Missing log file for training.")
            sys.exit(1)
        # GỌI HÀM ANALYZE_LOG
        analyze_log(sys.argv[2], mode="train")

    elif mode == "scan":
         if len(sys.argv) < 3:
            print("Missing log file for scanning.")
            sys.exit(1)
         # GỌI HÀM ANALYZE_LOG
         analyze_log(sys.argv[2], mode="scan")

    elif mode == "monitor":
        if not ai_engine.load_model():
            print("⚠️  Chưa tìm thấy model AI. Hãy chạy lệnh train trước.")
            sys.exit(1)
        # GỌI HÀM MONITOR_REALTIME
        monitor_realtime(ai_engine)