import re
import json
import sys
import os
from collections import Counter, defaultdict
from urllib.parse import unquote, urlparse, parse_qs
from apachelogs import LogParser

# --- CONFIGURATION & REGEX (UPDATED) ---

# SQLi: Bổ sung bắt '1'='1 và union all
SQLI_RE = re.compile(r'(?i)(\bunion\s+(all\s+)?select\b|\bselect\s+.*\bfrom\b|\binsert\s+into\b|\bupdate\s+.*\bset\b|\bdelete\s+from\b|\bdrop\s+(table|database)\b|\balter\s+table\b|\btruncate\s+table\b|[\'"]\s*(or|and)\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+|\b(or|and)\s+\d+\s*=\s*\d+|--|\/\*)')
# XSS: Giữ nguyên
XSS_RE = re.compile(r'(?i)(<script\b|javascript:|onerror\s*=|onload\s*=|eval\(|<img\s+src|alert\()')

# LFI/Path Traversal
LFI_RE = re.compile(r'(?i)(\.\./|\.\.\\|/etc/passwd|/proc/self|C:\\Windows|win\.ini)')

# Command Injection
CMD_INJ_RE = re.compile(r'(?i)('
                        # Nhóm 1: Các lệnh ngắn/phổ thông -> Bắt buộc phải có dấu phân cách (; | && $)
                        r'(;|\||&&|\$|\>)\s*(rm|ls|cat|whoami|ping|tail|head)\b'
                        r'|'
                        # Nhóm 2: Các lệnh nguy hiểm đặc thù -> Bắt luôn nếu thấy (cho phép đứng đầu hoặc sau dấu cách/cộng)
                        r'\b(wget|curl|netcat|nc|bash|sh|python|perl)\b'
                        r'|'
                        # Nhóm 3: Dấu backtick
                        r'`.*`'
                        r')')

# Sensitive Files
SENSITIVE_FILE_RE = re.compile(r'(?i)(\.env|\.git/config|config\.php|wp-config\.php|\.bak|\.sql|/cgi-bin/|test-cgi|/backup/|phpinfo\.php)')

# Scanner User-Agent
SCANNER_UA_RE = re.compile(r'(?i)(sqlmap|nikto|masscan|nessus|nmap|dirbuster|gobuster|acunetix|hydra)')

LOG_FORMAT = '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"'

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

# --- MAIN ANALYSIS ---

def analyze_log(path_log, path_out_alerts="alerts.jsonl", mode="scan"):
    parser = LogParser(LOG_FORMAT)
    alerts = []
    
    # Thống kê
    ip_activity = defaultdict(int)
    ip_paths = defaultdict(set)
    ip_401_counts = defaultdict(int)
    training_data = []

    print(f"[*] Starting {mode} on {path_log}...")
    
    with open(path_log, "r", encoding="utf-8", errors="replace") as f_in:
        for line_no, line in enumerate(f_in, start=1):
            try:
                entry = parser.parse(line)
            except Exception:
                continue

            client_ip = entry.remote_host
            status = entry.final_status
            
            # --- FIX: PARSING URL CÓ KHOẢNG TRẮNG ---
            req_line_str = entry.request_line if entry.request_line else ""
            parts = req_line_str.split()
            
            if len(parts) >= 3:
                # Method là phần đầu, Protocol (HTTP/1.1) là phần cuối
                # URL là TẤT CẢ những gì ở giữa (xử lý trường hợp URL chứa dấu cách)
                method = parts[0]
                raw_url = " ".join(parts[1:-1]) 
            elif len(parts) == 2:
                method = parts[0]
                raw_url = parts[1]
            else:
                method = ""
                raw_url = ""

            # User Agent
            ua = ""
            if entry.headers_in and entry.headers_in.get("User-Agent"):
                ua = entry.headers_in.get("User-Agent")

            # Decode URL
            decoded_url = unquote(raw_url)
            # URL parse đôi khi lỗi nếu URL quá dị, ta fallback
            try:
                parsed = urlparse(decoded_url)
                path = parsed.path
                query = parsed.query
            except:
                path = decoded_url
                query = ""
            
            params = parse_qs(query)

            # Thu thập dữ liệu train AI
            training_data.append({
                "path": path, "query": query, "method": method, "status": status
            })

            # Nếu đang mode train thì không cần check regex, chỉ cần đọc dữ liệu
            if mode == "train":
                continue

            # --- CHECK REGEX (RULE BASED) ---
            matches = []
            payload_to_check = f"{path} {query}" # Check cả path và query, bao gồm khoảng trắng

            if res := check_sqli(payload_to_check): matches.append(res)
            if res := check_xss(payload_to_check): matches.append(res)
            if res := check_lfi(payload_to_check): matches.append(res)
            if res := check_cmd_injection(payload_to_check): matches.append(res)
            if res := check_rfi(params): matches.append(res)
            if res := check_sensitive_files(path): matches.append(res)
            if res := check_scanner_ua(ua): matches.append(res)

            # Thống kê behavior
            ip_activity[client_ip] += 1
            ip_paths[client_ip].add(path)
            if status == 401 or status == 403:
                ip_401_counts[client_ip] += 1

            if matches:
                alert = {
                    "line_no": line_no,
                    "client_ip": client_ip,
                    "matches": matches,
                    "detail": f"{method} {raw_url}"
                }
                alerts.append(alert)
                print(f"[REGEX] Line {line_no} | {matches[0]['id']}")

    # --- AI INTEGRATION ---
    from ai_detector import LogAnomalyDetector
    ai_engine = LogAnomalyDetector()

    if mode == "train":
        print(f"[*] Training AI model with {len(training_data)} entries...")
        # Xóa model cũ nếu train lại
        if os.path.exists("ad_model.pkl"): os.remove("ad_model.pkl")
        ai_engine.train(training_data)
        return

    if mode == "scan":
        if ai_engine.load_model():
            print("\n[AI MODULE] Scanning for anomalies...")
            ai_alerts = 0
            for idx, item in enumerate(training_data, start=1):
                is_anomaly = ai_engine.predict(item['path'], item['query'], item['method'], item['status'])
                
                # --- [DEBUG BLOCK IMPROVED] ---
                full_url_check = str(item['path']) + str(item['query'])
                decoded_check = unquote(full_url_check)
                
                # In ra thông số của các dòng tấn công quan trọng để kiểm tra
                keywords = ["rm ", "wget", "union", "'1'='1", "sleep", "cat "]
                if any(k in decoded_check.lower() for k in keywords):
                    print(f"\n[DEBUG] Line {idx} Payload: {decoded_check}")
                    feats = ai_engine.extract_features(item['path'], item['query'], item['method'], item['status'])
                    print(f"[DEBUG] Vector đặc trưng: {feats}")
                    # feats[2] là Risk Score (phải cao > 0)
                    # feats[3] là Spaces Score (phải cao > 0)
                # ----------------------------------------

                if is_anomaly:
                    # --- WHITELIST (DANH SÁCH MIỄN TRỪ) ---
                    # 1. Bỏ qua các file tĩnh và file hệ thống vô hại
                    if any(x in item['path'] for x in ["favicon.ico", "robots.txt", ".css", ".js", ".png", ".jpg"]):
                        continue
                        
                    # 2. Bỏ qua Timeout 408
                    if str(item['status']) == "408": 
                        continue

                    
                    # --- NẾU KHÔNG NẰM TRONG WHITELIST THÌ MỚI BÁO LỖI ---
                    #if not any(a['line_no'] == idx for a in alerts):
                    if True:
                        print(f"[AI] Line {idx} -> Anomaly Detected: {item['method']} {item['path']}")
                        alerts.append({
                            "line_no": idx,
                            "client_ip": "Check_Log",
                            "matches": [{"id": "AI_ANOMALY", "desc": "Abnormal request structure detected by ML"}],
                            "detail": f"{item['method']} {item['path']}?{item['query']}"
                        })
                        ai_alerts += 1
            print(f"[AI] Finished. Found {ai_alerts} anomalies missed by Regex.")
        else:
            print("[AI] No model found. Run 'train' mode first.")

    # Behavior Analysis (SỬA LẠI ĐOẠN NÀY)
    print("\n[BEHAVIOR MODULE] Analyzing traffic patterns...")
    for ip, paths in ip_paths.items():
        # Ngưỡng scan: Truy cập trên 10 đường dẫn khác nhau
        if len(paths) >= 10:
            print(f"[BEHAVIOR] IP {ip} scan {len(paths)} paths -> DETECTED!")
            
            # Thêm alert luôn, KHÔNG CẦN kiểm tra xem đã bị bắt scanner tool chưa
            # Vì hành vi quét diện rộng (Scan) là một chỉ báo quan trọng độc lập
            alerts.append({
                "line_no": "SUMMARY",
                "client_ip": ip,
                "matches": [{
                    "id": "BEHAVIOR_SCANNING", 
                    "desc": f"Suspicious behavior: Accessed {len(paths)} unique paths (Port/Dir Scan suspected)"
                }],
                "detail": "Summary Report"
            })

    with open(path_out_alerts, "w", encoding="utf-8") as f:
        for a in alerts:
            f.write(json.dumps(a) + "\n")
    print(f"\n[DONE] Saved {len(alerts)} alerts to {path_out_alerts}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python apache_log.py [train|scan] [logfile]")
        sys.exit(1)
    analyze_log(sys.argv[2], mode=sys.argv[1])