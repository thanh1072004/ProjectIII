import random
import time
from datetime import datetime, timedelta

# Cấu hình
OUTPUT_FILE = "training_clean.log"
NUM_ENTRIES = 3000  # Tạo 3000 dòng log sạch

# Danh sách URL bình thường (Học thói quen người dùng tốt)
NORMAL_PATHS = [
    "/", "/index.php", "/home", "/about-us", "/contact.php", 
    "/products.php", "/services", "/login.php", "/register.php",
    "/assets/css/style.css", "/assets/js/main.js", "/images/logo.png",
    "/images/banner.jpg", "/favicon.ico", "/blog/post-1", "/blog/category/tech", "/robots.txt"
]

# Danh sách tham số truy vấn an toàn
SAFE_PARAMS = [
    "?id=1", "?id=102", "?page=1", "?page=2", "?cat=mobile", 
    "?sort=asc", "?view=grid", "?lang=en", "?q=iphone", ""
]

# Danh sách User-Agent phổ biến
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
]

# Hàm tạo IP ngẫu nhiên
def random_ip():
    return f"{random.randint(10, 192)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_log():
    with open(OUTPUT_FILE, "w") as f:
        start_time = datetime.now()
        print(f"[*] Đang sinh {NUM_ENTRIES} dòng log sạch vào '{OUTPUT_FILE}'...")
        
        for _ in range(NUM_ENTRIES):
            ip = random_ip()
            # Thời gian giả lập
            log_time = start_time.strftime("%d/%b/%Y:%H:%M:%S +0700")
            
            # Chọn URL ngẫu nhiên
            method = "GET"
            path = random.choice(NORMAL_PATHS)
            query = random.choice(SAFE_PARAMS)
            
            # Thỉnh thoảng có method POST cho login/contact (nhưng sạch)
            if "login" in path or "contact" in path:
                if random.random() > 0.7: method = "POST"

            url = f"{path}{query}"
            
            # Status code (đa số là 200, thi thoảng 304, 404 nhẹ)
            status = 200
            if random.random() > 1.00: status = 304
            elif random.random() > 1.50: status = 404

            size = random.randint(500, 5000)
            ua = random.choice(USER_AGENTS)
            
            # Format chuẩn Apache Combined
            # 1.2.3.4 - - [Date] "GET /path HTTP/1.1" 200 123 "-" "UserAgent"
            line = f'{ip} - - [{log_time}] "{method} {url} HTTP/1.1" {status} {size} "-" "{ua}"\n'
            f.write(line)
            
            # Tăng thời gian lên 1 chút
            start_time += timedelta(seconds=random.randint(1, 5))
            
    print("[DONE] Đã tạo xong dữ liệu training.")

if __name__ == "__main__":
    generate_log()