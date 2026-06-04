# import csv
# import random
# from datetime import datetime, timedelta

# def convert_csic_to_apache_log(csv_file_path, output_log_path):
#     print(f"[*] Bắt đầu chuyển đổi {csv_file_path} sang Apache Log format...")
    
#     start_time = datetime(2026, 1, 1, 12, 0, 0)
    
#     with open(csv_file_path, mode='r', encoding='utf-8') as csv_file, \
#          open(output_log_path, mode='w', encoding='utf-8') as log_file:
         
#         # Đọc CSV dưới dạng Dictionary (tự động map Header của cột)
#         reader = csv.DictReader(csv_file)
        
#         count_normal = 0
#         count_attack = 0
        
#         for row in reader:
#             # Lấy các trường cần thiết từ CSV (chú ý tên cột trong file của bạn phải khớp)
#             method = row.get('Method', 'GET').strip()
#             url = row.get('URL', '/').strip()
#             user_agent = row.get('User-Agent', '-').strip()
#             classification = str(row.get('classification', '0')).strip()
            
#             # Xử lý URL (Chỉ lấy phần path và query, bỏ "http://localhost:8080")
#             if "http://localhost:8080" in url:
#                 url = url.replace("http://localhost:8080", "")
            
#             # Tạo IP giả lập
#             ip = f"{random.randint(10, 192)}.{random.randint(0, 255)}.1.1"
            
#             # Thời gian tăng dần
#             dt = start_time.strftime("%d/%b/%Y:%H:%M:%S +0700")
#             start_time += timedelta(seconds=random.randint(1, 3))
            
#             status = 200 # Giả định
#             size = random.randint(500, 2000)
            
#             # --- LOGIC GẮN NHÃN QUAN TRỌNG ---
#             # Nếu là tấn công (classification == 1), nhét cờ vào User-Agent để evaluate bắt được
#             if classification == '1':
#                 user_agent = f"{user_agent} (Simulated-Attack)"
#                 count_attack += 1
#             else:
#                 count_normal += 1
                
#             # Ráp thành chuẩn Apache Combined Format
#             log_line = f'{ip} - - [{dt}] "{method} {url} HTTP/1.1" {status} {size} "-" "{user_agent}"\n'
#             log_file.write(log_line)

#     print(f"[XONG] Đã tạo file: {output_log_path}")
#     print(f"       Tổng số dòng Normal: {count_normal}")
#     print(f"       Tổng số dòng Attack: {count_attack}")

# if __name__ == "__main__":
#     # Đổi tên file csv ở đây cho khớp với file bạn lưu trên máy
#     convert_csic_to_apache_log("csic_database.csv", "csic_evaluated.log")

import csv
import random
import os
import urllib.parse  # Cần thiết để mã hóa các khoảng trắng trong Payload
from datetime import datetime, timedelta

def convert_csic_to_apache_log(csv_file_path, output_log_path):
    print(f"[*] Bắt đầu chuyển đổi {csv_file_path} sang Apache Log format...")
    
    start_time = datetime(2026, 1, 1, 12, 0, 0)
    
    with open(csv_file_path, mode='r', encoding='utf-8') as csv_file, \
         open(output_log_path, mode='w', encoding='utf-8') as log_file:
         
        # Đọc CSV dưới dạng Dictionary
        reader = csv.DictReader(csv_file)
        
        count_normal = 0
        count_attack = 0
        
        for row in reader:
            # 1. Lấy các trường cơ bản từ CSV
            method = row.get('Method', 'GET').strip()
            url = row.get('URL', '/').strip()
            user_agent = row.get('User-Agent', '-').strip()
            
            # Lấy nhãn (Bao quát cả trường hợp file lưu là classification hoặc classificati)
            classification_raw = row.get('classification', row.get('classificati', '0'))
            classification = str(classification_raw).strip().lower()
            
            # Lấy nội dung POST payload (Cột 'content')
            content = row.get('content', '').strip()
            
            # 2. Xử lý URL (Bỏ chữ localhost)
            if "http://localhost:8080" in url:
                url = url.replace("http://localhost:8080", "")
            
            # --- 3. LOGIC ĐỘT PHÁ: ĐẨY POST BODY VÀO URL ---
            if method == 'POST' and content:
                # BẮT BUỘC: Encode nội dung để không làm vỡ format khoảng trắng của Apache Log
                encoded_content = urllib.parse.quote(content)
                
                # Nếu URL đã có dấu hỏi chấm (đã có tham số), thì nối bằng dấu &
                if '?' in url:
                    url = f"{url}&POST_BODY={encoded_content}"
                else:
                    url = f"{url}?POST_BODY={encoded_content}"
            
            # 4. Khởi tạo IP giả lập và thời gian
            ip = f"{random.randint(10, 192)}.{random.randint(0, 255)}.1.1"
            dt = start_time.strftime("%d/%b/%Y:%H:%M:%S +0700")
            start_time += timedelta(seconds=random.randint(1, 3))
            status = 200 # Giả định
            size = random.randint(500, 2000)
            
            # 5. Phân loại và gắn cờ (Simulated-Attack)
            if classification in ['1', 'anomalous', 'anomaly', 'true']:
                user_agent = f"{user_agent} (Simulated-Attack)"
                count_attack += 1
            else:
                count_normal += 1
                
            # 6. Ráp thành chuẩn Apache Combined Format và ghi ra file
            log_line = f'{ip} - - [{dt}] "{method} {url} HTTP/1.1" {status} {size} "-" "{user_agent}"\n'
            log_file.write(log_line)

    print(f"\n[XONG] Đã tạo file: {output_log_path}")
    print(f"       Tổng số dòng Normal: {count_normal}")
    print(f"       Tổng số dòng Attack: {count_attack}")

if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    csv_input_path = os.path.join(current_dir, "csic_database.csv")
    log_output_path = os.path.join(current_dir, "csic_evaluated.log")
    
    convert_csic_to_apache_log(csv_input_path, log_output_path)