import random

def split_csic_log(input_file="csic_evaluated.log", train_file="csic_train_clean.log", test_file="csic_test.log"):
    normal_logs = []
    attack_logs = []

    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            if "(Simulated-Attack)" in line:
                attack_logs.append(line)
            else:
                normal_logs.append(line)

    # Đảo lộn ngẫu nhiên
    random.shuffle(normal_logs)
    
    # Lấy 20,000 dòng bình thường làm tập Train
    train_normal = normal_logs[:20000]
    
    # Số bình thường còn lại và toàn bộ attack làm tập Test
    test_data = normal_logs[20000:] + attack_logs
    random.shuffle(test_data) # Trộn đều test data

    with open(train_file, 'w', encoding='utf-8') as f:
        f.writelines(train_normal)

    with open(test_file, 'w', encoding='utf-8') as f:
        f.writelines(test_data)

    print(f"[XONG] Đã tạo {train_file} (Chứa {len(train_normal)} dòng Sạch)")
    print(f"[XONG] Đã tạo {test_file} (Chứa {len(test_data)} dòng hỗn hợp)")

if __name__ == "__main__":
    split_csic_log()