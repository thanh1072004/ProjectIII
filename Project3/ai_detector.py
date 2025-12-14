# ai_detector.py
import numpy as np
import os
import joblib
from urllib.parse import unquote
from sklearn.ensemble import IsolationForest

class LogAnomalyDetector:
    def __init__(self, model_path="ad_model.pkl"):
        self.model_path = model_path
        self.model = None
        # Contamination: Tỷ lệ nhiễu/tấn công ước lượng trong dữ liệu (30%)
        self.clf = IsolationForest(contamination='auto', random_state=42, n_jobs=-1, n_estimators=200)

    def extract_features(self, path, query, method, status):
        full_url = str(path) + str(query)
        decoded_url = unquote(full_url)
        
        # 1. Độ dài (Giữ nguyên)
        len_url = len(full_url)
        if len_url == 0: len_url = 1
        
        # 2. Safe Chars (Giữ nguyên)
        safe_chars = sum(decoded_url.count(c) for c in ["/", "?", "&", "=", ".", "_", "-", ":"])
        
        # 3. Risk Chars (PHÓNG ĐẠI X50 LẦN)
        # Chỉ cần xuất hiện 1 dấu nguy hiểm, giá trị feature sẽ vọt lên 50
        raw_risk_count = sum(decoded_url.count(c) for c in [";", "|", "$", "`", "(", ")", "<", ">", "'", '"', "{", "}", "\\"])
        risk_score = raw_risk_count * 150  # <--- TRỌNG SỐ CAO
        
        # 4. Số khoảng trắng (PHÓNG ĐẠI X20 LẦN)
        # Vì URL sạch chuẩn mực không nên có dấu cách
        raw_spaces = decoded_url.count(' ')
        spaces_score = raw_spaces * 100    # <--- TRỌNG SỐ CAO
        
        # 5. Các chỉ số khác
        path_depth = path.count('/')
        is_post = 1 if method == "POST" else 0
        is_error = 1 if str(status).startswith(('4', '5')) else 0
        
        # 6. Tỷ lệ nguy hiểm (Cũng sẽ tự động tăng theo risk_score thực tế nếu muốn, nhưng ở đây dùng count gốc chia len)
        risk_ratio = raw_risk_count / len_url

        num_commas = decoded_url.count(',')
        num_upper = sum(1 for c in decoded_url if c.isupper())
        upper_ratio = num_upper / len(decoded_url) if len(decoded_url) > 0 else 0
        is_percent_encoded = 1 if '%' in full_url else 0  # Bắt %20 etc.
    
        return [len_url, safe_chars, risk_score, spaces_score, path_depth, is_post, is_error, risk_ratio, num_commas, num_upper * 10, upper_ratio, is_percent_encoded*150]  # Thêm 4 features, amplify num_upper x10


    def train(self, log_data):
        """
        Huấn luyện model.
        log_data: List các dictionary {'path':..., 'query':..., 'method':..., 'status':...}
        """
        if not log_data:
            print("[AI] Không có dữ liệu để train.")
            return

        print(f"[AI] Đang trích xuất đặc trưng từ {len(log_data)} dòng log...")
        X = [self.extract_features(d['path'], d['query'], d['method'], d['status']) for d in log_data]
        
        print("[AI] Đang huấn luyện mô hình Isolation Forest...")
        self.clf.fit(X)
        self.model = self.clf
        
        joblib.dump(self.model, self.model_path)
        print(f"[AI] Đã lưu model tại {self.model_path}")

    def load_model(self):
        """Load model đã train từ file"""
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                print(f"[AI] Đã load model từ {self.model_path}")
                return True
            except:
                return False
        return False

    def predict(self, path, query, method, status):
        """
        Dự đoán: Trả về True nếu là Bất thường (Anomaly), False nếu Bình thường
        """
        if not self.model:
            return False # Chưa có model thì coi như bình thường
            
        features = self.extract_features(path, query, method, status)
        # Reshape(1, -1) vì predict dự đoán cho 1 mẫu
        pred = self.model.predict([features])
        
        # Isolation Forest: -1 là bất thường, 1 là bình thường
        return pred[0] == -1