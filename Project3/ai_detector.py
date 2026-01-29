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
        self.clf = IsolationForest(contamination=0.08, random_state=42, n_jobs=-1, n_estimators=200)

    def extract_features(self, path, query, method, status):
        full_url = str(path) + str(query)
        decoded_url = unquote(full_url)
        
        # 1. Length of URL 
        len_url = len(full_url)
        if len_url == 0: len_url = 1
        
        # 2. Risk Chars 
        raw_risk_count = sum(decoded_url.count(c) for c in [";", "|", "$", "`", "(", ")", "<", ">", "'", '"', "{", "}", "\\"]) 
        
        # 3. Depth of path
        path_depth = path.count('/')

        # 4. Method POST
        is_post = 1 if method == "POST" else 0

        # 5. Risk Ratio 
        risk_ratio = raw_risk_count / len_url

    
        return [len_url, raw_risk_count, path_depth, is_post, risk_ratio]  


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
            return False 
            
        features = self.extract_features(path, query, method, status)
        pred = self.model.predict([features])
        
        return pred[0] == -1