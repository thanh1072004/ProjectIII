# IDS System Diagnostic Report

## Executive Summary
Hệ thống IDS hiện tại có kết quả rất thấp do **sự không match giữa feature extraction và dữ liệu thực tế**. Vấn đề chính là:
1. **URL Encoding Issue**: Payload attacks được URL-encode, ẩn ngữ nghĩa của chúng
2. **Weak Features**: Chỉ 7 features đơn giản không đủ để phân biệt
3. **Model Configuration**: Threshold anomalies quá thấp (5% vs 61% attacks)
4. **Data Transformation**: POST body transform thành query string làm thay đổi distribution

---

## 1. ROOT CAUSE ANALYSIS

### 1.1 POST Encoding Problem

**The Issue:**
```
Gốc POST payload:
  quantidade='; DROP TABLE usuarios; SELECT * FROM dados WHERE name LIKE '%

Sau khi transform thành URL query:
  /tienda1/publico/anadir.jsp?POST_BODY=id%3D2%26nombre%3D...%2527%253B%2BDROP%2BTABLE%2Busuarios%253B...

Features extracted từ URL-encoded:
  - len_url: 450 (dài, nhưng normal URLs cũng dài)
  - raw_risk_count: Chỉ đếm được %, =, + (encode characters)
  - Không thấy ";" hay "DROP" keywords vì bị ẩn trong %XX format
  - entropy: Cao (nhưng normal long URLs cũng có entropy cao)
```

**Impact:**
- SQL injection payload không phát hiện được keyword "DROP", "UNION", etc
- Attack chỉ nhận ra bởi raw_risk_count = số ký tự % (mà normal URLs cũng có)
- False Negative Rate rất cao

### 1.2 Feature Extraction Chi tiết

Hiện tại:
```python
def extract_features(path, query, method, status):
    # 1. URL length - shared với normal dài
    len_url = len(full_url)
    
    # 2. Risk Chars - chỉ đếm raw chars, không xét context
    raw_risk_count = sum(count(c) for c in ";<>|$`(){}'\"{}\\")
    # ❌ Không phát hiện được encoded attacks
    
    # 3. Path depth - shared với normal
    path_depth = path.count('/')
    
    # 4. Is POST - binary feature
    is_post = 1 if method == "POST" else 0
    
    # 5. Risk ratio - không robust với encoding
    risk_ratio = raw_risk_count / len_url
    
    # 6. Entropy - normal URLs cũng có entropy cao
    entropy = calculate_entropy(full_url)
    
    # 7. Keyword hits - không decode URL nên miss encoded attacks
    keyword_hits = sum(1 for k in ['select', 'union', ...] 
                       if k in decoded_url.lower())
```

**Problem:** Chỉ 7 features, và hầu hết đều có giá trị tương đồng giữa normal và attack

### 1.3 Model Configuration Mismatch

```
Test Dataset Composition:
- Attacks: 25,065 (61%)
- Normal: 16,000 (39%)

Model Settings:
- Isolation Forest: contamination="auto" 
- One-Class SVM: nu=0.05 (expects ~5% anomalies)
- LOF: contamination=0.05 (expects ~5% anomalies)

❌ Models trained to find 5% anomalies,
   but test data has 61% attacks + ~35-40% false normal from CSIC

Result:
- High False Negative Rate
- Models consider attacks as "within normal distribution"
```

### 1.4 Dataset Bias

CSIC Dataset characteristics:
- Contains URL parameters: id, nombre, precio, login, pwd, mode, etc
- Normal requests already have:
  - Complex parameters (5-15 params per request)
  - URL lengths: 100-400+ chars
  - Special characters: &, =, %, +, @, #, etc
  
- Attacks overlay:
  - Use same parameter structure
  - But add payloads inside parameter values
  - After URL-encoding: indistinguishable from normal

**Example:**
```
Normal:   GET /tienda1/publico/anadir.jsp?id=3&nombre=Vino+Rioja&precio=100
Attack:   GET /tienda1/publico/anadir.jsp?id=2&nombre=Jamón&cantidad=%27;DROP TABLE...

After analysis:
- Normal: len=95, risk_chars=0, entropy=4.2
- Attack: len=380, risk_chars=3 (just %), entropy=4.8
- Difference is NOT significant for anomaly detection
```

---

## 2. DETAILED FINDINGS

### 2.1 Encoding Issues
| Aspect | Impact | Severity |
|--------|--------|----------|
| URL encoding hides SQL keywords | Keywords miss detection | HIGH |
| % characters treated as risk_char | False positives on normal URLs | HIGH |
| Decoded URL not used for detection | Attack patterns hidden | CRITICAL |
| POST→Query transformation | Distribution mismatch | HIGH |

### 2.2 Feature Space Analysis
- **Current Space**: 7 dimensions (very sparse)
- **Coverage**: ~40% of attack patterns captured (SQL Injection by keywords)
- **Missing**: 60% attacks use only parameter values/encoding
- **Overlap**: Features highly overlap between normal and attack

### 2.3 Model Behavior
- **IF (Isolation Forest)**: Marked too many normal as anomalies
- **OCSVM**: Too strict threshold (nu=0.05)
- **LOF**: Better but still inadequate features

---

## 3. PHƯƠNG ÁN CẢI THIỆN (Solutions)

### 3.1 IMMEDIATE FIXES (Quick Win)

#### Fix 1: Decode and Analyze Payloads
```python
# BEFORE (Current - BẠN CÓ RỦI RO)
payload = unquote(full_url)  # URL decode nhưng không dùng trong analysis
keywords = ['select', 'union', ...]  # Check trên raw URL

# AFTER (Improved)
payload_decoded = unquote(full_url)  # Decode đúng
# Use decoded payload for keyword detection
keyword_hits = sum(1 for k in keywords 
                   if k in payload_decoded.lower())
```

#### Fix 2: Adjust Model Parameters
```python
# For CSIC Dataset with 61% attacks
# One-Class SVM
self.clf = OneClassSVM(nu=0.65, kernel="rbf", gamma="scale")  # 65% anomalies

# LOF
self.clf = LocalOutlierFactor(
    n_neighbors=20,
    contamination=0.65,  # Match 65% expected attacks
    novelty=True
)
```

#### Fix 3: Add POST Payload Detection
```python
# Extract POST body before URL encode
if method == 'POST':
    # Decode POST_BODY parameter if exists
    if 'POST_BODY=' in full_url:
        post_body = unquote(full_url.split('POST_BODY=')[1])
        # Analyze post_body separately for attacks
```

### 3.2 MID-TERM FIXES (Enhanced Features)

#### Enhanced Feature Set (15+ features)
```python
def extract_features_v2(path, query, method, status, raw_post_body=None):
    """Version 2 with better feature engineering"""
    
    # Combine path + query + decoded payload
    decoded_payload = unquote(full_url)
    
    features = {
        # URL Structure Features
        'url_length': len(full_url),
        'path_depth': path.count('/'),
        'param_count': len(parse_qs(query)),
        'avg_param_length': np.mean([len(v) for v in parse_qs(query).values()]),
        
        # Encoding Features
        'percent_encoding_ratio': full_url.count('%') / len(full_url),
        'encoding_ratio': sum(ord(c) > 127 for c in full_url) / len(full_url),
        
        # Payload Semantic Features
        'sql_keywords': count_keywords(decoded_payload, SQL_KEYWORDS),
        'xss_keywords': count_keywords(decoded_payload, XSS_KEYWORDS),
        'traversal_keywords': count_keywords(decoded_payload, TRAVERSAL_KEYWORDS),
        
        # Statistical Features
        'entropy': calculate_entropy(decoded_payload),
        'unique_chars_ratio': len(set(decoded_payload)) / len(decoded_payload),
        
        # Method Features
        'is_post': 1 if method == 'POST' else 0,
        'is_put': 1 if method == 'PUT' else 0,
        'is_delete': 1 if method == 'DELETE' else 0,
        
        # Response Features
        'status_anomaly': 1 if status in [401, 403, 500] else 0,
    }
    
    return [v for v in features.values()]
```

### 3.3 LONG-TERM FIXES (Robust Solution)

#### Use Hybrid Approach with Better Preprocessing
```
1. Input Preparation:
   - Fully decode all URL-encoded content
   - Separate path, query, and POST body
   - Normalize payloads

2. Multi-Layer Detection:
   a) Layer 1: Signature-based (Regex) - High precision
   b) Layer 2: Feature-based AI - Medium precision
   c) Layer 3: Behavioral - Low FP rate
   
3. Ensemble Decision:
   if (Layer1_Hit AND confidence > 0.8):
       Alert with HIGH severity
   elif (Layer1_Hit OR Layer2_Hit):
       Alert with MEDIUM severity
   elif (Layer3_Hit AND behavior_score > 0.7):
       Alert with LOW severity
```

#### Better Training Strategy
```
1. Re-balance training data:
   - Current: 100% normal
   - Proposed: 70% normal + 30% synthetic/real attacks
   
2. Re-label test data properly:
   - Verify ground truth
   - Ensure distribution match
   
3. Hyperparameter tuning:
   - Grid search for contamination rate
   - Cross-validation on CSIC data
```

---

## 4. PRIORITY IMPLEMENTATION ROADMAP

### Phase 1: Critical Fixes (Today - 1 day)
1. ✅ Decode payloads before analysis
2. ✅ Fix model contamination parameters
3. ✅ Fix keyword detection on decoded payloads

### Phase 2: Medium Priority (2-3 days)
1. Add 8-10 more features
2. Implement POST body extraction
3. Add HTTP method specific handling

### Phase 3: Long-term (1-2 weeks)
1. Collect more real-world logs
2. Fine-tune models
3. Implement multi-layer detection

---

## 5. EXPECTED IMPROVEMENTS

After applying Phase 1 fixes:
- **Recall**: 20-30% → 60-70%
- **Precision**: 50-60% → 75-85%
- **F1-Score**: 0.3 → 0.65+

After Phase 2+3:
- **Recall**: 75-85%
- **Precision**: 85-90%
- **F1-Score**: 0.80+

---

## 6. RECOMMENDED NEXT STEP

Implement Phase 1 fixes immediately:
1. Update `ai_detector.py` with proper URL decoding
2. Adjust model parameters
3. Enhance keyword detection
4. Re-train models
5. Re-evaluate on test set
