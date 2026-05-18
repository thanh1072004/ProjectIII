# ai_detector.py
# PHASE 3: Feature engineering - expanded from 9 -> 21 features.
# Restores Phase 1 best contamination/nu (0.50/0.60) after Phase 2 backfire.

import numpy as np
import os
import re
import math
import joblib
from urllib.parse import unquote, parse_qs

from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler


# ---------- shared keyword sets ----------
# Phase 3.1 (B+C): re-added 'or'/'and' (matched only as whole words by
# feat_risk_keyword_density's regex, so normal text like 'orden' / 'nombre'
# does not trigger).
SQL_KEYWORDS = [
    'select', 'insert', 'update', 'delete', 'drop', 'union',
    'where', 'exec', 'execute', 'declare', 'cast', 'concat',
    'sleep', 'benchmark', 'load_file', 'outfile',
    'or', 'and',
]
XSS_KEYWORDS = [
    'script', 'alert', 'onclick', 'onerror', 'onload',
    'eval', 'javascript', 'iframe', 'svg', 'img', 'prompt', 'confirm'
]
LFI_KEYWORDS = [
    'etc/passwd', 'etc/shadow', '../', '..\\', 'cmd', 'bash',
    '/bin/', 'proc/self', 'win.ini', 'boot.ini'
]
ALL_KEYWORDS = SQL_KEYWORDS + XSS_KEYWORDS + LFI_KEYWORDS

SUSPICIOUS_PARAM_NAMES = {
    'cmd', 'exec', 'command', 'system', 'shell', 'query',
    'file', 'filename', 'path', 'dir', 'include', 'page',
    'redirect', 'url', 'goto', 'next', 'target', 'return',
    'debug', 'test', 'admin', 'pwd', 'passwd', 'password'
}

SENSITIVE_PATH_PARTS = [
    '/admin', '/manage', '/wp-admin', '/login', '/config',
    '/upload', '/api/', '/cgi-bin', '/phpmyadmin', '/console'
]

# ---------- compiled signature regexes ----------
# Phase 3.1 fix (C): broaden SQL pattern to catch:
#   - 'OR'a'='a (letter-based tautology, NO spaces, quotes around everything)
#   - 'OR 1=1, 'OR a=a (with optional whitespace)
#   - ') OR ('1'='1 (parenthesised forms)
#   - encoded variants land on decoded text via multi_decode upstream
SIG_SQL_RE = re.compile(
    r"(?i)("
    r"\bunion\s+(all\s+)?select\b"
    r"|\bselect\b\s+.{1,200}?\bfrom\b"
    r"|\binsert\s+into\b"
    r"|\bdelete\s+from\b"
    r"|\bdrop\s+(table|database|schema)\b"
    r"|\bupdate\s+\w+\s+set\b"
    # quoted tautology, no/any whitespace, letters or digits on both sides:
    #   'OR'a'='a , 'OR'a='a , 'or'1'='1 , 'or"1"="1
    # NOTE: the second quote (before '=') is OPTIONAL — CSIC payloads decode
    # to 'OR'a='a (only 3 quotes), not 'OR'a'='a (4 quotes).
    r"|['\"][^'\"]{0,4}(or|and)[^'\"]{0,4}['\"]\s*\w+\s*['\"]?\s*=\s*['\"]?\s*\w+"
    # bare tautology:  OR 1=1 / OR a=a / AND 1=1
    r"|\b(or|and)\s+['\"]?\s*\w{1,15}\s*['\"]?\s*=\s*['\"]?\s*\w{1,15}"
    # paren-prefixed:  ') or ('1'='1
    r"|\)\s*(or|and)\s*\("
    # comments / exec / xp_cmdshell
    r"|--\s|#\s|/\*.*?\*/"
    r"|\bexec(ute)?\s*[\(\s]"
    r"|\bxp_cmdshell\b"
    r")"
)
SIG_XSS_RE = re.compile(
    r'(?i)(<script\b|javascript:|onerror\s*=|onload\s*=|onclick\s*=|eval\(|alert\(|<iframe\b|<svg\b)'
)
SIG_LFI_RE = re.compile(
    r'(?i)(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self|win\.ini|boot\.ini)'
)
SIG_CMD_RE = re.compile(
    r'(?i)([;|&`]\s*(rm|cat|ls|wget|curl|bash|sh|nc|netcat|whoami|ping|id\b)|`[^`]+`|\$\([^)]+\))'
)

SCANNER_UA_RE = re.compile(
    r'(?i)(sqlmap|nikto|nmap|masscan|nessus|dirbuster|gobuster|acunetix|hydra'
    r'|wfuzz|burp|zaproxy|w3af|skipfish|appscan|qualys|openvas|metasploit)'
)
AUTOMATED_UA_RE = re.compile(
    r'(?i)(curl/|wget/|python-requests|python-urllib|libwww|java/|go-http|httpclient|okhttp)'
)

CONSEC_ENC_RE = re.compile(r'(?:%[0-9a-fA-F]{2}){2,}')


# ---------- generic helpers ----------
def calculate_entropy(text):
    if not text:
        return 0.0
    length = len(text)
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    return -sum((cnt / length) * math.log2(cnt / length) for cnt in freq.values())


def multi_decode(url, max_iter=3):
    """Iteratively URL-decode, returning (fully_decoded, depth_used)."""
    prev = url
    depth = 0
    for _ in range(max_iter):
        curr = unquote(prev)
        if curr == prev:
            break
        prev = curr
        depth += 1
    return prev, depth


# ---------- feature helpers (Phase 3 additions) ----------
def feat_suspicious_ua_score(ua):
    if not ua or ua == "-":
        return 1.0
    ua_stripped = ua.strip()
    if len(ua_stripped) < 5:
        return 0.9
    if SCANNER_UA_RE.search(ua_stripped):
        return 1.0
    if AUTOMATED_UA_RE.search(ua_stripped):
        return 0.6
    if 'Mozilla' not in ua_stripped:
        return 0.4
    return 0.0


def feat_referer_suspicion(ref):
    if not ref or ref == "-":
        return 0.3
    ref_lower = ref.lower()
    if any(p in ref_lower for p in ['<script', 'javascript:', 'union', 'select ', '../', 'etc/passwd', 'onerror', 'onload']):
        return 1.0
    if '%' in ref and ref.count('%') >= 3:
        return 0.6
    if '%' in ref:
        return 0.4
    return 0.0


def feat_param_names_anomaly(query):
    if not query:
        return 0
    try:
        params = parse_qs(query, keep_blank_values=True)
        return sum(1 for k in params.keys() if k.lower() in SUSPICIOUS_PARAM_NAMES)
    except Exception:
        return 0


def feat_param_value_max_entropy(query):
    if not query:
        return 0.0
    try:
        params = parse_qs(query, keep_blank_values=True)
        best = 0.0
        for values in params.values():
            for v in values:
                if len(v) >= 4:
                    e = calculate_entropy(v)
                    if e > best:
                        best = e
        return best
    except Exception:
        return 0.0


def feat_longest_param_value(query):
    if not query:
        return 0
    try:
        params = parse_qs(query, keep_blank_values=True)
        return max((len(v) for vs in params.values() for v in vs), default=0)
    except Exception:
        return 0


def feat_status_indicator(status):
    try:
        s = int(status)
    except (TypeError, ValueError):
        return 0
    if s < 300:
        return 0
    if s < 400:
        return 1
    if s < 500:
        return 2
    return 3


def feat_consecutive_encoding_intensity(raw_url):
    if not raw_url:
        return 0.0
    matches = CONSEC_ENC_RE.findall(raw_url)
    if not matches:
        return 0.0
    total_enc_chars = sum(len(m) for m in matches)
    return total_enc_chars / len(raw_url)


def feat_signature_score(decoded_payload):
    score = 0
    if SIG_SQL_RE.search(decoded_payload):
        score += 1
    if SIG_XSS_RE.search(decoded_payload):
        score += 1
    if SIG_LFI_RE.search(decoded_payload):
        score += 1
    if SIG_CMD_RE.search(decoded_payload):
        score += 1
    return score


def feat_risk_keyword_density(decoded_payload):
    if not decoded_payload:
        return 0.0
    words = re.findall(r'[A-Za-z_]+', decoded_payload.lower())
    if not words:
        return 0.0
    hits = sum(1 for w in words if w in ALL_KEYWORDS)
    return hits / len(words)


def feat_method_path_combo_risk(method, path):
    score = 0.0
    path_lower = path.lower()
    if any(p in path_lower for p in SENSITIVE_PATH_PARTS):
        score += 1.0
    if method == 'POST' and any(p in path_lower for p in ['/login', '/admin', '/upload', '/api']):
        score += 1.0
    if method in ('PUT', 'DELETE', 'PATCH'):
        score += 1.0
    if method == 'GET' and ('/admin' in path_lower or '/config' in path_lower):
        score += 0.5
    return score


def feat_path_special_chars(path):
    specials = set(";|$`<>'\"\\%&()*")
    return sum(1 for c in path if c in specials)


def feat_unknown_param_ratio(path, query, path_param_vocab):
    """
    Phase 3.1 (B) — per-endpoint parameter vocabulary.

    Returns the fraction of param names on this request that were never
    seen on this path during training. If the path itself is brand-new
    (not in vocab at all) returns 1.0 (entirely unknown endpoint).
    If vocab is empty (e.g. legacy model without vocab) returns 0.0.
    """
    if not path_param_vocab:
        return 0.0
    if path not in path_param_vocab:
        return 1.0
    if not query:
        return 0.0
    try:
        params = parse_qs(query, keep_blank_values=True)
        if not params:
            return 0.0
        known = path_param_vocab[path]
        unknown = sum(1 for k in params.keys() if k not in known)
        return unknown / len(params)
    except Exception:
        return 0.0


# ---------- main class ----------
class LogAnomalyDetector:
    """
    Hỗ trợ các model:
      - 'if'   : Isolation Forest
      - 'ocsvm': One-Class SVM
      - 'lof'  : Local Outlier Factor

    Phase 3: 21 features, contamination/nu restored to Phase 1 best (0.50/0.60).
    """

    FEATURE_NAMES = [
        # Phase 1/2 (9 base features)
        "len_url", "raw_risk_count", "path_depth", "is_post", "risk_ratio",
        "entropy", "keyword_hits", "encoding_ratio", "param_count",
        # Phase 3 (12 new features)
        "suspicious_ua_score", "referer_suspicion",
        "param_names_anomaly", "param_value_max_entropy", "longest_param_value",
        "status_code_indicator", "encoding_depth", "consecutive_encoding_intensity",
        "signature_score", "risk_keyword_density", "method_path_combo_risk",
        "path_special_chars",
        # Phase 3.1 (B) — per-endpoint parameter vocabulary
        "unknown_param_ratio",
    ]

    def __init__(self, model_type="if"):
        self.model_type = model_type.lower()
        self.model_path = f"ad_model_{self.model_type}.pkl"
        self.scaler_path = f"ad_scaler_{self.model_type}.pkl"
        self.vocab_path = f"ad_vocab_{self.model_type}.pkl"

        self.model = None
        self.scaler = StandardScaler()
        # Phase 3.1 (B): {path: set(param_names)} learned from training data.
        self.path_param_vocab = {}

        # Restored Phase 1 best contamination/nu (Phase 2 reduction backfired).
        if self.model_type == "if":
            self.clf = IsolationForest(
                contamination=0.50,
                random_state=42,
                n_jobs=-1,
                n_estimators=200,
            )
        elif self.model_type == "ocsvm":
            self.clf = OneClassSVM(
                nu=0.60,
                kernel="rbf",
                gamma="scale",
            )
        elif self.model_type == "lof":
            self.clf = LocalOutlierFactor(
                n_neighbors=20,
                contamination=0.50,
                novelty=True,
            )
        else:
            raise ValueError(f"[LỖI] Không hỗ trợ model: {self.model_type}")

    # ---------- feature extraction ----------
    def extract_features(self, path, query, method, status, user_agent="", referer=""):
        path = str(path) if path is not None else ""
        query = str(query) if query is not None else ""
        method = str(method) if method is not None else ""
        user_agent = str(user_agent) if user_agent is not None else ""
        referer = str(referer) if referer is not None else ""

        full_url = path + query
        if not full_url:
            full_url = "/"

        fully_decoded_url, decode_depth = multi_decode(full_url, max_iter=3)

        # 1. URL length
        len_url = len(full_url)
        if len_url == 0:
            len_url = 1

        # 2. Risky chars from fully decoded URL
        risk_chars = [";", "|", "$", "`", "(", ")", "<", ">", "'", '"', "{", "}", "\\"]
        raw_risk_count = sum(fully_decoded_url.count(c) for c in risk_chars)

        # 3. Path depth
        path_depth = path.count('/')

        # 4. POST flag
        is_post = 1 if method == "POST" else 0

        # 5. Risk ratio
        risk_ratio = raw_risk_count / len_url

        # 6. Entropy of fully decoded URL
        entropy = calculate_entropy(fully_decoded_url)

        # 7. Sensitive keyword hits
        decoded_lower = fully_decoded_url.lower()
        keyword_hits = sum(1 for k in ALL_KEYWORDS if k in decoded_lower)

        # 8. Encoding ratio (raw)
        encoding_ratio = full_url.count('%') / len_url

        # 9. Parameter count
        param_count = query.count('=')

        # ----- Phase 3 features -----
        # 10. Suspicious User-Agent score
        ua_score = feat_suspicious_ua_score(user_agent)

        # 11. Referer suspicion
        ref_score = feat_referer_suspicion(referer)

        # 12. Suspicious parameter names
        param_names = feat_param_names_anomaly(query)

        # 13. Max entropy across parameter values
        pv_entropy = feat_param_value_max_entropy(query)

        # 14. Longest param value
        longest_pv = feat_longest_param_value(query)

        # 15. Status code bucket
        status_ind = feat_status_indicator(status)

        # 16. Encoding depth (already computed above)
        enc_depth = decode_depth

        # 17. Consecutive encoding intensity
        consec_enc = feat_consecutive_encoding_intensity(full_url)

        # 18. Signature score (regex aggregate over decoded payload)
        sig_score = feat_signature_score(fully_decoded_url)

        # 19. Risk keyword density
        kw_density = feat_risk_keyword_density(fully_decoded_url)

        # 20. Method + path combo risk
        combo_risk = feat_method_path_combo_risk(method, path)

        # 21. Special chars in path itself
        path_specials = feat_path_special_chars(path)

        # 22. (Phase 3.1, B) unknown param ratio against learned vocab
        unk_param = feat_unknown_param_ratio(path, query, self.path_param_vocab)

        return [
            len_url, raw_risk_count, path_depth, is_post, risk_ratio,
            entropy, keyword_hits, encoding_ratio, param_count,
            ua_score, ref_score,
            param_names, pv_entropy, longest_pv,
            status_ind, enc_depth, consec_enc,
            sig_score, kw_density, combo_risk,
            path_specials,
            unk_param,
        ]

    # ---------- training / loading / prediction ----------
    def _row_features(self, d):
        return self.extract_features(
            d.get('path', ''),
            d.get('query', ''),
            d.get('method', ''),
            d.get('status', 0),
            d.get('user_agent', ''),
            d.get('referer', ''),
        )

    def _build_param_vocab(self, log_data):
        """Phase 3.1 (B): learn {path: set(param_names)} from training logs."""
        vocab = {}
        for d in log_data:
            path = d.get('path', '') or ''
            query = d.get('query', '') or ''
            if path not in vocab:
                vocab[path] = set()
            if not query:
                continue
            try:
                params = parse_qs(query, keep_blank_values=True)
                vocab[path].update(params.keys())
            except Exception:
                continue
        return vocab

    def train(self, log_data):
        if not log_data:
            print("[AI] Không có dữ liệu để train.")
            return

        # Phase 3.1 (B): build per-path param vocab BEFORE feature extraction,
        # so the unknown_param_ratio feature sees the learned vocab.
        print(f"[AI] (B) Đang xây dựng vocab tham số theo path từ {len(log_data)} log...")
        self.path_param_vocab = self._build_param_vocab(log_data)
        print(f"[AI] (B) Vocab: {len(self.path_param_vocab)} paths, "
              f"{sum(len(v) for v in self.path_param_vocab.values())} param-name entries.")

        n_feat = len(self.FEATURE_NAMES)
        print(f"[AI] Đang trích xuất đặc trưng từ {len(log_data)} dòng log ({n_feat} features)...")
        X_raw = [self._row_features(d) for d in log_data]

        print(f"[AI] Đang chuẩn hóa (Scaling) dữ liệu cho mô hình {self.model_type.upper()}...")
        X_scaled = self.scaler.fit_transform(X_raw)

        print(f"[AI] Đang huấn luyện mô hình {self.model_type.upper()}...")
        self.clf.fit(X_scaled)
        self.model = self.clf

        joblib.dump(self.model, self.model_path)
        joblib.dump(self.scaler, self.scaler_path)
        joblib.dump(self.path_param_vocab, self.vocab_path)
        print(f"[AI] Đã lưu model {self.model_path}, scaler {self.scaler_path}, vocab {self.vocab_path}")

    def load_model(self):
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            try:
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                expected = len(self.FEATURE_NAMES)
                actual = getattr(self.scaler, 'n_features_in_', expected)
                if actual != expected:
                    print(f"[CẢNH BÁO] Scaler kỳ vọng {actual} features nhưng code hiện sinh {expected}. "
                          f"Vui lòng train lại model {self.model_type.upper()}.")
                    return False
                # Phase 3.1 (B): vocab is required for the 22nd feature.
                if os.path.exists(self.vocab_path):
                    self.path_param_vocab = joblib.load(self.vocab_path)
                    print(f"[AI] Đã load model + scaler + vocab cho {self.model_type.upper()} "
                          f"({expected} features, vocab={len(self.path_param_vocab)} paths)")
                else:
                    self.path_param_vocab = {}
                    print(f"[CẢNH BÁO] Không tìm thấy {self.vocab_path}. Feature unknown_param_ratio sẽ luôn = 0. "
                          f"Vui lòng train lại model {self.model_type.upper()}.")
                return True
            except Exception as e:
                print(f"[LỖI] Lỗi khi load model: {e}")
                return False
        return False

    def predict(self, path, query, method, status, user_agent="", referer=""):
        if not self.model or not self.scaler:
            return False

        features = self.extract_features(path, query, method, status, user_agent, referer)
        features_scaled = self.scaler.transform([features])
        pred = self.model.predict(features_scaled)
        return pred[0] == -1
