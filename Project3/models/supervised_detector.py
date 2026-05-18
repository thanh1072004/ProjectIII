"""
Supervised classifier for the IDS — comparison baseline against the
unsupervised IF/OCSVM/LOF models. Uses the SAME 22-feature vector as
LogAnomalyDetector so the only difference being measured is "labeled
data + supervised algorithm" vs "no labels + anomaly detection".

Algorithms supported:
  - 'rf' : RandomForestClassifier (default — robust, no scaling needed)
  - 'lr' : LogisticRegression (linear baseline)
"""
import os
import joblib
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
)

# Reuse the unsupervised extractor + vocab so the feature space is identical.
from models.ai_detector import LogAnomalyDetector, parse_qs


class SupervisedDetector:
    def __init__(self, algo="rf"):
        self.algo = algo.lower()
        self.model_path = f"sup_model_{self.algo}.pkl"
        self.scaler_path = f"sup_scaler_{self.algo}.pkl"
        self.vocab_path = f"sup_vocab_{self.algo}.pkl"

        if self.algo == "rf":
            self.clf = RandomForestClassifier(
                n_estimators=200,
                max_depth=None,
                class_weight="balanced",
                n_jobs=-1,
                random_state=42,
            )
            self.needs_scaling = False
        elif self.algo == "lr":
            self.clf = LogisticRegression(
                max_iter=2000,
                class_weight="balanced",
                solver="lbfgs",
                random_state=42,
            )
            self.needs_scaling = True
        else:
            raise ValueError(f"[LỖI] Không hỗ trợ algo: {self.algo}")

        self.scaler = StandardScaler() if self.needs_scaling else None
        # We reuse LogAnomalyDetector ONLY as a feature extractor (its
        # extract_features() reads self.path_param_vocab so we set that here).
        self._extractor = LogAnomalyDetector(model_type="if")
        self.model = None

    # -- feature extraction (mirrors LogAnomalyDetector._row_features) --
    def _build_param_vocab(self, log_data):
        return self._extractor._build_param_vocab(log_data)

    def _row_features(self, d):
        return self._extractor.extract_features(
            d.get('path', ''),
            d.get('query', ''),
            d.get('method', ''),
            d.get('status', 0),
            d.get('user_agent', ''),
            d.get('referer', ''),
        )

    # -- training --
    def train(self, log_data, labels):
        """
        log_data: list of dicts with path/query/method/status/user_agent/referer
        labels:   list of 0/1 (1 = attack)
        """
        assert len(log_data) == len(labels)
        print(f"[SUP] (B) Building per-path param vocab from {len(log_data)} log entries...")
        self._extractor.path_param_vocab = self._build_param_vocab(log_data)
        n_paths = len(self._extractor.path_param_vocab)
        n_params = sum(len(v) for v in self._extractor.path_param_vocab.values())
        print(f"[SUP] (B) Vocab: {n_paths} paths, {n_params} param-name entries.")

        n_feat = len(self._extractor.FEATURE_NAMES)
        print(f"[SUP] Extracting features ({n_feat} features) from {len(log_data)} samples...")
        X = np.array([self._row_features(d) for d in log_data], dtype=float)
        y = np.array(labels, dtype=int)

        if self.needs_scaling:
            print(f"[SUP] Scaling features for {self.algo.upper()}...")
            X = self.scaler.fit_transform(X)

        print(f"[SUP] Training {self.algo.upper()} on {len(y)} samples "
              f"({y.sum()} attacks, {len(y) - y.sum()} normals)...")
        self.clf.fit(X, y)
        self.model = self.clf

        joblib.dump(self.model, self.model_path)
        if self.scaler is not None:
            joblib.dump(self.scaler, self.scaler_path)
        joblib.dump(self._extractor.path_param_vocab, self.vocab_path)
        print(f"[SUP] Saved: {self.model_path}"
              f"{' + '+self.scaler_path if self.scaler is not None else ''}"
              f" + {self.vocab_path}")

    def load_model(self):
        if not os.path.exists(self.model_path):
            return False
        try:
            self.model = joblib.load(self.model_path)
            self.clf = self.model  # so evaluate_batch / predict use the fitted estimator
            if self.needs_scaling and os.path.exists(self.scaler_path):
                self.scaler = joblib.load(self.scaler_path)
            if os.path.exists(self.vocab_path):
                self._extractor.path_param_vocab = joblib.load(self.vocab_path)
            print(f"[SUP] Loaded {self.algo.upper()} model "
                  f"(vocab={len(self._extractor.path_param_vocab)} paths)")
            return True
        except Exception as e:
            print(f"[LỖI] Lỗi khi load supervised model: {e}")
            return False

    def predict(self, path, query, method, status, user_agent="", referer=""):
        if self.model is None:
            return False
        feats = self._extractor.extract_features(path, query, method, status, user_agent, referer)
        X = np.array([feats], dtype=float)
        if self.needs_scaling:
            X = self.scaler.transform(X)
        return bool(self.clf.predict(X)[0] == 1)

    def predict_proba(self, path, query, method, status, user_agent="", referer=""):
        if self.model is None:
            return 0.0
        feats = self._extractor.extract_features(path, query, method, status, user_agent, referer)
        X = np.array([feats], dtype=float)
        if self.needs_scaling:
            X = self.scaler.transform(X)
        return float(self.clf.predict_proba(X)[0][1])

    # -- batch eval helper --
    def evaluate_batch(self, log_data, labels):
        X = np.array([self._row_features(d) for d in log_data], dtype=float)
        y = np.array(labels, dtype=int)
        if self.needs_scaling:
            X = self.scaler.transform(X)
        y_pred = self.clf.predict(X)
        cm = confusion_matrix(y, y_pred, labels=[0, 1])
        return {
            "tn": int(cm[0, 0]), "fp": int(cm[0, 1]),
            "fn": int(cm[1, 0]), "tp": int(cm[1, 1]),
            "accuracy":  accuracy_score(y, y_pred) * 100,
            "precision": precision_score(y, y_pred, zero_division=0) * 100,
            "recall":    recall_score(y, y_pred, zero_division=0) * 100,
            "f1":        f1_score(y, y_pred, zero_division=0) * 100,
        }
