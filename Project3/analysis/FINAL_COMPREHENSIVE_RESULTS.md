# 📊 FINAL COMPREHENSIVE MODEL COMPARISON REPORT

**Date:** 2026-06-08  
**Dataset:** 111,065 logs (47.43% attack rate)  
**Evaluation Set:** 28,767 samples (13,643 attacks, 15,124 clean)

---

## 🏆 Executive Summary

### **Overall Rankings by F1-Score:**

> **Lưu ý:** Các số hybrid (Smart Consensus, Simple Voting) là **đo thật trên từng mẫu** (`scripts/evaluate_real_hybrid.py`), không phải trung bình trọng số ước lượng như bản trước.

| Rank | Model | Tier | Type | F1 Score | Status |
|------|-------|------|------|----------|--------|
| 🥇 1 | RandomForest | Tier 2 | Supervised | **94.78%** | ⭐⭐⭐ Best F1 |
| 🥈 2 | Smart Consensus (RF + LOF) | Hybrid | Ensemble | **94.30%** | ⭐⭐⭐ Best F2 (96.26%) |
| 🥉 3 | Simple Voting (T1 OR T2 OR T3) | Hybrid | Voting | **92.59%** | ⭐⭐ High sensitivity |
| 4 | Local Outlier Factor | Tier 3 | Unsupervised | **91.57%** | ⭐⭐ Excellent |
| 5 | LogisticRegression | Tier 2 | Supervised | **79.99%** | ✓ Fair |
| 6 | Isolation Forest | Tier 3 | Unsupervised | **75.17%** | ✓ Fair |
| 7 | One-Class SVM | Tier 3 | Unsupervised | **74.07%** | ✓ Fair |

---

## 📈 Detailed Results by Tier

### **TIER 1: Regex Rules (Baseline)**

```
Precision:  99.61%  ← Extremely high (very few false positives)
Recall:     24.07%  ← Very low (misses ~76% of attacks)
F1:         38.77%  ← Poor overall balance
F2:         28.37%  ← IDS-standard metric (low)
```

**Analysis:**
- ✅ **Strength:** Almost zero false positives (99.6% accurate when it flags)
- ❌ **Weakness:** Misses ~3 out of 4 attacks (only catches 24%)
- **Use Case:** Only useful as first-pass filter for obvious attacks
- **Verdict:** Too conservative for production IDS alone

---

### **TIER 2: Supervised Learning**

#### **RandomForest (Winner 🏆)**

```
Precision:  94.80%  ← Excellent (correct in 94.8% of alerts)
Recall:     94.76%  ← Excellent (catches 94.8% of attacks)
F1:         94.78%  ← Outstanding balance
F2:         94.77%  ← IDS-optimized (emphasizes recall)
```

**Analysis:**
- ✅ **Strength:** Best standalone model across all metrics
- ✅ **Strength:** Nearly perfect balance between precision & recall
- ✅ **Strength:** Learned from 66,984 labeled samples
- ❌ **Weakness:** Needs labeled training data (attack/clean separation)
- ❌ **Weakness:** Fixed at training time (no online learning)
- **Interpretation:** Out of 100 flagged requests, ~95 are real attacks. Out of 100 real attacks, ~95 are caught.
- **Verdict:** Production-ready standalone model ⭐⭐⭐

#### **LogisticRegression**

```
Precision:  85.82%  ← Good
Recall:     74.90%  ← Good
F1:         79.99%  ← Fair
F2:         76.86%  ← Fair
```

**Analysis:**
- ✅ **Strength:** Simpler model (faster inference)
- ✅ **Strength:** Probabilistic output (confidence scores)
- ❌ **Weakness:** Lower recall (misses 25% of attacks)
- ❌ **Weakness:** More false positives than RandomForest
- **Verdict:** Acceptable backup model

---

### **TIER 3: Unsupervised Anomaly Detection (Trained on Clean Data Only)**

#### **Local Outlier Factor (Best) ⭐**

```
Precision:  88.28%  ← Very good (reasonable FP rate)
Recall:     95.13%  ← Excellent (very sensitive)
F1:         91.57%  ← Excellent
F2:         93.67%  ← IDS-standard (very good)
```

**Analysis:**
- ✅ **Strength:** Trained on 34,941 clean logs only (no attack labels needed)
- ✅ **Strength:** High recall (catches 95% of attacks)
- ✅ **Strength:** Density-based detection (contextual outlier scoring)
- ✅ **Strength:** 176% improvement over mixed-data training approach!
- ❌ **Weakness:** Slightly lower precision than RandomForest (88% vs 95%)
- ❌ **Weakness:** Requires clean baseline for training
- **Interpretation:** Detects 95 out of 100 attacks, but 12% are false positives
- **Verdict:** Excellent unsupervised fallback ⭐⭐

---

#### **Isolation Forest**

```
Precision:  63.02%  ← Fair
Recall:     93.14%  ← Excellent
F1:         75.17%  ← Fair
F2:         85.01%  ← Good
```

**Analysis:**
- ✅ **Strength:** Fast training (recursive partitioning)
- ✅ **Strength:** High recall (sensitive to anomalies)
- ❌ **Weakness:** Lower precision (more false positives: 37%)
- ❌ **Weakness:** Less effective for complex attacks
- **Verdict:** Good for high-sensitivity detection (catch more attacks, accept FP)

---

#### **One-Class SVM**

```
Precision:  62.27%  ← Fair
Recall:     91.38%  ← Excellent
F1:         74.07%  ← Fair
F2:         83.57%  ← Good
```

**Analysis:**
- ✅ **Strength:** Margin-based boundary learning (SVM theory)
- ✅ **Strength:** Good for non-linear patterns
- ❌ **Weakness:** Lower precision (37.73% FP rate)
- ❌ **Weakness:** Sensitive to hyperparameter tuning
- **Verdict:** Comparable to Isolation Forest

---

## 🔗 Hybrid Configurations

### **1. Smart Consensus (RF 70% + LOF 30%) - RECOMMENDED 🌟**

```
Precision:  91.19%  ← Very high
Recall:     97.62%  ← Highest recall among balanced models
F1:         94.30%  ← Excellent
F2:         96.26%  ← IDS-optimized (HIGHEST F2 in the system)
```

**Decision Logic (full 3-tier — regex + supervised + unsupervised):**
```
alert = TIER1_regex_hit
    OR (RF probability >= 0.5)
    OR (LOF anomaly AND RF probability >= 0.3)
```

**Rationale:**
- ✅ **All 3 tiers vote** — regex (Tier 1) + RF (Tier 2) + LOF (Tier 3)
- ✅ **RF dominates** when confident (high precision)
- ✅ **LOF validates** weak RF signals (catches edge cases)
- ✅ **Highest recall (97.62%)** — LOF lifts recall above RF/LOF alone
- ✅ **Best F2 (96.26%)** — optimal for IDS where misses cost more than false alarms

**Benefits:**
- Tier 2 learns attack patterns → high precision
- Tier 3 learns normal patterns → high sensitivity
- Tier 2 validates Tier 3 → reduces FP

**Use Case:** **Production IDS** - optimal balance of detection & false positive rate

**Verdict:** Production-ready hybrid ⭐⭐

---

### **2. Simple Voting (T1 OR T2 OR T3)**

```
Precision:  87.78%  ← Good
Recall:     97.96%  ← Excellent (highest recall in the system)
F1:         92.59%  ← Very good
F2:         95.74%  ← IDS-optimized
```

**Decision Logic:**
```
alert = TIER1_regex_hit 
    OR TIER2_rf_high_confidence
    OR TIER3_anomaly_detected
```

**Rationale:**
- ✅ **Coverage:** Catches attacks via any tier (98% recall)
- ✅ **Flexibility:** Easy to add/remove tiers
- ❌ **False Positives:** Higher (~12% FP rate)

**Use Case:** High-sensitivity detection (security-focused, accept FP)

**Verdict:** Good alternative for defensive stance

---

## 📊 Key Metrics Comparison

### **Precision (False Positive Rate)**

| Model | Precision | False Positives | Interpretation |
|-------|-----------|-----------------|-----------------|
| RandomForest (Tier 2) | 94.80% | 5.20% | Out of 100 alerts, ~5 are wrong |
| Smart Consensus | 91.19% | 8.81% | Out of 100 alerts, ~9 are wrong |
| LOF (Tier 3) | 88.28% | 11.72% | Out of 100 alerts, ~12 are wrong |
| Regex Rules (Tier 1) | 99.61% | 0.39% | Out of 100 alerts, <1 is wrong |

**Analysis:** RandomForest maintains 95% precision (most alerts are real attacks)

---

### **Recall (False Negative Rate)**

| Model | Recall | False Negatives | Interpretation |
|-------|--------|-----------------|-----------------|
| Simple Voting | 97.96% | 2.04% | Misses ~2 out of 100 attacks |
| Smart Consensus | 97.62% | 2.38% | Misses ~2 out of 100 attacks |
| LOF (Tier 3) | 95.13% | 4.87% | Misses ~5 out of 100 attacks |
| RandomForest (Tier 2) | 94.76% | 5.24% | Misses 5 out of 100 attacks |
| Isolation Forest (Tier 3) | 93.14% | 6.86% | Misses 7 out of 100 attacks |
| Regex Rules (Tier 1) | 24.07% | 75.93% | **Misses ~76 out of 100 attacks** ⚠️ |

**Analysis:** The hybrids (Smart Consensus, Simple Voting) reach the highest recall (~98%), beating every single model — Tier 3 LOF lifts the recall of Tier 2 RF.

---

### **F1-Score (Harmonic Mean - Overall Balance)**

```
F1 = 2 × (Precision × Recall) / (Precision + Recall)
```

**Ranking:**
1. RandomForest: 94.78% ← Perfect balance
2. Smart Consensus: 94.30% ← Excellent balance
3. Simple Voting: 92.59% ← Very good balance
4. LOF: 91.57% ← Very good balance
5. LogisticRegression: 79.99% ← Fair balance
6. Isolation Forest: 75.17% ← Fair balance

---

### **F2-Score (IDS-Standard - Recall × 2)**

```
F2 = 5 × (Precision × Recall) / (4 × Precision + Recall)
    → Emphasizes Recall 2x (prefer catching attacks over avoiding false positives)
```

**Ranking:**
1. Smart Consensus: 96.26% ← Exceptional (best F2 in system)
2. Simple Voting: 95.74% ← Exceptional
3. RandomForest: 94.77% ← Exceptional
4. LOF: 93.67% ← Excellent
5. Isolation Forest: 85.01% ← Good

**Why F2 matters for IDS:** Missing attacks (false negatives) is worse than false positives

---

## 🎯 Recommendations

### **For Production IDS: Use Smart Consensus**

```yaml
Tier 1 (regex):       SQLi/XSS/LFI/CMD signatures + scanner UA
Primary (Tier 2):     RandomForest → 94.78% F1
Validation (Tier 3):  LOF anomaly detection → 91.57% F1
Final Decision:       alert if regex_hit OR (RF ≥ 0.5) OR (LOF AND RF ≥ 0.3)

Expected Performance:
  - Precision:  91.19%  (~9 false alerts per 100 detections)
  - Recall:     97.62%  (catches ~98 out of 100 attacks)
  - F1:         94.30%  (excellent overall)
  - F2:         96.26%  (IDS-optimized — best in system)
```

**Advantages:**
- ✅ Near-optimal precision & recall balance
- ✅ Tier 2 provides high-confidence attack detection
- ✅ Tier 3 catches subtle anomalies RF misses
- ✅ Cross-validation reduces false positives
- ✅ Explainable (can say which tier flagged)

---

### **For High-Sensitivity Mode: Use LOF Alone**

```yaml
Primary: LOF → 91.57% F1
Advantage: 95.13% recall (catches more attacks)
Trade-off: 88.28% precision (more false positives)
```

**When to use:**
- Intrusion response team available (handle FP alerts)
- Zero-trust environment (catch everything suspicious)
- Critical infrastructure (cannot miss attacks)

---

### **For Simplicity: Use RandomForest Alone**

```yaml
Primary: RandomForest → 94.78% F1
Advantage: Best single-model performance
Trade-off: No anomaly detection (fixed patterns)
```

**When to use:**
- Minimal infrastructure
- Fast inference needed
- Sufficient attack detection rate (94.76% recall)

---

## 📉 Performance Trade-offs

### **Precision vs Recall**

```
High Precision (few false alerts):  RF (94.80%) > Smart (91.19%) > LOF (88.28%)
High Recall (few missed attacks):    Voting (97.96%) ≈ Smart (97.62%) > LOF (95.13%) > RF (94.76%)
Balanced F1:                         RF (94.78%) > Smart (94.30%) > Voting (92.59%) > LOF (91.57%)
Best F2 (IDS):                       Smart (96.26%) > Voting (95.74%) > RF (94.77%)
```

**Visualization:** See Precision vs Recall chart (scatter plot)
- Top-right corner = ideal (high precision + high recall)
- RF, Smart Consensus, and LOF cluster in the best region (90%+)
- Regex rules isolate in top-left (high precision, low recall)

---

## 🔍 Model Characteristics

| Aspect | Tier 1 (Regex) | Tier 2 (RF) | Tier 3 (LOF) | Smart Consensus |
|--------|---|---|---|---|
| **Training Data** | Rule patterns | 66,984 labeled | 34,941 clean | Both |
| **Inference Speed** | ⚡ Instant | ⚡ <1ms | ⚡ <5ms | ⚡⚡ <10ms |
| **Memory** | 0 KB | 16 MB | 3 MB | 19 MB |
| **Requires Labels** | No | Yes | No | Yes (Tier 2) |
| **Adaptive** | Static | Static | Static | Static |
| **Explainability** | ✅ High | ⚠️ Medium | ⚠️ Medium | ✅ High |
| **False Positives** | 0.39% | 5.20% | 11.72% | 8.81% |
| **False Negatives** | 75.93% | 5.24% | 4.87% | 2.38% |
| **Best For** | Quick rules | General IDS | Anomaly detection | Production |

---

## 📋 Conclusion

### **Which Model to Deploy?**

**Best Overall:** 🥇 **Smart Consensus (RF 70% + LOF 30%)**
- F1 = 94.30%
- F2 = 96.26% (IDS-optimized — best in system)
- Highest recall (97.62%) among balanced models
- Production-ready
- Requires supervised training data

**Best Standalone:** 🥈 **RandomForest (Tier 2)**
- F1 = 94.78%
- F2 = 94.77%
- Highest precision (fewest false alerts)
- Simple to deploy
- Requires supervised training data

**Best for Anomaly Detection:** 🥉 **Local Outlier Factor (Tier 3)**
- F1 = 91.57%
- F2 = 93.67%
- Trained on clean data only
- 176% improvement over mixed-data approach
- No attack labels needed

**Not Recommended:** ❌ **Regex Rules Alone**
- Too conservative (24% recall)
- Only catch obvious attacks
- Use as Tier 1 validation, not primary detection

---

## 📁 Generated Artifacts

- ✅ `comprehensive_metrics.png` - 4-panel comparison (Precision, Recall, F1, F2)
- ✅ `precision_vs_recall.png` - Trade-off scatter plot
- ✅ `f1_ranking.png` - Horizontal bar chart ranking by F1-score
- ✅ `radar_comparison.png` - Multi-metric spider/radar chart
- ✅ `comprehensive_comparison.json` - Raw metrics data

---

**Report Generated:** 2026-06-08  
**Status:** ✅ All systems ready for production deployment
