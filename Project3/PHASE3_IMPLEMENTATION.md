# Phase 3 Implementation — Feature Engineering Expansion

## Goal
Push recall from ~21% (Phase 1 best, LOF @ cont=0.50) up to **40–50%+** by replacing/augmenting the 9-feature vector with a 21-feature vector that brings more discriminative signals (headers, parameter structure, signature aggregates, encoding depth).

## Configuration changes

### Contamination / nu — restored to Phase 1 best
Phase 2 (cont=0.10) backfired (IF recall fell 6.4%, OCSVM fell 3.5%). Phase 3 restores Phase 1 settings:

| Model | Phase 2 (bad) | Phase 3 (restored) |
|-------|---------------|--------------------|
| IF    | 0.10          | **0.50**           |
| OCSVM | 0.10          | **0.60**           |
| LOF   | 0.10          | **0.50**           |

## Feature vector — 9 → 21

### Kept (9 base features)
1. `len_url` — raw URL length
2. `raw_risk_count` — count of risky chars in *fully decoded* URL
3. `path_depth` — `/` count in path
4. `is_post` — POST flag
5. `risk_ratio` — `raw_risk_count / len_url`
6. `entropy` — Shannon entropy of fully decoded URL
7. `keyword_hits` — SQL/XSS/LFI keyword hits in decoded URL
8. `encoding_ratio` — `%` density in raw URL
9. `param_count` — `=` count in query

### New (12 Phase 3 features)
10. `suspicious_ua_score` — scanner UAs (sqlmap/nikto/…) → 1.0; automated (curl/wget/python-requests) → 0.6; empty/short → 0.9–1.0; non-browser → 0.4
11. `referer_suspicion` — script/SQL/traversal payload in referer → 1.0; heavy `%` encoding → 0.4–0.6; missing → 0.3
12. `param_names_anomaly` — count of param names in attack-target set (`cmd`, `exec`, `file`, `path`, `url`, `redirect`, `admin`, `pwd`, …)
13. `param_value_max_entropy` — max Shannon entropy across all parameter values (≥4 chars)
14. `longest_param_value` — length of the longest param value
15. `status_code_indicator` — bucket: 2xx=0, 3xx=1, 4xx=2, 5xx=3
16. `encoding_depth` — number of `unquote` iterations needed to fully decode (>1 = nested encoding)
17. `consecutive_encoding_intensity` — fraction of URL covered by ≥2 consecutive `%XX` sequences (catches `%27%3B%20DROP`)
18. `signature_score` — count of regex families that match decoded payload: SQLi, XSS, LFI, CmdInj (0–4)
19. `risk_keyword_density` — risk-keyword hits divided by total word count in decoded payload
20. `method_path_combo_risk` — risky combinations: POST to `/login`/`/admin`/`/upload`, write methods (PUT/DELETE/PATCH), sensitive paths
21. `path_special_chars` — count of risky chars **inside the path itself** (not query)

## Code changes

### `models/ai_detector.py`
- Full rewrite. New helpers: `multi_decode`, `feat_suspicious_ua_score`, `feat_referer_suspicion`, `feat_param_names_anomaly`, `feat_param_value_max_entropy`, `feat_longest_param_value`, `feat_status_indicator`, `feat_consecutive_encoding_intensity`, `feat_signature_score`, `feat_risk_keyword_density`, `feat_method_path_combo_risk`, `feat_path_special_chars`.
- `LogAnomalyDetector.extract_features(path, query, method, status, user_agent="", referer="")` — back-compat: UA/referer default to `""`.
- `LogAnomalyDetector.predict(...)` — same extended signature.
- `FEATURE_NAMES` class attr lists all 21 names in order for downstream tooling.
- `load_model()` cross-checks `scaler.n_features_in_` against `len(FEATURE_NAMES)` and refuses to load mismatched scalers — old 9-feature `.pkl` files will print a clear "vui lòng train lại" warning instead of crashing at predict time.

### `apache_log.py`
- `parse_log_entry` now also extracts the `Referer` header.
- `build_training_item` now includes `user_agent` and `referer` in the dict it produces.
- All 3 `ai_engine.predict(...)` call sites (`scan` mode, `evaluate_model`, `monitor_realtime`) now forward `user_agent` + `referer`.
- `print_ai_debug` also forwards them so the 21-element vector is printed for debug payloads.

## Required steps before evaluation

The old `ad_model_*.pkl` / `ad_scaler_*.pkl` were trained with 9 features. They **must be retrained** before scan/evaluate works again. The existing `train` mode already deletes the old files automatically (`apache_log.py:145-150`).

```powershell
$env:PYTHONIOENCODING="utf-8"
cd d:\ProjectIII\ProjectIII\Project3

python apache_log.py train datasets/csic_train_clean.log if
python apache_log.py train datasets/csic_train_clean.log ocsvm
python apache_log.py train datasets/csic_train_clean.log lof
```

Then evaluate:

```powershell
python apache_log.py evaluate datasets/csic_test.log if
python apache_log.py evaluate datasets/csic_test.log ocsvm
python apache_log.py evaluate datasets/csic_test.log lof
```

## Expected results

| Model | Phase 1 (9f, cont=0.50) | Phase 3 target (21f, cont=0.50) |
|-------|-------------------------|----------------------------------|
| IF    | 18.63% recall, F1=31.4  | 40%+ recall, F1=50+              |
| OCSVM | 20.01% recall, F1=33.3  | 40%+ recall, F1=50+              |
| LOF   | **21.15% recall**, F1=34.9 | **45%+ recall**, F1=55+       |

Precision should remain ≥95% — the new features are designed to be discriminative, not noisy.

## Fallback if recall still <40% (Phase 4 candidates)
- Response-side features (response size, content-type) — requires extended log format
- Temporal/per-IP request frequency features
- Train on a **balanced** subset rather than normal-only (semi-supervised → supervised pivot)
- Replace anomaly detection with a supervised classifier (RF / XGBoost) using the same 21 features — anomaly models cap at ~50% recall on this dataset because CSIC "normal" traffic overlaps heavily with attacks in feature space.
