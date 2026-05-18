"""
Streamlit dashboard for the Hybrid 3-Tier Real-Time IDS.

It reads `monitor_alerts.jsonl` (written by `apache_log.py monitor`) and
refreshes the view every 2 seconds.

Run locally:
    pip install streamlit pandas  (one-time)
    # Terminal 1 — start the monitor pipeline:
    tail -F /var/log/apache2/access.log | python apache_log.py monitor /dev/null lof
    # Terminal 2 — start the dashboard:
    streamlit run dashboard.py
"""
import json
import os
import time
from collections import Counter
from datetime import datetime

import pandas as pd
import streamlit as st

ALERT_FILE = os.environ.get("IDS_ALERT_FILE", "monitor_alerts.jsonl")
REFRESH_MS = int(os.environ.get("IDS_REFRESH_MS", "2000"))

# --- page config ---
st.set_page_config(
    page_title="Hybrid IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# --- auto-refresh ---
# Prefer streamlit_autorefresh if present, otherwise meta-refresh fallback.
try:
    from streamlit_autorefresh import st_autorefresh
    st_autorefresh(interval=REFRESH_MS, key="ids_refresh")
except ImportError:
    st.markdown(
        f'<meta http-equiv="refresh" content="{REFRESH_MS // 1000}">',
        unsafe_allow_html=True,
    )


# --- data loader ---
@st.cache_data(ttl=1.0)
def load_alerts(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        return pd.DataFrame()
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if not records:
        return pd.DataFrame()
    df = pd.DataFrame(records)
    df["ts"] = pd.to_datetime(df["ts"], errors="coerce")
    df = df.sort_values("ts", ascending=False).reset_index(drop=True)
    return df


df = load_alerts(ALERT_FILE)

# --- header ---
st.markdown("# 🛡️ Hybrid 3-Tier IDS — Live Dashboard")
hdr_l, hdr_r = st.columns([3, 2])
with hdr_l:
    st.caption(
        f"Reading **`{ALERT_FILE}`** · refresh every {REFRESH_MS // 1000}s · "
        f"last updated {datetime.now().strftime('%H:%M:%S')}"
    )
with hdr_r:
    if os.path.exists(ALERT_FILE):
        size_kb = os.path.getsize(ALERT_FILE) / 1024
        st.caption(f"Alert log size: {size_kb:.1f} KB · {len(df)} alerts")
    else:
        st.warning(f"Alert log `{ALERT_FILE}` not found yet. "
                   "Start the monitor (see top of `dashboard.py`).")

st.divider()

if df.empty:
    st.info("Waiting for alerts… (run `apache_log.py monitor` in another terminal)")
    st.stop()

# --- KPI cards ---
counts = Counter(df["level"])
total = len(df)
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total alerts", total)
c2.metric("🔴 CRITICAL", counts.get("CRITICAL", 0))
c3.metric("🟠 HIGH",     counts.get("HIGH", 0))
c4.metric("🟡 MEDIUM",   counts.get("MEDIUM", 0))
c5.metric("🔵 LOW",      counts.get("LOW", 0))

st.divider()

# --- two-column layout: charts on the left, recent feed on the right ---
left, right = st.columns([1, 1.4])

with left:
    # Level distribution
    st.subheader("Threat level distribution")
    level_df = pd.DataFrame({
        "level": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "count": [counts.get(l, 0) for l in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]],
    })
    st.bar_chart(level_df, x="level", y="count", height=240)

    # Top attacking IPs
    st.subheader("Top attacking IPs")
    if "client_ip" in df.columns:
        top_ips = (df["client_ip"].fillna("(unknown)")
                   .value_counts().head(10).rename_axis("IP")
                   .reset_index(name="alerts"))
        st.dataframe(top_ips, hide_index=True, use_container_width=True, height=260)

    # Per-tier contribution
    st.subheader("Per-tier contribution")
    tier_counter = Counter()
    for tier_list in df["tiers"].dropna():
        for entry in tier_list:
            name = entry.split("(", 1)[0]   # REGEX / SUPERVISED / UNSUPERVISED
            tier_counter[name] += 1
    tier_df = pd.DataFrame(
        {"tier": list(tier_counter.keys()), "alerts": list(tier_counter.values())}
    )
    st.bar_chart(tier_df, x="tier", y="alerts", height=200)

with right:
    st.subheader("Live alert feed (most recent first)")

    level_filter = st.multiselect(
        "Filter by severity",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    )
    fdf = df[df["level"].isin(level_filter)].copy()
    if "ts" in fdf.columns:
        fdf["time"] = fdf["ts"].dt.strftime("%H:%M:%S")
    else:
        fdf["time"] = ""
    fdf["tiers_str"] = fdf["tiers"].apply(lambda xs: ", ".join(xs) if isinstance(xs, list) else "")

    show_cols = ["time", "level", "score", "client_ip", "method", "raw_url", "tiers_str"]
    show_cols = [c for c in show_cols if c in fdf.columns]
    head_df = fdf[show_cols].head(50)

    def _row_style(row):
        color = {
            "CRITICAL": "background-color: #5a0d0d; color: #ffffff",
            "HIGH":     "background-color: #6b3000; color: #ffffff",
            "MEDIUM":   "background-color: #5c5300; color: #ffffff",
            "LOW":      "background-color: #003e5c; color: #ffffff",
        }.get(row.get("level"), "")
        return [color] * len(row)

    st.dataframe(
        head_df.style.apply(_row_style, axis=1),
        hide_index=True,
        use_container_width=True,
        height=520,
    )

st.divider()

# --- alerts over time ---
st.subheader("Alerts over time (last 5 min, 10-second bins)")
if "ts" in df.columns and df["ts"].notna().any():
    recent = df[df["ts"] >= (df["ts"].max() - pd.Timedelta(minutes=5))].copy()
    if not recent.empty:
        recent["bin"] = recent["ts"].dt.floor("10s")
        timeline = (recent.groupby(["bin", "level"]).size()
                    .unstack(fill_value=0)
                    .reindex(columns=["CRITICAL", "HIGH", "MEDIUM", "LOW"], fill_value=0))
        st.area_chart(timeline, height=240)
    else:
        st.caption("No alerts in the last 5 minutes.")

st.caption("Hybrid IDS · regex + supervised RF + unsupervised LOF · "
           "trained on CSIC e-commerce dataset")
