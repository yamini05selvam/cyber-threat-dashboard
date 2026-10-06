
import streamlit as st
import pandas as pd
import numpy as np

st.set_page_config(
    page_title="Hybrid Transformer–PPO | Cyber Threat Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------
# Demo data
# -----------------------------
np.random.seed(23)

attack_types = ["Benign", "Botnet", "DDoS", "DoS", "PortScan", "BruteForce"]
protocols = ["TCP", "UDP", "ICMP", "DNS", "HTTP/HTTPS"]
actions = ["Allow", "Monitor", "Alert", "Block", "Isolate"]

n = 180
labels = np.random.choice(
    attack_types,
    size=n,
    p=[0.52, 0.09, 0.11, 0.08, 0.12, 0.08],
)
proto = np.random.choice(protocols, size=n, p=[0.45, 0.18, 0.07, 0.12, 0.18])

confidence = np.where(
    labels == "Benign",
    np.random.uniform(0.75, 0.99, n),
    np.random.uniform(0.72, 0.99, n),
)
anomaly = np.where(
    labels == "Benign",
    np.random.uniform(0.02, 0.35, n),
    np.random.uniform(0.45, 0.98, n),
)
risk = np.clip(
    0.25 * confidence + 0.55 * anomaly + np.random.normal(0, 0.05, n),
    0,
    1,
)

def choose_action(label, risk_score):
    if label == "Benign":
        return "Allow" if risk_score < 0.35 else "Monitor"
    if risk_score >= 0.82:
        return "Isolate"
    if risk_score >= 0.68:
        return "Block"
    if risk_score >= 0.48:
        return "Alert"
    return "Monitor"

df = pd.DataFrame({
    "Flow ID": [f"FLOW-{1001+i}" for i in range(n)],
    "Protocol": proto,
    "Threat": labels,
    "Confidence": confidence,
    "Anomaly Score": anomaly,
    "Risk Score": risk,
})
df["Recommended Action"] = [
    choose_action(t, r) for t, r in zip(df["Threat"], df["Risk Score"])
]
df["Source IP"] = [
    f"192.168.{np.random.randint(1,10)}.{np.random.randint(10,250)}"
    for _ in range(n)
]
df["Destination Port"] = np.random.choice(
    [21, 22, 53, 80, 443, 445, 3389, 8080], size=n
)

# -----------------------------
# Styling
# -----------------------------
st.markdown("""
<style>
.main {
    background: #0b1020;
}
.block-container {
    padding-top: 3.2rem !important;
    padding-bottom: 2rem;
}
[data-testid="stMetric"] {
    background: #16213a;
    border: 1px solid #334563;
    padding: 16px;
    border-radius: 12px;
}
[data-testid="stMetricLabel"] {
    color: #b9c7df !important;
    font-weight: 600 !important;
}
[data-testid="stMetricValue"] {
    color: #ffffff !important;
    font-size: 2rem !important;
    font-weight: 750 !important;
}
[data-testid="stMetricDelta"] {
    color: #8ee6b1 !important;
}
.dashboard-title {
    font-size: 1.85rem;
    line-height: 1.25;
    font-weight: 700;
    margin-top: 0.4rem;
    margin-bottom: 0.35rem;
}
.subtitle {
    color: #9aa8c2;
    margin-bottom: 1.2rem;
}
.section-title {
    font-size: 1.15rem;
    font-weight: 650;
    margin-top: 1rem;
}
.small-note {
    color: #8d9ab2;
    font-size: 0.85rem;
}
</style>
""", unsafe_allow_html=True)

# -----------------------------
# Sidebar
# -----------------------------
st.sidebar.title("🛡️ Threat Monitor")
st.sidebar.caption("Hybrid Transformer–PPO Framework")

st.sidebar.subheader("Filters")
selected_protocols = st.sidebar.multiselect(
    "Protocol",
    protocols,
    default=protocols,
)
selected_threats = st.sidebar.multiselect(
    "Threat class",
    attack_types,
    default=attack_types,
)
min_risk = st.sidebar.slider(
    "Minimum risk score",
    0.0, 1.0, 0.0, 0.05
)

filtered = df[
    df["Protocol"].isin(selected_protocols)
    & df["Threat"].isin(selected_threats)
    & (df["Risk Score"] >= min_risk)
].copy()

st.sidebar.divider()
st.sidebar.info(
    "Demo Mode: the displayed values are representative data for the "
    "Phase-1 dashboard. Replace the demo dataframe with your trained "
    "Transformer/anomaly/PPO outputs when available."
)

# -----------------------------
# Header
# -----------------------------
st.markdown(
    '<div class="dashboard-title">🛡️ Cyber Threat Detection & Adaptive Response</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="subtitle">Hybrid Transformer–PPO Framework &nbsp;•&nbsp; SOC Monitoring Dashboard</div>',
    unsafe_allow_html=True,
)

# -----------------------------
# System status
# -----------------------------
s1, s2, s3 = st.columns([1, 1, 2])
with s1:
    st.success("● Detection Engine Online")
with s2:
    st.info("● PPO Decision Layer Ready")
with s3:
    st.caption("CICIDS2017 • Offline flow analysis • Phase-1 prototype")

# -----------------------------
# KPI cards
# -----------------------------
total_flows = len(filtered)
threats = int((filtered["Threat"] != "Benign").sum())
anomalies = int((filtered["Anomaly Score"] >= 0.50).sum())
high_risk = int((filtered["Risk Score"] >= 0.75).sum())

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Flows", f"{total_flows:,}")
c2.metric("Threats Detected", f"{threats:,}")
c3.metric("Anomalies", f"{anomalies:,}")
c4.metric("High-Risk Events", f"{high_risk:,}")

st.divider()

# -----------------------------
# Charts
# -----------------------------
left, right = st.columns(2)

with left:
    st.markdown("#### Threat Distribution")
    threat_counts = (
        filtered["Threat"]
        .value_counts()
        .reindex(attack_types, fill_value=0)
        .rename("Flows")
    )
    st.bar_chart(threat_counts, height=300)

with right:
    st.markdown("#### Protocol Distribution")
    protocol_counts = (
        filtered["Protocol"]
        .value_counts()
        .reindex(protocols, fill_value=0)
        .rename("Flows")
    )
    st.bar_chart(protocol_counts, height=300)

# -----------------------------
# Response summary
# -----------------------------
st.markdown("#### PPO Adaptive Response Summary")
response_counts = (
    filtered["Recommended Action"]
    .value_counts()
    .reindex(actions, fill_value=0)
    .rename("Events")
)
st.bar_chart(response_counts, height=250)

# -----------------------------
# Detection details
# -----------------------------
tab1, tab2, tab3 = st.tabs(
    ["Threat Events", "Detection Analytics", "System Architecture"]
)

with tab1:
    st.markdown("#### Recent Threat Events")
    display_df = filtered.sort_values("Risk Score", ascending=False).head(25).copy()
    for col in ["Confidence", "Anomaly Score", "Risk Score"]:
        display_df[col] = display_df[col].round(3)

    st.dataframe(
        display_df[
            [
                "Flow ID",
                "Protocol",
                "Threat",
                "Confidence",
                "Anomaly Score",
                "Risk Score",
                "Recommended Action",
                "Source IP",
                "Destination Port",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )

with tab2:
    a, b, c = st.columns(3)
    avg_conf = filtered["Confidence"].mean() if len(filtered) else 0
    avg_anom = filtered["Anomaly Score"].mean() if len(filtered) else 0
    avg_risk = filtered["Risk Score"].mean() if len(filtered) else 0

    a.metric("Average Confidence", f"{avg_conf:.2f}")
    b.metric("Average Anomaly Score", f"{avg_anom:.2f}")
    c.metric("Average Risk Score", f"{avg_risk:.2f}")

    st.markdown("#### Threat vs. Risk")
    risk_table = (
        filtered.groupby("Threat")["Risk Score"]
        .mean()
        .reindex(attack_types)
        .fillna(0)
        .rename("Average Risk")
    )
    st.bar_chart(risk_table, height=280)

    st.markdown(
        '<div class="small-note">Detection stages: Transformer contextual '
        'representation → Known Threat Classifier + Anomaly Detector → threat/risk information.</div>',
        unsafe_allow_html=True,
    )

with tab3:
    st.markdown("#### Framework Flow")
    st.code(
        """CICIDS2017 Flow Data
        ↓
Data Cleaning + Normalization
        ↓
CART Feature Selection
        ↓
Transformer Encoder
        ↓
┌───────────────────────┬───────────────────────┐
│ Known Threat          │ Anomaly Detector      │
│ Classifier             │                       │
│ Benign / Botnet /      │ Anomaly Score         │
│ DDoS / DoS /           │ Unknown / Emerging   │
│ PortScan / BruteForce  │ Behavior             │
└──────────────┬────────┴──────────────┬────────┘
               ↓                       ↓
          Threat Information + Risk State
                       ↓
                  PPO Decision
                       ↓
       Allow / Monitor / Alert / Block / Isolate""",
        language="text",
    )

st.caption(
    "Phase-1 dashboard prototype — response actions are recommendations. "
    "Actual blocking/isolation requires external security infrastructure."
)
