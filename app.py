from __future__ import annotations

import streamlit as st
import pandas as pd

from src.grc_dashboard.data import CONTROL_DATA
from src.grc_dashboard.risk_engine import (
    compute_overall_score,
    map_controls_by_framework,
    prioritize_controls,
    summarize_risk_register,
)

st.set_page_config(page_title="Cybersecurity GRC Dashboard", page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
        :root {
            --bg: #f7fff9;
            --panel: #ffffff;
            --primary: #16a34a;
            --primary-soft: #ecfdf5;
            --success: #15803d;
            --warning: #f59e0b;
            --danger: #dc2626;
            --text: #1f2d1f;
            --muted: #5f6f5e;
            --border: #d8f5df;
            --shadow: 0 8px 18px rgba(22, 163, 74, 0.08);
        }
        .stApp {
            background: linear-gradient(180deg, #f8fff9 0%, #effcf3 100%);
            color: var(--text);
        }
        .block-container {
            padding-top: 2rem;
            padding-bottom: 2rem;
        }
        .metric-card {
            background: linear-gradient(135deg, var(--panel) 0%, #f0fff4 100%);
            border: 1px solid var(--border);
            border-radius: 18px;
            padding: 1.1rem 1.2rem;
            box-shadow: var(--shadow);
            min-height: 120px;
        }
        .metric-label {
            color: var(--muted);
            font-size: 0.82rem;
            font-weight: 600;
            letter-spacing: 0.02em;
            text-transform: uppercase;
        }
        .metric-value {
            margin-top: 0.6rem;
            color: var(--primary);
            font-size: 2rem;
            font-weight: 700;
        }
        .metric-sub {
            margin-top: 0.4rem;
            color: var(--muted);
            font-size: 0.85rem;
        }
        .status-box {
            background: #f1fff4;
            border-left: 4px solid var(--primary);
            padding: 0.9rem 1rem;
            border-radius: 12px;
            margin-top: 1rem;
            color: var(--text);
        }
        .section-header {
            color: var(--text);
            font-weight: 700;
            margin-top: 1.6rem;
            margin-bottom: 0.6rem;
        }
        div[data-testid="stSidebar"] {
            background: linear-gradient(180deg, #f9fff9 0%, #eefcf3 100%);
        }
        div[data-testid="stDataFrame"] {
            border-radius: 14px;
            overflow: hidden;
        }
        .stTabs [role="tablist"] {
            gap: 0.5rem;
        }
        .stTabs [role="tab"] {
            background: #f1fff4;
            border-radius: 12px 12px 0 0;
            color: var(--text);
            border: 1px solid var(--border);
        }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("Cybersecurity GRC Control & Evidence Dashboard")
st.caption("Governance • Risk • Compliance • Evidence")

controls_df = pd.DataFrame(CONTROL_DATA).copy()
framework_counts = map_controls_by_framework(CONTROL_DATA)
summary = summarize_risk_register(CONTROL_DATA)

with st.sidebar:
    st.header("Controls workspace")
    framework = st.selectbox("Framework", ["All", *sorted(framework_counts)])
    domain = st.selectbox("Domain", ["All", *sorted(controls_df["domain"].unique())])

    if framework != "All":
        controls_df = controls_df[controls_df["framework"] == framework]
    if domain != "All":
        controls_df = controls_df[controls_df["domain"] == domain]

    st.markdown("---")
    st.markdown("### Operating posture")
    st.info("Primary focus: reduce legacy hardening gaps and strengthen evidence retention for critical risk areas.")
    st.caption("Designed for GRC, ISO 27001, NIST CSF 2.0, NIS2, GDPR, and executive reporting.")

controls_list = controls_df.to_dict("records") if not controls_df.empty else []
score = compute_overall_score(controls_list)
open_gaps = max(0, round(100 - score, 0))
priority_items = summary["high"] + summary["critical"]

metric_columns = st.columns(4)
with metric_columns[0]:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Overall control score</div>
            <div class="metric-value">{score:.1f}%</div>
            <div class="metric-sub">Across {len(controls_df)} tracked controls</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
with metric_columns[1]:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Open gaps</div>
            <div class="metric-value">{open_gaps}</div>
            <div class="metric-sub">Areas needing action</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
with metric_columns[2]:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">High-risk items</div>
            <div class="metric-value">{priority_items}</div>
            <div class="metric-sub">Prioritized for remediation</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
with metric_columns[3]:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Framework coverage</div>
            <div class="metric-value">{len(framework_counts)}</div>
            <div class="metric-sub">Active control frameworks</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.markdown('<div class="section-header">Executive summary</div>', unsafe_allow_html=True)
summary_col, chart_col = st.columns([1.4, 1])
with summary_col:
    st.markdown(
        """
        <div class="status-box">
            This control landscape demonstrates a mature governance model with strong executive ownership, risk visibility, and evidence tracking. The largest residual risks remain in legacy hardening, evidence retention, and consistent validation of critical system controls.
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.write(
        "Priority actions: strengthen secure configuration baselines, validate evidence for critical assets, and formalize remediation tracking for high-risk exceptions."
    )

with chart_col:
    st.bar_chart(controls_df.groupby("domain")["status_score"].mean().round(1))

st.markdown('<div class="section-header">Framework coverage</div>', unsafe_allow_html=True)
framework_df = pd.DataFrame(
    [{"Framework": key, "Controls": value} for key, value in framework_counts.items()]
)
st.dataframe(framework_df, hide_index=True, use_container_width=True)

overview_tabs = st.tabs(["Overview", "Risk register", "Evidence and actions"])

with overview_tabs[0]:
    st.write("The dashboard is built to mirror how governance and risk programs are discussed in real organizations: ownership, evidence, risks, and control maturity are all visible in one place.")
    board_summary = [
        "Board accountability is embedded in the control model.",
        "Framework mapping supports NIST, ISO 27001, NIS2, and GDPR alignment.",
        "Controls are assigned to owners and linked to evidence placeholders.",
    ]
    for item in board_summary:
        st.markdown(f"- {item}")

with overview_tabs[1]:
    priority_df = pd.DataFrame(prioritize_controls(controls_df.to_dict("records")))
    st.dataframe(priority_df, hide_index=True, use_container_width=True)

with overview_tabs[2]:
    evidence_columns = [
        "id",
        "control",
        "owner",
        "status",
        "evidence",
        "due_date",
    ]
    st.dataframe(controls_df[evidence_columns], hide_index=True, use_container_width=True)
    st.info(
        "This project is intentionally designed as a portfolio artifact, not a production SOC platform. It demonstrates how governance professionals reason about risk, evidence, accountability, and control maturity."
    )

st.markdown('<div class="section-header">Control register</div>', unsafe_allow_html=True)
show_columns = [
    "id",
    "control",
    "domain",
    "framework",
    "owner",
    "status",
    "status_score",
    "evidence",
    "risk_level",
    "due_date",
]
st.dataframe(controls_df[show_columns], hide_index=True, use_container_width=True)

st.markdown('<div class="section-header">Recommended next actions</div>', unsafe_allow_html=True)
next_actions = [
    "Complete secure configuration baselines for legacy systems.",
    "Validate evidence retention for critical control artifacts.",
    "Formalize quarterly review process with business and technical owners.",
    "Document clear remediation ownership for high-risk exceptions.",
]
for action in next_actions:
    st.markdown(f"- {action}")
