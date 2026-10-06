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

st.set_page_config(page_title="Cybersecurity GRC Dashboard", layout="wide")
st.title("Cybersecurity GRC Control & Evidence Dashboard")

controls_df = pd.DataFrame(CONTROL_DATA)
framework_counts = map_controls_by_framework(CONTROL_DATA)
summary = summarize_risk_register(CONTROL_DATA)

with st.sidebar:
    st.header("Filters")
    framework = st.selectbox("Framework", ["All", *sorted(framework_counts)])
    domain = st.selectbox("Domain", ["All", *sorted(controls_df["domain"].unique())])

    if framework != "All":
        controls_df = controls_df[controls_df["framework"] == framework]
    if domain != "All":
        controls_df = controls_df[controls_df["domain"] == domain]

    st.markdown("---")
    st.caption("Designed for GRC, ISO 27001, NIST CSF 2.0, NIS2, and GDPR reporting.")

overview = st.columns(4)
with overview[0]:
    st.metric("Overall control score", f"{compute_overall_score(controls_df):.1f}%")
with overview[1]:
    st.metric("Open control gaps", int((100 - compute_overall_score(controls_df)) / 10))
with overview[2]:
    st.metric("High-risk items", summary["high"] + summary["critical"])
with overview[3]:
    st.metric("Framework coverage", len(framework_counts))

st.subheader("Board summary")
summary_col, chart_col = st.columns([1.4, 1])
with summary_col:
    st.write(
        "This dashboard demonstrates a real-world GRC operating model: controls are mapped to frameworks, owners are assigned, and evidence is tracked to support governance and compliance decisions."
    )
    st.write(
        "Key focus areas: reduce legacy hardening gaps, improve evidence retention, and strengthen control validation for high-impact systems."
    )

with chart_col:
    st.bar_chart(controls_df.groupby("domain")["status_score"].mean().round(1))

st.subheader("Framework coverage")
framework_df = pd.DataFrame(
    [{"Framework": key, "Controls": value} for key, value in framework_counts.items()]
)
st.dataframe(framework_df, use_container_width=True, hide_index=True)

st.subheader("Priority controls")
priority_df = pd.DataFrame(prioritize_controls(controls_df.to_dict("records")))
st.dataframe(priority_df, use_container_width=True, hide_index=True)

st.subheader("Control register")
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
st.dataframe(controls_df[show_columns], use_container_width=True, hide_index=True)

st.subheader("GRC narrative")
st.info(
    "This project is intentionally designed to show how governance and risk programs can be represented in a business-friendly dashboard. "
    "It maps controls to common frameworks and demonstrates evidence-based compliance management."
)
