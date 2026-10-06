# Architecture Overview

This project is intentionally lightweight and readable so that a beginner can explain it clearly in interviews.

## High-level design

- Streamlit front end: dashboards, metrics, tables, and summary views
- Python data model: control definitions and risk logic
- Framework mapping: NIST CSF 2.0, ISO 27001 Annex A, NIS2, and GDPR
- Risk scoring: uses status maturity and risk severity to prioritize remediation

## Why this architecture is practical

The goal is not to build a complex SIEM or SOC system. The goal is to prove that you understand how governance, risk, and compliance programs work in practice.

This architecture is easy to understand and easy to defend in interviews:

- business users can read the dashboard
- risk owners can see accountability
- auditors can review evidence
- managers can see the gap between security policy and actual control maturity
