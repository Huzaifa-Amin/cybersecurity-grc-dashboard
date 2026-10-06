"""Cybersecurity GRC dashboard package."""

from .risk_engine import compute_overall_score, map_controls_by_framework, summarize_risk_register

__all__ = [
    "compute_overall_score",
    "map_controls_by_framework",
    "summarize_risk_register",
]
