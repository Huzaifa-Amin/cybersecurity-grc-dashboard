from src.grc_dashboard.data import CONTROL_DATA
from src.grc_dashboard.risk_engine import compute_overall_score, map_controls_by_framework, summarize_risk_register


def test_compute_overall_score():
    score = compute_overall_score(CONTROL_DATA)
    assert isinstance(score, float)
    assert 70 <= score <= 90


def test_framework_map_has_entries():
    result = map_controls_by_framework(CONTROL_DATA)
    assert "NIST CSF 2.0" in result
    assert "ISO 27001 Annex A" in result
    assert "NIS2" in result


def test_risk_summary_counts_total_controls():
    result = summarize_risk_register(CONTROL_DATA)
    assert result["total"] == len(CONTROL_DATA)
    assert result["low"] + result["moderate"] + result["high"] + result["critical"] == len(CONTROL_DATA)
