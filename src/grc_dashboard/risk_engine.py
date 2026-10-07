from __future__ import annotations

from collections import defaultdict
from statistics import mean
from typing import Any, Iterable, Mapping

RISK_RATING_ORDER = [
    ("Low", 0),
    ("Moderate", 1),
    ("High", 2),
    ("Critical", 3),
]


def compute_overall_score(controls: Iterable[Mapping[str, Any]]) -> float:
    values = [float(control["status_score"]) for control in controls]
    if not values:
        return 0.0
    return round(mean(values), 1)


def prioritize_controls(controls: Iterable[Mapping[str, Any]]) -> list[dict]:
    ranked = []
    for control in controls:
        risk_level = control.get("risk_level", "Critical")
        level_value = {label: index for index, (label, _) in enumerate(RISK_RATING_ORDER)}.get(
            risk_level, len(RISK_RATING_ORDER) - 1
        )
        ranked.append(
            {
                "id": control["id"],
                "control": control["control"],
                "risk_level": risk_level,
                "status_score": control.get("status_score", 0),
                "priority_score": (level_value * 25) + (100 - control.get("status_score", 0)),
                "owner": control.get("owner", "Unassigned"),
            }
        )
    return sorted(ranked, key=lambda item: item["priority_score"], reverse=True)


def map_controls_by_framework(controls: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for control in controls:
        counts[str(control.get("framework", "Unmapped"))] += 1
    return dict(sorted(counts.items()))


def summarize_risk_register(controls: Iterable[Mapping[str, Any]]) -> dict[str, float | int]:
    records = list(controls)
    total = len(records)
    low = 0
    moderate = 0
    high = 0
    critical = 0
    for control in records:
        rating = control.get("risk_level", "Critical")
        if rating == "Low":
            low += 1
        elif rating == "Moderate":
            moderate += 1
        elif rating == "High":
            high += 1
        else:
            critical += 1

    return {
        "total": total,
        "low": low,
        "moderate": moderate,
        "high": high,
        "critical": critical,
    }
