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

RISK_BANDS = ((4, "Low"), (9, "Moderate"), (16, "High"), (25, "Critical"))
DOMAIN_ACTIONS = {
    "Governance": (
        "Assign an accountable executive owner, approve the policy, and record a dated review."
    ),
    "Identify": (
        "Validate asset ownership and scope, then document the highest-impact dependencies."
    ),
    "Protect": (
        "Apply the approved secure baseline, track exceptions, and verify access or evidence."
    ),
    "Detect": ("Test alert coverage safely and record triage ownership and response time."),
    "Respond": ("Exercise the response playbook and capture lessons and dated corrective actions."),
    "Recover": ("Run a controlled restore test and record results against the agreed objectives."),
    "Privacy": (
        "Confirm data purpose, retention, access, and review evidence with the privacy owner."
    ),
}


def inherent_risk_score(control: Mapping[str, Any]) -> int:
    """Return the 1-25 likelihood-by-impact score recorded for this control."""
    return int(control.get("likelihood", 1)) * int(control.get("impact", 1))


def inherent_risk_band(score: int) -> str:
    if not 1 <= score <= 25:
        raise ValueError("Inherent risk score must be from 1 to 25.")
    return next(band for upper_bound, band in RISK_BANDS if score <= upper_bound)


def suggested_next_step(control: Mapping[str, Any]) -> str:
    """Provide a deterministic, human-reviewed next-step suggestion by control domain."""
    domain = str(control.get("domain", ""))
    suggestion = DOMAIN_ACTIONS.get(
        domain,
        "Confirm the control owner, capture a dated remediation action, and validate evidence.",
    )
    if control.get("status") == "Implemented" and int(control.get("status_score", 0)) >= 80:
        return "Schedule the next effectiveness test and record its result and reviewer."
    if control.get("risk_level") == "Critical" or inherent_risk_band(
        inherent_risk_score(control)
    ) in ("High", "Critical"):
        return f"Prioritize immediate owner review. {suggestion}"
    return suggestion


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
                "likelihood": control.get("likelihood", 1),
                "impact": control.get("impact", 1),
                "inherent_risk_score": inherent_risk_score(control),
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
