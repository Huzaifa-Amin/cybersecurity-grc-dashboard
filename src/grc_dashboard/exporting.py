from __future__ import annotations

import csv
import io
from collections.abc import Mapping, Sequence
from typing import Any

import pandas as pd

CONTROL_EXPORT_FIELDS = (
    "id",
    "control",
    "domain",
    "framework",
    "owner",
    "status",
    "status_score",
    "likelihood",
    "impact",
    "risk_level",
    "due_date",
    "evidence",
)
FORMULA_PREFIXES = ("=", "+", "-", "@")


def control_frame(items: Sequence[Mapping[str, Any]]) -> pd.DataFrame:
    return pd.DataFrame(
        [{field: item[field] for field in CONTROL_EXPORT_FIELDS} for item in items],
        columns=CONTROL_EXPORT_FIELDS,
    )


def _spreadsheet_safe(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    if value.lstrip(" \t\r\n").startswith(FORMULA_PREFIXES):
        return "'" + value
    return value


def controls_csv(items: Sequence[Mapping[str, Any]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CONTROL_EXPORT_FIELDS)
    writer.writeheader()
    for item in items:
        writer.writerow({field: _spreadsheet_safe(item[field]) for field in CONTROL_EXPORT_FIELDS})
    return output.getvalue().encode("utf-8")
