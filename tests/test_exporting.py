from __future__ import annotations

import csv
import io

from src.grc_dashboard.data import CONTROL_DATA
from src.grc_dashboard.exporting import controls_csv


def test_csv_export_neutralizes_spreadsheet_formulas() -> None:
    record = dict(CONTROL_DATA[0])
    record["control"] = '=HYPERLINK("https://attacker.invalid","open")'
    record["owner"] = "  @SUM(1,2)"

    rows = list(csv.DictReader(io.StringIO(controls_csv([record]).decode("utf-8"))))

    assert rows[0]["control"].startswith("'=")
    assert rows[0]["owner"].startswith("'  @")
    assert rows[0]["id"] == record["id"]
