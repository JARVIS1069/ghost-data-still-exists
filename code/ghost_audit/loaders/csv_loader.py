"""Tolerant, schema-validated CSV loaders (never crash on malformed rows)."""
from __future__ import annotations

import csv
import logging
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Request

log = logging.getLogger("ghost_audit.loaders")

REQUEST_COLUMNS = ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"]
IDENTITY_COLUMNS = ["user_id", "name", "email", "phone", "email_hash", "updated_at"]
AUDIT_COLUMNS = ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"]
ACTIVITY_COLUMNS = [
    "activity_id", "event_time", "event_type", "source_system", "target_system",
    "resource_id", "reported_result", "details",
]
RULE_COLUMNS = ["rule_id", "data_category", "condition", "required_action"]
EVIDENCE_COLUMNS = ["file_id", "file_path", "origin", "captured_at"]
OUTPUT_COLUMNS = ["case_id", "deletion_status", "steps_json"]


@dataclass
class LoadReport:
    path: str
    rows: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    missing_columns: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.missing_columns


def validate_schema(header: list[str] | None, required: list[str]) -> list[str]:
    """Return required columns that are absent from ``header``."""
    present = {h.strip() for h in (header or [])}
    return [c for c in required if c not in present]


def load_csv(path: str | Path, required: list[str]) -> LoadReport:
    """Load a CSV. A missing file or missing columns yields an empty, flagged report."""
    path = Path(path)
    report = LoadReport(path=str(path))
    if not path.exists():
        report.errors.append(f"file not found: {path}")
        report.missing_columns = list(required)
        log.warning("missing file %s", path)
        return report
    try:
        with path.open(newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            report.missing_columns = validate_schema(reader.fieldnames, required)
            if report.missing_columns:
                report.errors.append(f"missing columns: {report.missing_columns}")
                return report
            for lineno, row in enumerate(reader, start=2):
                if None in row:  # more cells than header columns
                    report.errors.append(f"line {lineno}: too many fields")
                    row.pop(None, None)
                clean = {k.strip(): (v or "").strip() if isinstance(v, str) or v is None else v for k, v in row.items() if k}
                if not any(clean.values()):
                    continue
                report.rows.append(clean)
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        report.errors.append(f"unreadable: {exc}")
        log.error("cannot read %s: %s", path, exc)
    return report


def load_requests(path: str | Path) -> tuple[list[Request], list[str]]:
    """Load deletion requests; rows without a case_id are skipped and reported."""
    report = load_csv(path, REQUEST_COLUMNS)
    requests: list[Request] = []
    errors = list(report.errors)
    seen: set[str] = set()
    for i, row in enumerate(report.rows, start=1):
        if not row.get("case_id"):
            errors.append(f"row {i}: empty case_id skipped")
            continue
        if row["case_id"] in seen:
            errors.append(f"row {i}: duplicate case_id {row['case_id']} skipped")
            continue
        seen.add(row["case_id"])
        requests.append(Request(**{c: row.get(c, "") for c in REQUEST_COLUMNS}))
    return requests, errors
