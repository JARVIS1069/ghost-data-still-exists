"""Detects active processes that can recreate deleted data (sync/import flows, restores)."""
from __future__ import annotations

from dataclasses import dataclass

from ..models import Observation

FLOW, RESTORE = "FLOW", "RESTORE"
KIND_BY_CATEGORY = {"DATA_FLOW": FLOW, "BACKUP_ARCHIVE": RESTORE}
RECREATING_CATEGORIES = set(KIND_BY_CATEGORY)


@dataclass(frozen=True)
class RecreatePath:
    kind: str          # FLOW | RESTORE
    resource_id: str
    active: bool
    evidence_id: str
    finding_op: str
    remediation_op: str
    verification_op: str
    safe_state: str    # DISABLED | BLOCKED


def recreate_kind(category: str) -> str | None:
    return KIND_BY_CATEGORY.get(category)


def detect(category: str, resource_id: str, latest: Observation | None) -> RecreatePath | None:
    """Return the recreate path for a resource, or None if the resource is not a flow/backup."""
    kind = recreate_kind(category)
    if kind is None:
        return None
    active = bool(latest and latest.state == "ACTIVE")
    ev = latest.evidence_id if latest else ""
    if kind == FLOW:
        return RecreatePath(kind, resource_id, active, ev, "REPORT_ACTIVE_DATA_FLOW",
                            "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED", "DISABLED")
    return RecreatePath(kind, resource_id, active, ev, "REPORT_RESTORE_RISK",
                        "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED", "BLOCKED")
