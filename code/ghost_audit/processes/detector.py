"""Detects active processes that can recreate deleted data (sync/import flows, restores)."""
from __future__ import annotations

from ..models import Observation

RECREATING_CATEGORIES = {"DATA_FLOW", "BACKUP_ARCHIVE"}


def recreate_kind(obs: Observation) -> str | None:
    """Return 'FLOW' or 'RESTORE' when the observation is a recreate-path candidate."""
    if obs.record_type == "DATA_FLOW":
        return "FLOW"
    if obs.record_type == "BACKUP_ARCHIVE":
        return "RESTORE"
    return None


def is_active(obs: Observation) -> bool:
    kind = recreate_kind(obs)
    return kind is not None and obs.state == "ACTIVE"
