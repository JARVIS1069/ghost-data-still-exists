"""Ordered remediation planner.

Output order is fixed by the contract: FINDING -> REMEDIATION -> VERIFICATION, and inside each
phase by (operation order from the allowed-operations table, system_id, resource_id). That order
already encodes the dependency logic: recreating paths (DISABLE_DATA_FLOW, BLOCK_RESTORE) precede
any DELETE/REDACT/ANONYMIZE so nothing can re-create data mid-cleanup.
"""
from __future__ import annotations

from ..models import OPERATION_ORDER, OPERATIONS, PHASES, Step


def validate_step(step: Step) -> None:
    allowed = OPERATIONS.get(step.phase, {})
    if allowed.get(step.operation) != step.state:
        raise ValueError(f"illegal operation/state: {step.phase} {step.operation} {step.state}")


def order_steps(steps: list[Step]) -> list[Step]:
    """Sort into contract order and drop exact duplicates."""
    seen, unique = set(), []
    for s in steps:
        key = (s.phase, s.system_id, s.resource_id, s.operation)
        if key not in seen:
            seen.add(key)
            unique.append(s)
    return sorted(
        unique,
        key=lambda s: (PHASES.index(s.phase), OPERATION_ORDER[s.operation], s.system_id, s.resource_id),
    )


def to_json_steps(steps: list[Step]) -> list[dict]:
    ordered = order_steps(steps)
    for s in ordered:
        validate_step(s)
    return [s.to_json(i) for i, s in enumerate(ordered, start=1)]


def remediation_before_verification(steps: list[Step]) -> bool:
    """Invariant used by tests: phases never interleave and flows are disabled before deletions."""
    phases = [PHASES.index(s.phase) for s in steps]
    if phases != sorted(phases):
        return False
    rem = [s.operation for s in steps if s.phase == "REMEDIATION"]
    stop = [i for i, o in enumerate(rem) if o in {"DISABLE_DATA_FLOW", "BLOCK_RESTORE"}]
    change = [i for i, o in enumerate(rem) if o in {"DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"}]
    return not stop or not change or max(stop) < min(change)
