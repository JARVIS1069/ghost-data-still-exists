"""Core typed data structures shared by every pipeline stage."""
from __future__ import annotations

from dataclasses import dataclass, field

# Allowed output vocabulary (problem_statement.md "Allowed Operations").
PHASES = ("FINDING", "REMEDIATION", "VERIFICATION")
OPERATIONS = {
    "FINDING": {
        "REPORT_REMAINING_RECORD": "PRESENT",
        "REPORT_EXPOSED_PII": "PRESENT",
        "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
        "REPORT_RESTORE_RISK": "ACTIVE",
    },
    "REMEDIATION": {
        "DISABLE_DATA_FLOW": "DISABLED",
        "BLOCK_RESTORE": "BLOCKED",
        "DELETE_RECORD": "ABSENT",
        "REDACT_RECORD": "REDACTED",
        "ANONYMIZE_RECORD": "ANONYMIZED",
    },
    "VERIFICATION": {
        "VERIFY_RECORD_ABSENT": "ABSENT",
        "VERIFY_RECORD_PRESENT": "PRESENT",
        "VERIFY_RECORD_REDACTED": "REDACTED",
        "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
        "VERIFY_RESTORE_BLOCKED": "BLOCKED",
    },
}
# Canonical operation order across phases (the order of the problem-statement table).
OPERATION_ORDER = {
    op: i for i, op in enumerate([o for phase in PHASES for o in OPERATIONS[phase]])
}
STATUSES = ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")


@dataclass(frozen=True)
class Request:
    case_id: str
    email: str
    requested_at: str
    reported_status: str
    reported_at: str
    audit_at: str
    request_text: str


@dataclass
class Identity:
    """A resolved subject with every current and historical identifier."""

    user_id: str
    name: str = ""
    emails: set[str] = field(default_factory=set)
    phones: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)
    current_email: str = ""
    matched_via: str = ""  # "current_email" | "historical_email"
    history: list[dict] = field(default_factory=list)


@dataclass
class Observation:
    """One fact extracted from an evidence file.

    ``state`` is the normalised condition of the record at ``observed_at``:
    PRESENT / ABSENT / IDENTIFIABLE / ANONYMIZED / REDACTED / ACTIVE / DISABLED / BLOCKED.
    """

    evidence_id: str
    observed_at: str
    system_id: str
    resource_id: str
    state: str
    emails: frozenset[str] = frozenset()
    phones: frozenset[str] = frozenset()
    hashes: frozenset[str] = frozenset()
    user_ids: frozenset[str] = frozenset()
    names: frozenset[str] = frozenset()
    record_type: str = ""
    channel: str = ""  # sub-source such as a replica table or log event name
    note: str = ""

    def has_identifiers(self) -> bool:
        return bool(self.emails or self.phones or self.hashes or self.user_ids or self.names)


@dataclass
class Step:
    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str = ""

    def to_json(self, step_no: int) -> dict:
        return {
            "step_no": step_no,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }


@dataclass
class CaseResult:
    case_id: str
    status: str
    steps: list[Step]
    notes: list[str] = field(default_factory=list)
