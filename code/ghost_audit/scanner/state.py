"""Point-in-time state resolution for a resource, honouring the audit cutoff."""
from __future__ import annotations

from ..models import Observation

# When several observations disagree at the same instant the riskiest one wins
# (a copy visible in any replica/source means the data still exists there).
RISK = {"ACTIVE": 5, "IDENTIFIABLE": 4, "PRESENT": 3, "REDACTED": 2, "ANONYMIZED": 2,
        "BLOCKED": 1, "DISABLED": 1, "ABSENT": 0}


def eligible(observations: list[Observation], captured: dict[str, str], audit_at: str) -> list[Observation]:
    """Only evidence captured, and facts observed, at or before the audit moment."""
    out = []
    for ob in observations:
        cap = captured.get(ob.evidence_id, ob.observed_at)
        if cap <= audit_at and ob.observed_at <= audit_at:
            out.append(ob)
    return out


def latest_state(observations: list[Observation]) -> Observation | None:
    """Most recent observation; ties on time resolved by risk, then evidence id."""
    if not observations:
        return None
    return sorted(observations, key=lambda o: (o.observed_at, RISK.get(o.state, 0), o.evidence_id))[-1]
