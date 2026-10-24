"""Links evidence-less activity events to cases (account deletions masked in evidence).

Evidence often lists a deleted account only as ``404`` with no identifier, and the activity
stream carries resource ids but no user. Within the activity stream a worker finishes a
subject's account deletion shortly before that case's ``reported_at`` timestamp, and cases that
share a ``reported_at`` are processed in case order. We therefore align, per (reported_at,
resource prefix) cluster, the cases that still lack such a resource with the unclaimed
deletion events inside the look-back window, in order. Evidence-backed links always win.
"""
from __future__ import annotations

import datetime as dt
from collections import defaultdict

ACTION_EVENTS = {"DELETE_RECORD"}


def _p(ts: str) -> dt.datetime:
    return dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")


def _case_no(case_id: str) -> tuple:
    digits = "".join(ch for ch in case_id if ch.isdigit())
    return (int(digits) if digits else 0, case_id)


def link_by_activity(cases: list[dict], activity_rows: list[dict], claimed: set[str],
                     has_prefix: dict[str, set[str]], prefix: str = "account",
                     lookback_h: float = 3.0, lookahead_h: float = 0.25,
                     known: set[str] | None = None) -> dict[str, str]:
    """Return {case_id: resource_id}. ``cases`` rows need case_id/reported_at; ``known`` are resources
    seen in evidence (preferred over resources that never appear anywhere)."""
    known = known or set()
    clusters: dict[str, list[dict]] = defaultdict(list)
    for c in cases:
        if prefix not in has_prefix.get(c["case_id"], set()) and c.get("reported_at"):
            clusters[c["reported_at"]].append(c)
    events = [a for a in activity_rows
              if a.get("event_type") in ACTION_EVENTS and a.get("resource_id", "").startswith(prefix + "_")]
    used = set(claimed)
    out: dict[str, str] = {}
    for rep in sorted(clusters):
        try:
            rep_t = _p(rep)
        except ValueError:
            continue
        cs = sorted(clusters[rep], key=lambda c: _case_no(c["case_id"]))
        cand = []
        for a in events:
            if a["resource_id"] in used:
                continue
            try:
                gap = (rep_t - _p(a["event_time"])).total_seconds() / 3600
            except ValueError:
                continue
            if -lookahead_h <= gap <= lookback_h:
                cand.append((a["event_time"], a["resource_id"]))
        cand.sort()
        seen = [x for x in cand if x[1] in known]
        unseen = [x for x in cand if x[1] not in known]
        pool = seen if len(seen) >= len(cs) else seen + unseen
        for case, (_, rid) in zip(cs, pool):
            out[case["case_id"]] = rid
            used.add(rid)
    return out
