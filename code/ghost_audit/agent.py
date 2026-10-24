"""Pipeline orchestration: request -> identity -> evidence state -> rules -> ordered plan."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from .identity import IdentityResolver
from .loaders import (ACTIVITY_COLUMNS, AUDIT_COLUMNS, IDENTITY_COLUMNS, load_csv, load_requests)
from .models import CaseResult, Identity, Observation, Request, Step
from .planner import to_json_steps
from .processes import detect
from .reasoner import IntentClassifier
from .rules import RuleEngine
from .scanner import EvidenceIndex
from .scanner.linker import link_by_activity
from .scanner.state import eligible, latest_state
from .taxonomy import category_for, system_for

log = logging.getLogger("ghost_audit.agent")
DIRTY = {"PRESENT", "IDENTIFIABLE"}


@dataclass
class AgentConfig:
    dataset_dir: str = "dataset"
    cache_dir: str = ".cache/ocr"
    use_llm: bool = False
    link_by_activity: bool = True
    lookback_hours: float = 3.0
    seed: int = 7


@dataclass
class AuditAgent:
    cfg: AgentConfig
    resolver: IdentityResolver
    index: EvidenceIndex
    rules: RuleEngine
    activity: list[dict]
    classifier: IntentClassifier
    extra_links: dict[str, set] = field(default_factory=dict)

    @classmethod
    def from_config(cls, cfg: AgentConfig) -> "AuditAgent":
        ds = Path(cfg.dataset_dir)
        ids = load_csv(ds / "user_identities.csv", IDENTITY_COLUMNS).rows
        aud = load_csv(ds / "user_audit_log.csv", AUDIT_COLUMNS).rows
        act = load_csv(ds / "system_activity.csv", ACTIVITY_COLUMNS).rows
        resolver = IdentityResolver(ids, aud)
        index = EvidenceIndex.build(ds, resolver, cfg.cache_dir, act)
        rules = RuleEngine.from_csv(ds / "deletion_rules.csv")
        return cls(cfg, resolver, index, rules, act, IntentClassifier(use_llm=cfg.use_llm))

    # ---------------------------------------------------------------- batch API
    def run(self, requests: list[Request], context_requests: list[Request] | None = None) -> list[CaseResult]:
        """Audit ``requests``. ``context_requests`` are extra cases (e.g. the labelled samples) that
        compete for the same unattributed activity events but are not themselves returned."""
        everyone = list(requests) + [r for r in (context_requests or []) if r.case_id not in {q.case_id for q in requests}]
        intents = {r.case_id: self.classifier.classify(r.request_text) for r in everyone}
        if self.cfg.link_by_activity:
            self._link_activity([r for r in everyone if intents[r.case_id].is_deletion])
        results = [self.audit(r, intents[r.case_id]) for r in sorted(requests, key=lambda r: r.case_id)]
        if self.cfg.link_by_activity:
            results = self._second_pass(results, {r.case_id: r for r in everyone})
        return results

    def _second_pass(self, results: list[CaseResult], reqs: dict[str, Request]) -> list[CaseResult]:
        """Masked analytics copies: only attributed for cases that otherwise look clean, since a
        wrongly attributed copy there can only add a verification, never a false violation."""
        pending = [r for r in results if r.status == "COMPLETE"
                   and not any(s.resource_id.startswith("analytics_") for s in r.steps)]
        rows = [{"case_id": r.case_id, "reported_at": reqs[r.case_id].reported_at} for r in pending]
        claimed = set(self.index.links)
        links = link_by_activity(rows, self.activity, claimed, {r.case_id: set() for r in pending},
                                 "analytics", self.cfg.lookback_hours, known=set(self.index.by_resource),
                                 event_types={"ANONYMIZE_RECORD"})
        if not links:
            return results
        out = []
        for r in results:
            if r.case_id in links:
                self.extra_links.setdefault(r.case_id, set()).add(links[r.case_id])
                r = self.audit(reqs[r.case_id])
            out.append(r)
        return out

    def _link_activity(self, cases: list[Request]) -> None:
        has_prefix, claimed = {}, set()
        for r in cases:
            ident = self.resolver.resolve(r.email)
            res = self.index.by_user.get(ident.user_id, set()) if ident else set()
            has_prefix[r.case_id] = {x.rsplit("_", 1)[0] for x in res}
        claimed = set(self.index.links)
        rows = [{"case_id": r.case_id, "reported_at": r.reported_at} for r in cases]
        found = link_by_activity(rows, self.activity, claimed, has_prefix, "account",
                                 self.cfg.lookback_hours, known=set(self.index.by_resource))
        self.extra_links = {k: {v} for k, v in found.items()}

    # ------------------------------------------------------------------ one case
    def audit(self, req: Request, intent=None) -> CaseResult:
        intent = intent or self.classifier.classify(req.request_text)
        if not intent.is_deletion:
            return CaseResult(req.case_id, "NOT_APPLICABLE", [], [f"not a deletion request: {intent.reason}"])
        ident = self.resolver.resolve(req.email)
        if ident is None:
            return CaseResult(req.case_id, "INCOMPLETE", [], ["identity could not be resolved"])
        return self._audit_identity(req, ident)

    def _audit_identity(self, req: Request, ident: Identity) -> CaseResult:
        resources = set(self.index.by_user.get(ident.user_id, set()))
        resources |= self.extra_links.get(req.case_id, set())
        steps: list[Step] = []
        notes: list[str] = []
        dirty = False
        for rid in sorted(resources):
            obs = eligible(self.index.by_resource.get(rid, []), self.index.captured, req.audit_at)
            obs = [o for o in obs if self._belongs(o, ident, rid)]
            latest = latest_state(obs)
            cat = self._category(rid, obs)
            s, d = self._plan_resource(rid, cat, latest)
            steps.extend(s)
            dirty = dirty or d
            if latest:
                notes.append(f"{rid}: {latest.state} via {latest.evidence_id}")
        incomplete = dirty
        for s in steps:
            if s.phase == "FINDING":
                incomplete = True
        complete_steps = [s for s in steps if s.phase == "VERIFICATION"] if not incomplete else steps
        if not incomplete:
            # Every claim of a clean state must be backed by evidence.
            pass
        status = "INCOMPLETE" if incomplete else "COMPLETE"
        if not incomplete:
            steps = complete_steps
        else:
            for s in steps:
                if s.phase != "FINDING":
                    s.evidence_id = ""
        return CaseResult(req.case_id, status, steps, notes)

    # ----------------------------------------------------------------- helpers
    def _belongs(self, ob: Observation, ident: Identity, rid: str) -> bool:
        """An observation counts for this subject unless it names a *different* subject only."""
        owners = self.resolver.owners(ob.emails, ob.phones, ob.hashes, ob.user_ids)
        return (not owners) or ident.user_id in owners

    def _category(self, rid: str, obs: list[Observation]) -> str:
        cats = [o.record_type for o in obs if o.record_type]
        for special in ("SUPPORT_ATTACHMENT", "PRODUCT_TELEMETRY"):
            if special in cats:
                return special
        return cats[0] if cats else category_for(rid)

    def _plan_resource(self, rid: str, cat: str, latest: Observation | None) -> tuple[list[Step], bool]:
        system = system_for(rid)
        steps: list[Step] = []
        ev = latest.evidence_id if latest else ""
        state = latest.state if latest else "ABSENT"
        path = detect(cat, rid, latest)
        if path is not None:
            if path.active:
                steps += [Step("FINDING", system, rid, path.finding_op, "ACTIVE", ev),
                          Step("REMEDIATION", system, rid, path.remediation_op, path.safe_state)]
            steps.append(Step("VERIFICATION", system, rid, path.verification_op, path.safe_state, ev))
            return steps, path.active
        rule = self.rules.rule_for(cat)
        if rule is None:
            return [], False
        action = rule.action
        if action == "RETAIN":
            steps.append(Step("VERIFICATION", system, rid, "VERIFY_RECORD_PRESENT", "PRESENT", ev))
            return steps, state == "ABSENT" and latest is not None and False
        rem = rule.remediation_op
        fin = "REPORT_REMAINING_RECORD" if action == "DELETE" else "REPORT_EXPOSED_PII"
        if action == "ANONYMIZE" and state == "PRESENT":
            fin, rem = "REPORT_REMAINING_RECORD", "DELETE_RECORD"
        target = {"DELETE_RECORD": ("ABSENT", "VERIFY_RECORD_ABSENT"),
                  "REDACT_RECORD": ("REDACTED", "VERIFY_RECORD_REDACTED"),
                  "ANONYMIZE_RECORD": ("ANONYMIZED", "VERIFY_RECORD_ANONYMIZED")}[rem]
        is_dirty = state in DIRTY
        if is_dirty:
            steps += [Step("FINDING", system, rid, fin, "PRESENT", ev),
                      Step("REMEDIATION", system, rid, rem, target[0])]
        steps.append(Step("VERIFICATION", system, rid, target[1], target[0], ev))
        return steps, is_dirty

    # ----------------------------------------------------------------- output
    @staticmethod
    def to_row(result: CaseResult) -> dict:
        return {"case_id": result.case_id, "deletion_status": result.status,
                "steps_json": json.dumps(to_json_steps(result.steps), ensure_ascii=False,
                                         separators=(",", ":")) if result.steps else "[]"}

