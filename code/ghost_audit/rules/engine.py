"""Rule engine: turns deletion_rules.csv into executable per-category treatments."""
from __future__ import annotations

from dataclasses import dataclass

from ..loaders import RULE_COLUMNS, load_csv

# Treatment -> (remediation operation, verification operation, final state)
TREATMENTS = {
    "DELETE": ("DELETE_RECORD", "VERIFY_RECORD_ABSENT", "ABSENT"),
    "REDACT": ("REDACT_RECORD", "VERIFY_RECORD_REDACTED", "REDACTED"),
    "ANONYMIZE": ("ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    "RETAIN": (None, "VERIFY_RECORD_PRESENT", "PRESENT"),
}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    data_category: str
    condition: str
    action: str  # DELETE | REDACT | ANONYMIZE | RETAIN
    raw_action: str

    @property
    def remediation_op(self) -> str | None:
        return TREATMENTS[self.action][0]

    @property
    def verification_op(self) -> str:
        return TREATMENTS[self.action][1]

    @property
    def final_state(self) -> str:
        return TREATMENTS[self.action][2]

    @property
    def blocks_restore(self) -> bool:
        return "restore" in self.raw_action.lower() or "restore" in self.condition.lower()


def parse_action(text: str) -> str:
    """Map free-text required_action ('Delete', 'Redact ...', 'Retain ...') to a treatment."""
    t = (text or "").strip().upper()
    for key in ("ANONYMIZE", "ANONYMISE", "REDACT", "DELETE", "RETAIN"):
        if t.startswith(key) or key in t.split()[:2]:
            return "ANONYMIZE" if key.startswith("ANONYM") else key
    for key in ("ANONYM", "REDACT", "DELET", "RETAIN"):
        if key in t:
            return {"ANONYM": "ANONYMIZE", "REDACT": "REDACT", "DELET": "DELETE", "RETAIN": "RETAIN"}[key]
    raise ValueError(f"unrecognised required_action: {text!r}")


class RuleEngine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules
        self._by_category = {r.data_category: r for r in rules}

    @classmethod
    def from_csv(cls, path) -> "RuleEngine":
        report = load_csv(path, RULE_COLUMNS)
        rules = []
        for row in report.rows:
            try:
                rules.append(Rule(row["rule_id"], row["data_category"], row["condition"],
                                  parse_action(row["required_action"]), row["required_action"]))
            except ValueError:
                continue
        return cls(rules)

    def rule_for(self, category: str) -> Rule | None:
        return self._by_category.get(category)

    def action_for(self, category: str) -> str | None:
        r = self.rule_for(category)
        return r.action if r else None

    def categories(self) -> list[str]:
        return list(self._by_category)
