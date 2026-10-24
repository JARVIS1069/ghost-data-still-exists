import csv
import json

import pytest

from ghost_audit.identity import IdentityResolver
from ghost_audit.identity.resolver import email_hash, normalize_email, normalize_phone
from ghost_audit.loaders import OUTPUT_COLUMNS, REQUEST_COLUMNS, load_csv, load_requests, validate_schema
from ghost_audit.models import Step
from ghost_audit.planner import order_steps, remediation_before_verification, to_json_steps, validate_step
from ghost_audit.reasoner import heuristic_intent
from ghost_audit.rules import RuleEngine


@pytest.fixture
def resolver():
    ids = [{"user_id": "u1", "name": "Ann Lee", "email": "Ann.Lee@Example.com", "phone": "+1 (555) 010-2000",
            "email_hash": "", "updated_at": ""},
           {"user_id": "u2", "name": "Ann Leigh", "email": "ann.leigh@example.com", "phone": "", "email_hash": "",
            "updated_at": ""}]
    audit = [{"user_id": "u1", "field_name": "email", "old_value": "ann.old@mail.com",
              "new_value": "ann.lee@example.com"}]
    return IdentityResolver(ids, audit)


# ---- identity resolver
def test_normalisers():
    assert normalize_email("  A@B.COM ") == "a@b.com"
    assert normalize_phone("+1 (555) 010-2000") == "15550102000"


def test_resolves_current_and_historical_email(resolver):
    cur = resolver.resolve("ANN.LEE@example.com")
    old = resolver.resolve("ann.old@mail.com")
    assert cur.user_id == old.user_id == "u1"
    assert old.matched_via == "historical_email"
    assert {"ann.old@mail.com", "ann.lee@example.com"} <= cur.emails


def test_hash_derived_and_decoys_not_merged(resolver):
    ident = resolver.resolve("ann.lee@example.com")
    assert email_hash("ann.old@mail.com") in ident.hashes
    assert resolver.owners(emails=["ann.leigh@example.com"]) == {"u2"}
    assert resolver.resolve("nobody@x.com") is None


# ---- rule engine
@pytest.fixture
def rules(tmp_path):
    p = tmp_path / "rules.csv"
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["rule_id", "data_category", "condition", "required_action"])
        w.writerow(["R1", "USER_PROFILE", "always", "Delete"])
        w.writerow(["R2", "SUPPORT_MESSAGE", "always", "Redact personal fields"])
        w.writerow(["R3", "ANALYTICS_PROFILE", "always", "Anonymize"])
        w.writerow(["R4", "BACKUP_ARCHIVE", "legal", "Retain but block restore"])
    return RuleEngine.from_csv(p)


def test_rules_map_to_operations(rules):
    assert rules.rule_for("USER_PROFILE").remediation_op == "DELETE_RECORD"
    assert rules.rule_for("SUPPORT_MESSAGE").verification_op == "VERIFY_RECORD_REDACTED"
    assert rules.rule_for("ANALYTICS_PROFILE").final_state == "ANONYMIZED"
    retain = rules.rule_for("BACKUP_ARCHIVE")
    assert retain.remediation_op is None and retain.blocks_restore
    assert rules.rule_for("UNKNOWN") is None


# ---- planner
def S(phase, op, state, rid, system="x"):
    return Step(phase, system, rid, op, state, "")


def test_planner_orders_phases_and_stops_flows_first():
    steps = [S("VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT", "a1"),
             S("REMEDIATION", "DELETE_RECORD", "ABSENT", "a1"),
             S("REMEDIATION", "DISABLE_DATA_FLOW", "DISABLED", "data_flow_1"),
             S("FINDING", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", "data_flow_1")]
    out = order_steps(steps)
    assert [s.phase for s in out] == ["FINDING", "REMEDIATION", "REMEDIATION", "VERIFICATION"]
    assert out[1].operation == "DISABLE_DATA_FLOW"
    assert remediation_before_verification(out)
    js = to_json_steps(steps)
    assert [s["step_no"] for s in js] == [1, 2, 3, 4]


def test_planner_rejects_illegal_pair_and_dedupes():
    with pytest.raises(ValueError):
        validate_step(S("REMEDIATION", "DELETE_RECORD", "PRESENT", "a"))
    dup = S("FINDING", "REPORT_REMAINING_RECORD", "PRESENT", "a")
    assert len(order_steps([dup, dup])) == 1


# ---- CSV schema validator
def test_validate_schema():
    assert validate_schema(REQUEST_COLUMNS, REQUEST_COLUMNS) == []
    assert validate_schema(["case_id"], REQUEST_COLUMNS) != []
    assert validate_schema(None, REQUEST_COLUMNS) != []


def test_loader_tolerates_missing_file_and_bad_rows(tmp_path):
    rep = load_csv(tmp_path / "nope.csv", REQUEST_COLUMNS)
    assert rep.rows == [] and rep.errors
    p = tmp_path / "r.csv"
    p.write_text(",".join(REQUEST_COLUMNS) + "\ncase_1,a@b.com,t,s,r,a,hello\n,,,,,,\n", encoding="utf-8")
    reqs, _ = load_requests(p)
    assert [r.case_id for r in reqs] == ["case_1"]


def test_output_schema_constant():
    assert OUTPUT_COLUMNS == ["case_id", "deletion_status", "steps_json"]


# ---- intent heuristic
@pytest.mark.parametrize("text,expected", [
    ("Please delete my account", True),
    ("Solicito la eliminación permanente de la cuenta", True),
    ("이 계정의 영구 삭제를 요청합니다", True),
    ("Correct my surname without removing any records", False),
    ("Please keep the account as it is, I want to download my data", False),
])
def test_intent(text, expected):
    assert heuristic_intent(text).is_deletion is expected
