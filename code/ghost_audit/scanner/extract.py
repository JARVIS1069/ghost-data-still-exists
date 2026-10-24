"""Evidence extraction: turns every evidence format into normalised Observations.

Supported: SQLite-compatible .sql dumps (executed in memory), JSON (generic walker),
pipe-delimited handover text, structured/unstructured logs (joined by trace id),
PDF text (pypdf) and image text (OCR, cached). No file name or case id is special-cased.
"""
from __future__ import annotations

import json
import logging
import re
import sqlite3
from pathlib import Path

from ..identity import EMAIL_RE, USER_RE, normalize_email, normalize_phone, normalize_name
from ..models import Observation
from ..taxonomy import RESOURCE_RE, category_for, system_for

log = logging.getLogger("ghost_audit.scanner")

NAME_KEYS = {"name", "full_name", "display_name", "requester_name", "customer_name"}
SKIP_KEY_PARTS = ("seal", "integrity", "checksum")
RESULT_STATE = {
    "FOUND": "PRESENT", "NOT_FOUND": "ABSENT", "IDENTIFIABLE": "IDENTIFIABLE",
    "ANONYMIZED": "ANONYMIZED", "ANONYMISED": "ANONYMIZED", "REDACTED": "REDACTED",
    "ACTIVE": "ACTIVE", "BLOCKED": "BLOCKED", "DISABLED": "DISABLED", "PRESENT": "PRESENT",
    "ABSENT": "ABSENT",
}
TRUE = {"true", "1", "yes", "y"}
FALSE = {"false", "0", "no", "n"}


# ----------------------------------------------------------------- identifiers
def _is_true(v) -> bool | None:
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in TRUE:
        return True
    if s in FALSE:
        return False
    return None


def identifiers(rec: dict) -> dict[str, frozenset]:
    """Pull emails/phones/hashes/user_ids/names out of any flat or nested mapping."""
    emails, phones, hashes, users, names = set(), set(), set(), set(), set()

    def visit(key: str, val):
        k = key.lower()
        if isinstance(val, dict):
            for kk, vv in val.items():
                visit(kk, vv)
            return
        if isinstance(val, list):
            for vv in val:
                visit(key, vv)
            return
        if val is None or any(p in k for p in SKIP_KEY_PARTS):
            return
        s = str(val).strip()
        if not s or s.lower() in {"null", "none"}:
            return
        emails.update(normalize_email(e) for e in EMAIL_RE.findall(s))
        users.update(USER_RE.findall(s.lower()))
        if "hash" in k and re.fullmatch(r"[0-9a-fA-F]{64}", s):
            hashes.add(s.lower())
        if "phone" in k:
            digits = normalize_phone(s)
            if len(digits) >= 7:
                phones.add(digits)
        if k in NAME_KEYS and re.search(r"[A-Za-z]", s):
            names.add(normalize_name(s))

    for k, v in rec.items():
        visit(str(k), v)
    return {
        "emails": frozenset(emails), "phones": frozenset(phones), "hashes": frozenset(hashes),
        "user_ids": frozenset(users), "names": frozenset(names),
    }


def has_direct_pii(ids: dict[str, frozenset]) -> bool:
    return bool(ids["emails"] or ids["phones"] or ids["hashes"] or ids["names"])


def _obs(evidence_id, when, rid, state, rec, hint="", channel="", note="") -> Observation:
    ids = identifiers(rec)
    return Observation(
        evidence_id=evidence_id, observed_at=when, system_id=system_for(rid), resource_id=rid,
        state=state, emails=ids["emails"], phones=ids["phones"], hashes=ids["hashes"],
        user_ids=ids["user_ids"], names=ids["names"], record_type=category_for(rid, hint),
        channel=channel, note=note,
    )


# ------------------------------------------------------------------ state rules
def record_state(rid: str, rec: dict, hint: str = "") -> str:
    """Normalised state of a structured record (snapshot row, export entry, listing row)."""
    result = str(rec.get("result", "")).strip().upper()
    if result in RESULT_STATE:
        return RESULT_STATE[result]
    cat = category_for(rid, hint)
    ids = identifiers({k: v for k, v in rec.items() if k not in ("resource_id", "resource")})
    pii = has_direct_pii(ids)
    sc = rec.get("status_code")
    if sc is not None and str(sc) == "404":
        return "ABSENT"
    if "profile" in rec and rec.get("profile") is None and sc is not None:
        return "ABSENT"
    status = str(rec.get("account_status", "")).upper()
    if cat == "USER_PROFILE":
        return "ABSENT" if status in {"DELETED", "CLOSED", "PURGED"} else "PRESENT"
    if cat in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        return "IDENTIFIABLE" if (pii or ids["user_ids"]) else "ANONYMIZED"
    if cat in {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG"}:
        return "IDENTIFIABLE" if pii else "REDACTED"
    if cat == "ACCOUNT_TOMBSTONE":
        return "IDENTIFIABLE" if pii else "REDACTED"
    if cat == "DATA_FLOW":
        for k in ("enabled", "active", "is_enabled"):
            if k in rec:
                v = _is_true(rec[k])
                return "ACTIVE" if v else "DISABLED"
        return "ACTIVE"
    if cat == "BACKUP_ARCHIVE":
        for k in ("restore_allowed", "restorable", "eligible"):
            if k in rec:
                return "ACTIVE" if _is_true(rec[k]) else "BLOCKED"
        return "ACTIVE"
    if cat == "USER_EXPORT":
        for k in ("download_available", "available"):
            if k in rec:
                return "PRESENT" if _is_true(rec[k]) else "ABSENT"
    return "PRESENT"


# ------------------------------------------------------------------------ JSON
def parse_json(evidence_id: str, captured_at: str, data) -> list[Observation]:
    out: list[Observation] = []

    def walk(node, ctx):
        if isinstance(node, dict):
            when = (node.get("recorded_at") or node.get("observed_at") or node.get("captured_at")
                    or ctx.get("when") or captured_at)
            rid = node.get("resource_id") or node.get("resource")
            hint = " ".join(str(x) for x in (ctx.get("hint", ""), node.get("record_type", ""),
                                             node.get("collection", "")) if x)
            if isinstance(rid, str) and RESOURCE_RE.fullmatch(rid):
                rec = dict(node)
                if ctx.get("flow_hint") and "enabled" not in rec:
                    pass
                out.append(_obs(evidence_id, when, rid, record_state(rid, rec, hint), rec, hint,
                                channel=ctx.get("channel", "")))
                return
            ctx2 = dict(ctx)
            if node.get("captured_at"):
                ctx2["when"] = node["captured_at"]
            for key in ("data_store", "collection"):
                if isinstance(node.get(key), str):
                    ctx2["hint"] = (ctx2.get("hint", "") + " " + node[key]).strip()
                    ctx2["channel"] = node[key]
            for k, v in node.items():
                if isinstance(v, (dict, list)):
                    c3 = dict(ctx2)
                    c3["hint"] = (c3.get("hint", "") + " " + str(k)).strip()
                    walk(v, c3)
        elif isinstance(node, list):
            for it in node:
                walk(it, ctx)

    walk(data, {})
    return out


# ------------------------------------------------------------------------- SQL
def parse_sql(evidence_id: str, captured_at: str, text: str) -> list[Observation]:
    out: list[Observation] = []
    m = re.search(r"Captured at:\s*(\S+)", text)
    header_when = m.group(1) if m else captured_at
    con = sqlite3.connect(":memory:")
    try:
        con.executescript(text)
    except sqlite3.Error as exc:
        log.warning("%s: sql execution failed (%s); retrying statement-wise", evidence_id, exc)
        con.close()
        con = sqlite3.connect(":memory:")
        for stmt in re.split(r";\s*\n", text):
            try:
                con.execute(stmt)
            except sqlite3.Error:
                continue
    con.row_factory = sqlite3.Row
    tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
    scope = {}
    if "snapshot_scope" in tables:
        scope = {r["origin_system"]: r["captured_at"] for r in con.execute("select * from snapshot_scope")}
    for t in tables:
        if t == "snapshot_scope":
            continue
        for row in con.execute(f'select * from "{t}"'):
            rec = dict(row)
            if rec.get("record_json"):
                try:
                    rec.update(json.loads(rec.pop("record_json")))
                except (ValueError, TypeError):
                    pass
            rid = rec.get("resource_id")
            if not isinstance(rid, str) or not RESOURCE_RE.fullmatch(rid):
                continue
            origin = rec.get("origin_system") or system_for(rid)
            when = scope.get(origin) or scope.get(system_for(rid)) or header_when
            hint = " ".join(str(x) for x in (t, rec.get("collection_name", ""), rec.get("record_type", "")))
            out.append(_obs(evidence_id, when, rid, record_state(rid, rec, hint), rec, hint, channel=t))
    con.close()
    return out


# ------------------------------------------------------------------ text lists
LISTING_RE = re.compile(
    r"^\s*[-*]?\s*(\d{4}-\d\d-\d\dT[\d:]+Z)\s*\|\s*(\w+)\s*\|\s*(\w+)\s*\|\s*(\w+)\s*\|\s*(\w+)\s*\|\s*(\S+)\s*$"
)


def parse_listing_text(evidence_id: str, captured_at: str, text: str) -> list[Observation]:
    out = []
    for line in text.splitlines():
        m = LISTING_RE.match(line)
        if not m:
            continue
        when, _system, rid, rtype, result, subject = m.groups()
        if not RESOURCE_RE.fullmatch(rid):
            continue
        rec = {"result": result, "subject_reference": subject}
        out.append(_obs(evidence_id, when, rid, record_state(rid, rec, rtype), rec, rtype))
    return out


# ------------------------------------------------------------------------ logs
TS_RE = re.compile(r"^(\d{4}-\d\d-\d\dT[\d:]+Z)\s+(.*)$")
KV_RE = re.compile(r'([A-Za-z_][\w]*)=("(?:[^"\\]|\\.)*"|\S+)')
IDENT_KEYS = ("lookup_key", "match_key", "correlation_key", "subject_key", "scan_key", "owner_key",
              "subject_ref")


def _kv(body: str) -> dict:
    out = {}
    for k, v in KV_RE.findall(body):
        v = v.strip()
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        out[k] = v
    return out


def parse_log_line(line: str) -> tuple[str, dict] | None:
    m = TS_RE.match(line.strip())
    if not m:
        return None
    ts, rest = m.groups()
    kv: dict = {}
    if rest.startswith("{"):
        try:
            kv = {k: v for k, v in json.loads(rest).items()}
        except ValueError:
            return None
    elif rest.startswith("["):
        m2 = re.match(r"\[(\w+)\]\s+\[(\w+)\]\s+\[([\w-]+)\]\s+(\w+):\s*(.*)", rest)
        if not m2:
            return None
        kv = {"service": m2.group(2), "trace_id": m2.group(3), "event": m2.group(4)}
        kv.update(_kv(m2.group(5).replace('\\"', '"')))
    elif ' | ' in rest:
        parts = rest.split(" | ", 5)
        if len(parts) < 6:
            return None
        kv = {"service": parts[2], "trace_id": parts[3], "event": parts[4]}
        kv.update(_kv(parts[5]))
    elif rest.startswith("<"):
        m2 = re.match(r"<\d+>1\s+\S+\s+(\w+)\s+([\w-]+)\s+-\s+-\s+(.*)", rest)
        if not m2:
            return None
        kv = {"service": m2.group(1), "trace_id": m2.group(2)}
        kv.update(_kv(m2.group(3)))
    else:
        if 'message="' in rest:
            pre, _, msg = rest.partition('message="')
            kv.update(_kv(pre))
            kv["trace_id"] = kv.get("requestId", "")
            kv["service"] = kv.get("function", kv.get("service", ""))
            kv.update(_kv(msg.rstrip().rstrip('"').replace('\\"', '"')))
        else:
            kv.update(_kv(rest))
    return ts, {str(k): v for k, v in kv.items()}


def _log_event_state(event: str, kv: dict, rid: str) -> str | None:
    e = event.lower()
    if e in {"profile_lookup_completed", "contact_query_completed"}:
        if str(kv.get("http_status", "")) == "404" or str(kv.get("rows", "")) == "0":
            return "ABSENT"
        return "PRESENT"
    if e == "index_query_completed":
        return "PRESENT" if str(kv.get("result", "")).lower() == "hit" else "ABSENT"
    if e.endswith("_pii_scan") or e == "analytics_identity_scan":
        return "IDENTIFIABLE"
    if e.startswith("connector_config") or e == "connector_heartbeat":
        if "enabled" in kv:
            return "ACTIVE" if _is_true(kv["enabled"]) else "DISABLED"
        return None
    if e == "restore_candidate_evaluated":
        elig, block = _is_true(kv.get("eligible")), _is_true(kv.get("deletion_block"))
        return "ACTIVE" if elig and not block else "BLOCKED"
    if e == "restore_authorization_completed":
        return "BLOCKED" if str(kv.get("decision", "")).lower() == "deny" else "ACTIVE"
    if e == "restore_policy_read_completed":
        return "ACTIVE" if _is_true(kv.get("restore_allowed")) else "BLOCKED"
    if e in {"export_metadata_read_completed", "export_download_check_completed"}:
        return "PRESENT" if _is_true(kv.get("available")) else "ABSENT"
    if e in {"support_ticket_read_completed", "analytics_profile_read_completed",
             "notification_read_completed"}:
        return record_state(rid, {k: v for k, v in kv.items() if k not in {"resource_id"}})
    if e == "audit_record_read_completed":
        return "PRESENT"
    if e == "deletion_marker_check":
        return "ABSENT" if _is_true(kv.get("marker_found")) else "IDENTIFIABLE"
    if e == "record_lookup":
        return RESULT_STATE.get(str(kv.get("result", "")).upper())
    return None


def parse_log(evidence_id: str, captured_at: str, text: str) -> list[Observation]:
    traces: dict[str, list[tuple[str, dict]]] = {}
    standalone: list[tuple[str, dict]] = []
    for line in text.splitlines():
        parsed = parse_log_line(line)
        if not parsed:
            continue
        ts, kv = parsed
        tid = kv.get("trace_id")
        if kv.get("event") == "record_lookup" or not tid:
            standalone.append((ts, kv))
        else:
            traces.setdefault(tid, []).append((ts, kv))
    out: list[Observation] = []
    for ts, kv in standalone:
        rid = kv.get("resource_id", "")
        if RESOURCE_RE.fullmatch(rid):
            st = _log_event_state(kv.get("event", ""), kv, rid) or "PRESENT"
            hint = kv.get("record_type", "")
            rec = {k: v for k, v in kv.items() if k not in {"seq"}}
            out.append(_obs(evidence_id, ts, rid, st, rec, hint, channel=kv.get("event", "")))
    for tid, events in traces.items():
        merged: dict = {}
        for _, kv in events:
            merged.update({k: v for k, v in kv.items() if v not in ("", None)})
        rid = merged.get("resource_id", "")
        if not RESOURCE_RE.fullmatch(rid):
            continue
        state = None
        for ts, kv in events:
            s = _log_event_state(kv.get("event", ""), {**merged, **kv}, rid)
            if s:
                state, when = s, ts
        if state is None:
            continue
        rec = dict(merged)
        for k in IDENT_KEYS:
            if k in rec:
                rec[k] = rec[k]
        hint = merged.get("file", "") + " " + merged.get("event", "") if "attachment" in " ".join(
            str(kv.get("event", "")) for _, kv in events) else ""
        out.append(_obs(evidence_id, when, rid, state, rec, hint, channel=merged.get("event", "")))
    return out


# --------------------------------------------------------------------- media
def parse_plain_text(evidence_id: str, captured_at: str, text: str) -> list[Observation]:
    """Line/block based extraction for PDF and OCR text: a resource id plus nearby identifiers."""
    out = []
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for i, line in enumerate(lines):
        for m in RESOURCE_RE.finditer(line):
            rid = m.group(0)
            window = " ".join(lines[max(0, i - 1): i + 2]) if not EMAIL_RE.search(line) else line
            rec = {"text": window}
            low = window.lower()
            st = "PRESENT"
            for word, s in (("not found", "ABSENT"), ("not_found", "ABSENT"), ("deleted", "ABSENT"),
                            ("anonymized", "ANONYMIZED"), ("redacted", "REDACTED"),
                            ("identifiable", "IDENTIFIABLE"), ("disabled", "DISABLED"),
                            ("blocked", "BLOCKED"), ("active", "ACTIVE")):
                if word in low:
                    st = s
                    break
            out.append(_obs(evidence_id, captured_at, rid, st, rec, window, channel="text"))
    return out


def extract_text(path: Path, cache_dir: Path | None = None) -> str:
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        try:
            from pypdf import PdfReader
            return "\n".join((p.extract_text() or "") for p in PdfReader(str(path)).pages)
        except Exception as exc:  # noqa: BLE001 - corrupt media must never crash the run
            log.warning("pdf extraction failed for %s: %s", path.name, exc)
            return ""
    if suffix in {".png", ".jpg", ".jpeg"}:
        cache = (cache_dir / f"{path.stem}.txt") if cache_dir else None
        if cache and cache.exists():
            return cache.read_text(encoding="utf-8")
        try:
            from rapidocr_onnxruntime import RapidOCR
            res, _ = RapidOCR()(str(path))
            text = "\n".join(r[1] for r in (res or []))
        except Exception as exc:  # noqa: BLE001
            log.warning("ocr unavailable/failed for %s: %s", path.name, exc)
            return ""
        if cache:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(text, encoding="utf-8")
        return text
    return ""


def parse_file(evidence_id: str, path: Path, captured_at: str, cache_dir: Path | None = None) -> list[Observation]:
    """Dispatch on extension; any failure is logged and yields no observations."""
    try:
        suffix = path.suffix.lower()
        if suffix == ".json":
            return parse_json(evidence_id, captured_at, json.loads(path.read_text(encoding="utf-8")))
        if suffix == ".sql":
            return parse_sql(evidence_id, captured_at, path.read_text(encoding="utf-8"))
        if suffix == ".log":
            return parse_log(evidence_id, captured_at, path.read_text(encoding="utf-8"))
        if suffix == ".txt":
            return parse_listing_text(evidence_id, captured_at, path.read_text(encoding="utf-8"))
        if suffix in {".pdf", ".png", ".jpg", ".jpeg"}:
            return parse_plain_text(evidence_id, captured_at, extract_text(path, cache_dir))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        log.warning("failed to parse %s: %s", path, exc)
    return []
