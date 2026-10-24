"""Identity resolution: current + historical identifiers for a request subject."""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from ..models import Identity

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
HASH_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
USER_RE = re.compile(r"\buser_\d+\b")


def normalize_email(value: str) -> str:
    return (value or "").strip().lower()


def normalize_phone(value: str) -> str:
    """Digits only, so '+1 (202) 555-0103' == '12025550103'."""
    return re.sub(r"\D", "", value or "")


def normalize_name(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def email_hash(email: str) -> str:
    return hashlib.sha256(normalize_email(email).encode("utf-8")).hexdigest()


class IdentityResolver:
    """Indexes the identity snapshot and the audit log.

    Resolution order: exact current email, then any historical email, so a request
    that quotes an old address still resolves to the same stable ``user_id``.
    """

    def __init__(self, identities: list[dict], audit_log: list[dict]):
        self._by_user: dict[str, dict] = {}
        self._by_email: dict[str, str] = {}
        self._hist_email: dict[str, str] = {}
        self._history: dict[str, list[dict]] = defaultdict(list)
        for row in identities:
            uid = row.get("user_id", "")
            if not uid:
                continue
            self._by_user[uid] = row
            if row.get("email"):
                self._by_email[normalize_email(row["email"])] = uid
        for row in audit_log:
            uid = row.get("user_id", "")
            if not uid:
                continue
            self._history[uid].append(row)
            if row.get("field_name") == "email":
                for key in ("old_value", "new_value"):
                    if row.get(key):
                        self._hist_email.setdefault(normalize_email(row[key]), uid)

    def resolve(self, email: str) -> Identity | None:
        norm = normalize_email(email)
        via = ""
        uid = self._by_email.get(norm)
        if uid:
            via = "current_email"
        else:
            uid = self._hist_email.get(norm)
            via = "historical_email" if uid else ""
        if not uid:
            return None
        return self.for_user(uid, via)

    def for_user(self, user_id: str, via: str = "") -> Identity:
        row = self._by_user.get(user_id, {})
        ident = Identity(user_id=user_id, name=row.get("name", ""), matched_via=via)
        ident.current_email = normalize_email(row.get("email", ""))
        if row.get("email"):
            ident.emails.add(normalize_email(row["email"]))
        if row.get("phone"):
            ident.phones.add(normalize_phone(row["phone"]))
        if row.get("email_hash"):
            ident.hashes.add(row["email_hash"].lower())
        if row.get("name"):
            ident.names.add(normalize_name(row["name"]))
        for ev in self._history.get(user_id, []):
            ident.history.append(ev)
            field = ev.get("field_name")
            for key in ("old_value", "new_value"):
                val = ev.get(key, "")
                if not val:
                    continue
                if field == "email":
                    ident.emails.add(normalize_email(val))
                elif field == "phone":
                    ident.phones.add(normalize_phone(val))
                elif field == "email_hash":
                    ident.hashes.add(val.lower())
                elif field == "name":
                    ident.names.add(normalize_name(val))
        # Derived hashes cover historical addresses whose hash was never logged.
        ident.hashes.update(email_hash(e) for e in list(ident.emails))
        return ident

    def stable_ids(self) -> set[str]:
        return set(self._by_user)

    def _build_owner_index(self) -> None:
        idx: dict[str, set[str]] = defaultdict(set)
        for uid in self._by_user:
            ident = self.for_user(uid)
            for v in ident.emails | ident.hashes | ident.phones:
                idx[v].add(uid)
            idx[uid].add(uid)
        self._owner_idx = idx

    def owners(self, emails=(), phones=(), hashes=(), user_ids=()) -> set[str]:
        """Users that own any of the given identifiers (current or historical)."""
        if not hasattr(self, "_owner_idx"):
            self._build_owner_index()
        found: set[str] = set()
        for e in emails:
            found |= self._owner_idx.get(normalize_email(e), set())
        for p in phones:
            found |= self._owner_idx.get(normalize_phone(p), set())
        for h in hashes:
            found |= self._owner_idx.get(h.lower(), set())
        for u in user_ids:
            found |= self._owner_idx.get(u, set())
        return found
