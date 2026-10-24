"""System/category taxonomy derived from resource-id naming conventions in the dataset docs.

Kept in one place (and overridable from configs/default.yaml) so nothing is hardcoded in logic.
"""
from __future__ import annotations

import re

# resource-id prefix -> (system_id, default data_category)
PREFIX_MAP: dict[str, tuple[str, str]] = {
    "account": ("account_service", "USER_PROFILE"),
    "search": ("search_service", "SEARCH_INDEX_ENTRY"),
    "cache": ("cache_service", "CACHE_ENTRY"),
    "support": ("support_platform", "SUPPORT_MESSAGE"),
    "analytics": ("analytics_platform", "ANALYTICS_PROFILE"),
    "export": ("export_service", "USER_EXPORT"),
    "marketing": ("marketing_platform", "MARKETING_PROFILE"),
    "email_delivery": ("email_delivery_service", "EMAIL_DELIVERY_LOG"),
    "audit_record": ("security_service", "SECURITY_AUDIT_LOG"),
    "legal_hold": ("legal_service", "LEGAL_HOLD_RECORD"),
    "backup": ("backup_service", "BACKUP_ARCHIVE"),
    "tombstone": ("identity_service", "ACCOUNT_TOMBSTONE"),
    "data_flow": ("integration_service", "DATA_FLOW"),
}

RESOURCE_RE = re.compile(
    r"\b(" + "|".join(sorted(PREFIX_MAP, key=len, reverse=True)) + r")_(\d+)\b"
)


def prefix_of(resource_id: str) -> str:
    m = RESOURCE_RE.fullmatch(resource_id or "")
    return m.group(1) if m else ""


def system_for(resource_id: str) -> str:
    p = prefix_of(resource_id)
    return PREFIX_MAP[p][0] if p else ""


def category_for(resource_id: str, hint: str = "") -> str:
    """Data category for a resource; ``hint`` (record_type/collection/event text) refines it."""
    p = prefix_of(resource_id)
    if not p:
        return ""
    cat = PREFIX_MAP[p][1]
    h = (hint or "").lower()
    if p == "support" and "attach" in h:
        return "SUPPORT_ATTACHMENT"
    if p == "analytics" and "telemetry" in h:
        return "PRODUCT_TELEMETRY"
    return cat
