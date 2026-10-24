"""Evidence index: manifest-driven extraction plus a resource -> user link graph."""
from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path

from ..identity import IdentityResolver
from ..loaders import EVIDENCE_COLUMNS, load_csv
from ..models import Observation
from .extract import parse_file

log = logging.getLogger("ghost_audit.scanner")


class EvidenceIndex:
    def __init__(self, resolver: IdentityResolver):
        self.resolver = resolver
        self.observations: list[Observation] = []
        self.captured: dict[str, str] = {}  # evidence_id -> manifest captured_at
        self.by_resource: dict[str, list[Observation]] = defaultdict(list)
        self.links: dict[str, set[str]] = defaultdict(set)  # resource_id -> user_ids
        self.by_user: dict[str, set[str]] = defaultdict(set)  # user_id -> resource_ids

    @classmethod
    def build(cls, dataset_dir: str | Path, resolver: IdentityResolver, cache_dir: str | Path | None = None,
              activity_rows: list[dict] | None = None) -> "EvidenceIndex":
        dataset_dir = Path(dataset_dir)
        idx = cls(resolver)
        manifest = load_csv(dataset_dir / "evidence_files.csv", EVIDENCE_COLUMNS)
        for row in manifest.rows:
            path = dataset_dir / row["file_path"]
            if not path.exists():
                log.warning("evidence file missing: %s", path)
                continue
            idx.captured[row["file_id"]] = row["captured_at"]
            idx.observations.extend(
                parse_file(row["file_id"], path, row["captured_at"], Path(cache_dir) if cache_dir else None)
            )
        for ob in idx.observations:
            idx.by_resource[ob.resource_id].append(ob)
            owners = resolver.owners(ob.emails, ob.phones, ob.hashes, ob.user_ids)
            for u in owners:
                idx.links[ob.resource_id].add(u)
                idx.by_user[u].add(ob.resource_id)
        for row in activity_rows or []:
            if row.get("event_type") == "LINK_RESOURCE_IDENTITY":
                from ..identity import EMAIL_RE, USER_RE
                det = row.get("details", "")
                owners = resolver.owners(EMAIL_RE.findall(det), (), (), USER_RE.findall(det.lower()))
                for u in owners:
                    idx.links[row["resource_id"]].add(u)
                    idx.by_user[u].add(row["resource_id"])
        log.info("indexed %d observations over %d resources", len(idx.observations), len(idx.by_resource))
        return idx
