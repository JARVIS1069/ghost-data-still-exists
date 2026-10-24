"""Command line entry point.

    python code/cli.py run --input dataset/deletion_requests.csv --output output.csv
    python -m code.cli run ...      (works when the repo root is the cwd and `code` resolves to this package)
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from ghost_audit.agent import AgentConfig, AuditAgent  # noqa: E402
from ghost_audit.loaders import OUTPUT_COLUMNS, load_requests  # noqa: E402
from ghost_audit.models import Request  # noqa: E402


def load_env(path: str = ".env") -> None:
    p = Path(path)
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def load_config(path: str | None) -> dict:
    if not path or not Path(path).exists():
        return {}
    import yaml
    return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}


def build_agent(cfg_dict: dict, dataset: str | None = None, use_llm: bool | None = None) -> AuditAgent:
    a = cfg_dict.get("agent", {})
    cfg = AgentConfig(
        dataset_dir=dataset or cfg_dict.get("dataset_dir", "dataset"),
        cache_dir=cfg_dict.get("cache_dir", ".cache/ocr"),
        use_llm=a.get("use_llm", False) if use_llm is None else use_llm,
        link_by_activity=a.get("link_by_activity", True),
        lookback_hours=a.get("lookback_hours", 3.0),
        seed=cfg_dict.get("seed", 7),
    )
    return AuditAgent.from_config(cfg)


def write_output(rows: list[dict], out: str) -> None:
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=OUTPUT_COLUMNS)
        w.writeheader()
        w.writerows(sorted(rows, key=lambda r: r["case_id"]))


def run(args: argparse.Namespace) -> int:
    load_env()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    cfg = load_config(args.config)
    if not Path(args.input).exists():
        print(f"input not found: {args.input}", file=sys.stderr)
        return 2
    requests, errors = load_requests(args.input)
    for e in errors:
        logging.warning(json.dumps({"event": "bad_row", "detail": e}))
    dataset = str(Path(args.input).resolve().parent)
    agent = build_agent(cfg, dataset, args.llm)
    context: list[Request] = []
    sample = Path(dataset) / "sample_deletion_requests.csv"
    if sample.exists():
        context, _ = load_requests(sample)
    results = agent.run(requests, context_requests=context)
    rows = []
    for r in results:
        rows.append(AuditAgent.to_row(r))
        logging.info(json.dumps({"event": "case", "case_id": r.case_id, "status": r.status,
                                 "steps": len(r.steps), "evidence": r.notes[:8]}, ensure_ascii=False))
    write_output(rows, args.output)
    usage = agent.classifier.tracker.summary()
    logging.info(json.dumps({"event": "done", "cases": len(rows), "llm_usage": usage}))
    print(f"wrote {len(rows)} rows to {args.output}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ghost-audit")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="audit deletion requests and write output.csv")
    r.add_argument("--input", default="dataset/deletion_requests.csv")
    r.add_argument("--output", default="output.csv")
    r.add_argument("--config", default="configs/default.yaml")
    r.add_argument("--llm", dest="llm", action="store_true", default=None, help="enable LLM assist")
    r.set_defaults(func=run)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
