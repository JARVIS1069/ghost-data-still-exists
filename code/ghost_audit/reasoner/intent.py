"""Reasoner: request-intent classification (deterministic first, optional LLM second).

The heuristic handles clear cases offline. The LLM is consulted only when the heuristic is
unsure *and* an API key is configured; otherwise the deterministic answer stands. Every call is
recorded in ``UsageTracker`` so usage_report.md can be generated.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field

log = logging.getLogger("ghost_audit.reasoner")

# Phrases (multilingual stems) that signal a deletion intent.
DELETE_CUES = [
    r"\bdelet", r"\berase", r"\berasure", r"\bremov(e|al)", r"\bclose (my|this|the) account",
    r"\bforget", r"\bpurge", r"\bwipe", r"permanent account", r"eliminaci", r"\beliminar",
    r"suppression", r"supprim", r"exclus[aã]o", r"\bexcluir", r"\bl[oö]sch", r"\bcancell?ation de compte",
    r"삭제", r"削除", r"删除", r"удал", r"\bcancelar (mi|la) cuenta",
]
# Phrases that explicitly keep the account/data -> not a deletion request.
KEEP_CUES = [
    r"do not (close|delete|remove)", r"don'?t (close|delete|remove)", r"without (removing|deleting|closing)",
    r"leave (the|my) (account|profile)", r"keep (the|my) (account|profile)", r"in place",
    r"continue using", r"leave the account active", r"keep the account as it is",
]
OTHER_CUES = [
    r"\bdownload", r"portable format", r"\bcopy of\b", r"\bcorrect (it|my|the)\b", r"misspell",
    r"out of date", r"\breplace it\b", r"reset(ting)? the login", r"change the email", r"\bupdate my\b",
    r"opt.?out", r"unsubscribe", r"can'?t access",
]


@dataclass
class Intent:
    is_deletion: bool
    confidence: float
    reason: str
    source: str = "heuristic"


def heuristic_intent(text: str) -> Intent:
    t = (text or "").lower()
    if not t.strip():
        return Intent(True, 0.3, "empty request text; defaulting to deletion workflow")
    keep = [c for c in KEEP_CUES if re.search(c, t)]
    other = [c for c in OTHER_CUES if re.search(c, t)]
    dele = [c for c in DELETE_CUES if re.search(c, t)]
    if keep and not dele:
        return Intent(False, 0.95, f"explicit keep-account cue: {keep[0]}")
    if other and not dele:
        return Intent(False, 0.9, f"non-deletion request cue: {other[0]}")
    if keep and dele:
        return Intent(False, 0.55, "mixed deletion and keep cues")
    if dele:
        return Intent(True, 0.95, f"deletion cue: {dele[0]}")
    return Intent(True, 0.4, "no recognised cue; defaulting to deletion workflow")


@dataclass
class UsageTracker:
    calls: list[dict] = field(default_factory=list)

    def record(self, provider: str, model: str, in_tokens: int, out_tokens: int, seconds: float) -> None:
        self.calls.append({"provider": provider, "model": model, "input_tokens": in_tokens,
                           "output_tokens": out_tokens, "seconds": round(seconds, 3)})

    def summary(self) -> dict:
        agg: dict[tuple, dict] = {}
        for c in self.calls:
            a = agg.setdefault((c["provider"], c["model"]), {"calls": 0, "in": 0, "out": 0})
            a["calls"] += 1
            a["in"] += c["input_tokens"]
            a["out"] += c["output_tokens"]
        return {f"{p}/{m}": v for (p, m), v in agg.items()}


INTENT_SCHEMA = {
    "type": "object",
    "properties": {"is_deletion": {"type": "boolean"}, "reason": {"type": "string"}},
    "required": ["is_deletion", "reason"],
}
PROMPT = (
    "You classify privacy requests. Reply with JSON only: {\"is_deletion\": bool, \"reason\": str}. "
    "is_deletion is true only if the person asks for their account or personal data to be deleted/erased. "
    "Requests to access, export, correct, update, or keep data are NOT deletion requests."
)


class LLMClient:
    """Provider-agnostic JSON-mode client configured only via environment variables."""

    def __init__(self, tracker: UsageTracker, provider: str | None = None, model: str | None = None,
                 retries: int = 2):
        self.tracker = tracker
        self.provider = (provider or os.getenv("LLM_PROVIDER", "none")).lower()
        self.model = model or os.getenv("LLM_MODEL", "")
        self.retries = retries

    @property
    def available(self) -> bool:
        if self.provider == "openai":
            return bool(os.getenv("OPENAI_API_KEY"))
        if self.provider == "anthropic":
            return bool(os.getenv("ANTHROPIC_API_KEY"))
        return False

    def classify(self, text: str) -> Intent | None:
        if not self.available:
            return None
        for attempt in range(self.retries + 1):
            t0 = time.time()
            try:
                if self.provider == "openai":
                    from openai import OpenAI
                    r = OpenAI().chat.completions.create(
                        model=self.model or "gpt-4o-mini", temperature=0,
                        response_format={"type": "json_object"},
                        messages=[{"role": "system", "content": PROMPT}, {"role": "user", "content": text}],
                    )
                    raw = r.choices[0].message.content or "{}"
                    self.tracker.record("openai", r.model, r.usage.prompt_tokens, r.usage.completion_tokens,
                                        time.time() - t0)
                else:
                    import anthropic
                    r = anthropic.Anthropic().messages.create(
                        model=self.model or "claude-3-5-haiku-latest", max_tokens=200, temperature=0,
                        system=PROMPT, messages=[{"role": "user", "content": text}],
                    )
                    raw = r.content[0].text
                    self.tracker.record("anthropic", r.model, r.usage.input_tokens, r.usage.output_tokens,
                                        time.time() - t0)
                data = json.loads(raw[raw.index("{"): raw.rindex("}") + 1])
                return Intent(bool(data["is_deletion"]), 0.9, str(data.get("reason", "")), "llm")
            except Exception as exc:  # noqa: BLE001 - network/schema errors fall back to heuristics
                log.warning("llm attempt %d failed: %s", attempt + 1, exc)
        return None


class IntentClassifier:
    def __init__(self, use_llm: bool = True, tracker: UsageTracker | None = None, threshold: float = 0.7):
        self.tracker = tracker or UsageTracker()
        self.client = LLMClient(self.tracker) if use_llm else None
        self.threshold = threshold

    def classify(self, text: str) -> Intent:
        base = heuristic_intent(text)
        if base.confidence >= self.threshold or not self.client:
            return base
        return self.client.classify(text) or base
