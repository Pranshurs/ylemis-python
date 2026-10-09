"""Hosted Ylemis guards for :class:`ylemis.Pipeline`."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from .pipeline import Context, Guard, GuardResult

if TYPE_CHECKING:  # pragma: no cover
    from .client import GroundCheckClient, InjectionGuardClient, PIIShieldClient


class PIIShieldGuard(Guard):
    """Detect and redact personal data and secrets (PII Shield).

    mode="redact" (default): replace what was found and let the request
    continue; the decision is "allow" because the text passed on is redacted.
    mode="enforce": pass PII Shield's own allow/review/block decision through,
    for teams that would rather refuse than redact.
    """

    name = "pii-shield"
    transforms = True

    def __init__(self, client: "PIIShieldClient", *, redaction_mode: str = "replace", mode: str = "redact"):
        if mode not in ("redact", "enforce"):
            raise ValueError("mode must be 'redact' or 'enforce'")
        self.client = client
        self.redaction_mode = redaction_mode
        self.mode = mode

    def check(self, text: str, context: Context) -> GuardResult:
        result = self.client.scan(text, redaction_mode=self.redaction_mode)
        decision = result.decision if self.mode == "enforce" else "allow"
        return GuardResult(self.name, decision, text=result.redacted_text, detail=result)


class InjectionGuard(Guard):
    """Detect prompt injection and jailbreaks (Injection Guard)."""

    name = "injection-guard"

    def __init__(self, client: "InjectionGuardClient"):
        self.client = client

    def check(self, text: str, context: Context) -> GuardResult:
        result = self.client.score(text)
        return GuardResult(self.name, result.decision, detail=result)


class GroundCheckGuard(Guard):
    """Check that an answer is supported by its sources (GroundCheck).

    Reads the sources from ``context["docs"]`` (pass ``docs=`` to check_output
    or run). Without sources there is nothing to check against, so it allows
    and says so in ``error``.
    """

    name = "groundcheck"

    def __init__(self, client: "GroundCheckClient", *, threshold: float = 0.5,
                 question_key: Optional[str] = "question"):
        self.client = client
        self.threshold = threshold
        self.question_key = question_key

    def check(self, text: str, context: Context) -> GuardResult:
        docs = context.get("docs")
        if not docs:
            return GuardResult(self.name, "allow", error="skipped: no docs to check against")
        question = str(context.get(self.question_key, "")) if self.question_key else ""
        result = self.client.check(text, docs, question=question, threshold=self.threshold)
        return GuardResult(self.name, result.decision, detail=result)
