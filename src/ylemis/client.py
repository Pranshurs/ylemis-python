"""Ylemis Trust Platform client.

Two hook points match the real LLM request lifecycle (input checks run BEFORE
the prompt reaches the model — that is the DPDP story), plus `.scan()` as
batch/audit sugar:

    from ylemis import TrustEngine
    engine = TrustEngine(keys={"pii-shield": "sk_live_..."})   # or api_key="..." for all
    inp = engine.check_input(prompt)              # PII + injection, pre-LLM
    safe_prompt = inp.redacted_text               # send THIS to the LLM
    out = engine.check_output(response, docs=docs)  # PII + groundedness, post-LLM

Keys: pass `api_key=` to use one key everywhere (forward-compatible with the
unified platform key), and/or `keys={product: key}` per product. Products with
no key are skipped by check_* (reported in `.skipped`) and raise MissingKey if
called directly.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Iterable, Optional, Sequence

from ._http import Transport
from .exceptions import MissingKey
from .models import (CheckReport, GroundCheckResult, InjectionResult, PIIResult,
                     RedactResult, Usage, merge_decisions)

DEFAULT_BASE_URL = "https://api.ylemis.com"
PII, INJECTION, GROUNDCHECK = "pii-shield", "injection-guard", "groundcheck"


class _ProductClient:
    slug: str = ""
    _health_path: str = "/health"

    def __init__(self, transport: Transport, key: Optional[str]):
        self._transport = transport
        self._key = key

    def _require_key(self) -> str:
        if not self._key:
            raise MissingKey(f"no API key configured for {self.slug}", product=self.slug)
        return self._key

    def _post(self, path: str, payload: dict) -> dict:
        return self._transport.request("POST", f"/{self.slug}{path}",
                                       api_key=self._require_key(), payload=payload,
                                       product=self.slug)

    def _get(self, path: str, *, auth: bool = True) -> dict:
        return self._transport.request("GET", f"/{self.slug}{path}",
                                       api_key=self._require_key() if auth else None,
                                       product=self.slug)

    @property
    def configured(self) -> bool:
        return bool(self._key)

    def health(self) -> dict:
        """No-auth liveness check."""
        return self._get(self._health_path, auth=False)


class PIIShieldClient(_ProductClient):
    """Exact contract, verified against the deployed service source."""

    slug = PII

    def scan(self, text: str, *, redaction_mode: str = "mask") -> PIIResult:
        return PIIResult.from_dict(self._post("/v1/scan", {"text": text, "redaction_mode": redaction_mode}))

    def redact(self, text: str, *, redaction_mode: str = "mask") -> RedactResult:
        return RedactResult.from_dict(self._post("/v1/redact", {"text": text, "redaction_mode": redaction_mode}))

    def usage(self) -> Usage:
        return Usage.from_dict(self._get("/v1/usage"))


class InjectionGuardClient(_ProductClient):
    """Exact contract (locked from the deployed service's API.md, 2026-07-04).
    Limits: 100k chars/text; batch = max 32 texts, 200k chars total, metered per text."""

    slug = INJECTION

    def score(self, text: str, *, payload: Optional[dict] = None) -> InjectionResult:
        return InjectionResult.from_dict(self._post("/v1/score", payload or {"text": text}))

    def score_batch(self, texts: Sequence[str]) -> list[InjectionResult]:
        data = self._post("/v1/batch", {"texts": list(texts)})
        return [InjectionResult.from_dict(r) for r in data.get("results", [])]

    def usage(self) -> Usage:
        return Usage.from_dict(self._get("/v1/usage"))


class GroundCheckClient(_ProductClient):
    """Exact contract (locked from the deployed service source, 2026-07-04).
    Limits: source <=50k chars, answer <=10k, question <=2k; batch <=32 items."""

    slug = GROUNDCHECK
    _health_path = "/healthz"

    def check(self, answer: str = "", source: "str | Sequence[str] | None" = None, *,
              question: str = "", threshold: float = 0.5, granular: bool = False,
              payload: Optional[dict] = None) -> GroundCheckResult:
        """Is `answer` supported by `source`? `source` may be one string or a
        list of retrieved docs (joined with blank lines)."""
        if payload is None:
            if source is None:
                raise ValueError("check() needs source= (the grounding text/docs)")
            src = source if isinstance(source, str) else "\n\n".join(source)
            payload = {"source": src, "answer": answer, "question": question,
                       "threshold": threshold, "granular": granular}
        return GroundCheckResult.from_dict(self._post("/v1/check", payload))

    def check_batch(self, items: Sequence[dict]) -> list[GroundCheckResult]:
        """items = list of {source, answer, question?, threshold?, granular?} (max 32)."""
        data = self._post("/v1/check/batch", {"items": list(items)})
        return [GroundCheckResult.from_dict(r) for r in data.get("results", [])]

    def usage(self) -> Usage:
        return Usage.from_dict(self._get("/v1/usage"))


class TrustEngine:
    def __init__(self, api_key: Optional[str] = None, *,
                 keys: Optional[Dict[str, str]] = None,
                 base_url: str = DEFAULT_BASE_URL,
                 timeout: float = 15.0, max_retries: int = 2):
        resolved = {p: api_key for p in (PII, INJECTION, GROUNDCHECK)}
        resolved.update(keys or {})
        self._transport = Transport(base_url, timeout=timeout, max_retries=max_retries)
        self.pii = PIIShieldClient(self._transport, resolved.get(PII))
        self.injection = InjectionGuardClient(self._transport, resolved.get(INJECTION))
        self.groundcheck = GroundCheckClient(self._transport, resolved.get(GROUNDCHECK))

    def __repr__(self) -> str:  # never leak keys
        configured = [c.slug for c in (self.pii, self.injection, self.groundcheck) if c.configured]
        return f"TrustEngine(products={configured})"

    # -- hooks -------------------------------------------------------------
    def check_input(self, prompt: str, *, checks: Iterable[str] = (PII, INJECTION),
                    redaction_mode: str = "mask") -> CheckReport:
        """Run pre-LLM guardrails on the outbound prompt. Use `.redacted_text`
        as the safe prompt to actually send."""
        checks = set(checks)
        pii = inj = None
        skipped: list[str] = []
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {}
            if PII in checks:
                if self.pii.configured:
                    futures[PII] = pool.submit(self.pii.scan, prompt, redaction_mode=redaction_mode)
                else:
                    skipped.append(PII)
            if INJECTION in checks:
                if self.injection.configured:
                    futures[INJECTION] = pool.submit(self.injection.score, prompt)
                else:
                    skipped.append(INJECTION)
            pii = futures[PII].result() if PII in futures else None
            inj = futures[INJECTION].result() if INJECTION in futures else None
        decision = merge_decisions(pii.decision if pii else None, inj.decision if inj else None)
        return CheckReport(decision=decision, pii=pii, injection=inj, skipped=skipped)

    def check_output(self, response: str, docs: Optional[Sequence[str]] = None, *,
                     checks: Iterable[str] = (PII, GROUNDCHECK),
                     redaction_mode: str = "mask") -> CheckReport:
        """Run post-LLM guardrails on the model's answer (PII in the output;
        groundedness against `docs` when provided)."""
        checks = set(checks)
        if docs is None:
            checks.discard(GROUNDCHECK)  # nothing to ground against
        pii = gc = None
        skipped: list[str] = []
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {}
            if PII in checks:
                if self.pii.configured:
                    futures[PII] = pool.submit(self.pii.scan, response, redaction_mode=redaction_mode)
                else:
                    skipped.append(PII)
            if GROUNDCHECK in checks:
                if self.groundcheck.configured:
                    futures[GROUNDCHECK] = pool.submit(self.groundcheck.check, response, docs)
                else:
                    skipped.append(GROUNDCHECK)
            pii = futures[PII].result() if PII in futures else None
            gc = futures[GROUNDCHECK].result() if GROUNDCHECK in futures else None
        decision = merge_decisions(pii.decision if pii else None, gc.decision if gc else None)
        return CheckReport(decision=decision, pii=pii, groundcheck=gc, skipped=skipped)

    # -- audit sugar ---------------------------------------------------------
    def scan(self, *, prompt: Optional[str] = None, response: Optional[str] = None,
             docs: Optional[Sequence[str]] = None) -> CheckReport:
        """Offline/batch convenience: checks whatever you pass, merges decisions.
        For live traffic prefer check_input()/check_output() at their hook points."""
        reports = []
        if prompt is not None:
            reports.append(self.check_input(prompt))
        if response is not None:
            reports.append(self.check_output(response, docs))
        if not reports:
            raise ValueError("scan() needs prompt= and/or response=")
        merged = CheckReport(
            decision=merge_decisions(*(r.decision for r in reports)),
            pii=next((r.pii for r in reports if r.pii), None),
            injection=next((r.injection for r in reports if r.injection), None),
            groundcheck=next((r.groundcheck for r in reports if r.groundcheck), None),
            skipped=sorted({s for r in reports for s in r.skipped}),
        )
        return merged

    def health(self) -> Dict[str, dict]:
        """No-auth liveness of all three services."""
        return {c.slug: c.health() for c in (self.pii, self.injection, self.groundcheck)}
