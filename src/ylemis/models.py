"""Result types. Every wrapper keeps the full server payload in `.raw`.

PII Shield shapes are exact (verified against the deployed service source).
Injection Guard / GroundCheck payloads are PROVISIONAL passthroughs until one
live probe locks their field names — decisions for them are derived defensively.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

Decision = str  # "allow" | "review" | "block"
_DECISION_RANK = {"allow": 0, "review": 1, "block": 2}


def merge_decisions(*decisions: Optional[Decision]) -> Decision:
    """Most-restrictive-wins merge; unknown/None values are ignored."""
    best = "allow"
    for d in decisions:
        if d in _DECISION_RANK and _DECISION_RANK[d] > _DECISION_RANK[best]:
            best = d
    return best


@dataclass(frozen=True)
class Entity:
    """One detected PII span (positions refer to the original text)."""

    type: str
    start: int
    end: int
    text_preview: str
    confidence: float
    severity: str
    source: str = ""
    method: str = ""
    recognizer: str = ""
    format_validated: bool = False

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Entity":
        return cls(
            type=d.get("type", ""), start=int(d.get("start", 0)), end=int(d.get("end", 0)),
            text_preview=d.get("text_preview", ""), confidence=float(d.get("confidence", 0.0)),
            severity=str(d.get("severity", "")), source=d.get("source", ""),
            method=d.get("method", ""), recognizer=d.get("recognizer", ""),
            format_validated=bool(d.get("format_validated", False)),
        )


@dataclass(frozen=True)
class PIIResult:
    decision: Decision
    risk_level: str
    entities: List[Entity]
    redacted_text: str
    counts: Dict[str, int]
    latency_ms: float
    model_version: str
    quota_remaining: Optional[int]
    raw: Dict[str, Any] = field(repr=False, default_factory=dict)

    @property
    def has_pii(self) -> bool:
        return bool(self.entities)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PIIResult":
        return cls(
            decision=d.get("decision", "allow"),
            risk_level=d.get("risk_level", ""),
            entities=[Entity.from_dict(e) for e in d.get("entities", [])],
            redacted_text=d.get("redacted_text", ""),
            counts=dict(d.get("counts", {})),
            latency_ms=float(d.get("latency_ms", 0.0)),
            model_version=str(d.get("model_version", "")),
            quota_remaining=d.get("quota_remaining"),
            raw=d,
        )


@dataclass(frozen=True)
class RedactResult:
    redacted_text: str
    counts: Dict[str, int]
    risk_level: str
    quota_remaining: Optional[int]
    model_version: str
    raw: Dict[str, Any] = field(repr=False, default_factory=dict)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RedactResult":
        return cls(
            redacted_text=d.get("redacted_text", ""), counts=dict(d.get("counts", {})),
            risk_level=d.get("risk_level", ""), quota_remaining=d.get("quota_remaining"),
            model_version=str(d.get("model_version", "")), raw=d,
        )


@dataclass(frozen=True)
class Usage:
    plan: str
    quota: int          # -1 = unlimited
    used: int
    unlimited: bool
    raw: Dict[str, Any] = field(repr=False, default_factory=dict)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Usage":
        return cls(plan=d.get("plan", ""), quota=int(d.get("quota", 0)),
                   used=int(d.get("used", 0)), unlimited=bool(d.get("unlimited", False)), raw=d)


def _derive_decision(raw: Dict[str, Any]) -> Decision:
    """Defensive decision extraction for services whose schema isn't locked yet.

    Order: explicit `decision` field > boolean block-ish flags > allow.
    Deliberately does NOT invent numeric thresholds — that's server/policy work.
    """
    d = raw.get("decision")
    if d in _DECISION_RANK:
        return d
    for flag in ("blocked", "block", "flagged", "injection_detected", "is_injection"):
        v = raw.get(flag)
        if isinstance(v, bool):
            return "block" if v else "allow"
    verdict = raw.get("verdict") or raw.get("label")
    if isinstance(verdict, str) and verdict.lower() in ("malicious", "injection", "unsafe", "ungrounded", "hallucinated"):
        return "review"
    return "allow"


@dataclass(frozen=True)
class InjectionResult:
    """LOCKED to the deployed Injection Guard schema (verified against the
    service's API.md pulled from the VPS, 2026-07-04)."""

    decision: Decision          # "allow" | "review" | "block" (server-native)
    score: float = 0.0          # 0-1 probability of injection
    reason: str = ""            # "model" | "trivial_safe"
    obfuscation: bool = False   # homoglyph/base64/zero-width evasion detected
    quota_remaining: Optional[int] = None
    raw: Dict[str, Any] = field(repr=False, default_factory=dict)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "InjectionResult":
        return cls(decision=_derive_decision(d), score=float(d.get("score", 0.0)),
                   reason=str(d.get("reason", "")),
                   obfuscation=bool(d.get("obfuscation", False)),
                   quota_remaining=d.get("quota_remaining"), raw=d)


@dataclass(frozen=True)
class GroundCheckResult:
    """LOCKED to the deployed GroundCheck Pro schema (app/schemas.py + engine.py,
    verified 2026-07-04). `decision` is SDK-derived: hallucinated -> "review"
    (grounding failure is a review signal, not a hard block, by default)."""

    decision: Decision
    label: str = ""             # "grounded" | "hallucinated"
    p_grounded: float = 0.0     # 0-1 probability the answer is supported
    threshold: float = 0.5
    engine: str = ""            # "model" | "lexical" (degraded mode)
    sentences: List[Dict[str, Any]] = field(default_factory=list)  # granular=True only
    quota_remaining: Optional[int] = None
    raw: Dict[str, Any] = field(repr=False, default_factory=dict)

    @property
    def grounded(self) -> bool:
        return self.label == "grounded"

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "GroundCheckResult":
        label = str(d.get("label", ""))
        return cls(decision="review" if label == "hallucinated" else "allow",
                   label=label, p_grounded=float(d.get("p_grounded", 0.0)),
                   threshold=float(d.get("threshold", 0.5)), engine=str(d.get("engine", "")),
                   sentences=list(d.get("sentences", [])),
                   quota_remaining=d.get("quota_remaining"), raw=d)


@dataclass(frozen=True)
class CheckReport:
    """Combined result of a multi-product check. `skipped` lists products that
    had no API key configured and were therefore not consulted."""

    decision: Decision
    pii: Optional[PIIResult] = None
    injection: Optional[InjectionResult] = None
    groundcheck: Optional[GroundCheckResult] = None
    skipped: List[str] = field(default_factory=list)

    @property
    def redacted_text(self) -> Optional[str]:
        """The PII-safe text (None if PII check was skipped)."""
        return self.pii.redacted_text if self.pii else None
