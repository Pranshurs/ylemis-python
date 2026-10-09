"""Typed errors encoding the Ylemis API error semantics.

Contract (NEXT_AGENT_HANDOFF_2026-07-04.md §5.6):
  401 = bad/revoked key          -> InvalidAPIKey
  402 = GENUINE quota exhaustion -> QuotaExceeded  (never masked infra errors)
  413 = payload too large        -> PayloadTooLarge
  429 = rate limit / lockout     -> RateLimited
  503 = retryable infra hiccup   -> ServiceBusy    (transport auto-retries, honoring Retry-After)
  504 = request timeout          -> UpstreamTimeout
"""

from __future__ import annotations


class YlemisError(Exception):
    """Base for all SDK errors."""

    def __init__(self, message: str, *, status: int | None = None,
                 product: str | None = None, detail: object = None):
        super().__init__(message)
        self.status = status
        self.product = product
        self.detail = detail


class MissingKey(YlemisError):
    """No API key configured for the product being called."""


class InvalidAPIKey(YlemisError):
    """401 — key is missing, malformed, revoked, or scoped to another product."""


class QuotaExceeded(YlemisError):
    """402 — the plan's quota for this billing period is genuinely exhausted."""


class PayloadTooLarge(YlemisError):
    """413 — request body exceeds the service limit."""


class RateLimited(YlemisError):
    """429 — per-key/per-IP rate limit or temporary auth-failure lockout."""

    def __init__(self, message: str, *, retry_after: float | None = None, **kw):
        super().__init__(message, **kw)
        self.retry_after = retry_after


class ServiceBusy(YlemisError):
    """503 — transient infra/DB issue. The SDK already retried before raising this."""

    def __init__(self, message: str, *, retry_after: float | None = None, **kw):
        super().__init__(message, **kw)
        self.retry_after = retry_after


class UpstreamTimeout(YlemisError):
    """504 — the service timed out processing the request."""


class APIError(YlemisError):
    """Any other non-2xx response."""


STATUS_MAP = {
    401: InvalidAPIKey,
    402: QuotaExceeded,
    413: PayloadTooLarge,
    429: RateLimited,
    503: ServiceBusy,
    504: UpstreamTimeout,
}
