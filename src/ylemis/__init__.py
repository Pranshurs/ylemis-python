"""Ylemis Trust Platform — official Python SDK (zero dependencies)."""

from .client import (GroundCheckClient, InjectionGuardClient, PIIShieldClient,
                     TrustEngine, DEFAULT_BASE_URL)
from .exceptions import (APIError, InvalidAPIKey, MissingKey, PayloadTooLarge,
                         QuotaExceeded, RateLimited, ServiceBusy, UpstreamTimeout,
                         YlemisError)
from .models import (CheckReport, Entity, GroundCheckResult, InjectionResult,
                     PIIResult, RedactResult, Usage, merge_decisions)

__version__ = "0.1.0"

__all__ = [
    "TrustEngine", "PIIShieldClient", "InjectionGuardClient", "GroundCheckClient",
    "DEFAULT_BASE_URL",
    "YlemisError", "MissingKey", "InvalidAPIKey", "QuotaExceeded", "PayloadTooLarge",
    "RateLimited", "ServiceBusy", "UpstreamTimeout", "APIError",
    "CheckReport", "PIIResult", "RedactResult", "Usage", "Entity",
    "InjectionResult", "GroundCheckResult", "merge_decisions",
]
