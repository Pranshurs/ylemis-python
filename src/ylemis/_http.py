"""Stdlib-only HTTP transport with honest-error mapping and 503 auto-retry.

Retry policy: ONLY network errors and 503 ServiceBusy are retried (the API
guarantees 503 means the request was NOT metered — see store_pg.StoreUnavailable).
402/401/429 are never retried: they are truthful, actionable answers.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from .exceptions import APIError, RateLimited, ServiceBusy, STATUS_MAP, YlemisError

_USER_AGENT = "ylemis-python/0.1.0"


def _parse_retry_after(value: str | None, default: float = 1.0) -> float:
    if not value:
        return default
    try:
        return max(0.0, min(float(value), 10.0))  # cap: never sleep >10s per hop
    except ValueError:
        return default


class Transport:
    def __init__(self, base_url: str, *, timeout: float = 15.0, max_retries: int = 2):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max(0, int(max_retries))

    # -- public ----------------------------------------------------------
    def request(self, method: str, path: str, *, api_key: str | None = None,
                payload: dict | None = None, product: str | None = None) -> dict:
        attempt = 0
        while True:
            try:
                return self._once(method, path, api_key=api_key, payload=payload,
                                  product=product)
            except ServiceBusy as exc:
                if attempt >= self.max_retries:
                    raise
                time.sleep(exc.retry_after or 1.0)
            except YlemisError:
                raise
            except OSError as exc:  # DNS/conn reset — one class of retryable
                if attempt >= self.max_retries:
                    raise APIError(f"network error: {exc}", product=product) from exc
                time.sleep(0.5 * (attempt + 1))
            attempt += 1

    # -- internals ---------------------------------------------------------
    def _once(self, method: str, path: str, *, api_key: str | None,
              payload: dict | None, product: str | None) -> dict:
        url = f"{self.base_url}{path}"
        headers = {"Accept": "application/json", "User-Agent": _USER_AGENT}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if api_key:
            headers["X-API-Key"] = api_key
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return self._decode(resp.read())
        except urllib.error.HTTPError as err:
            raise self._to_error(err, product) from None

    @staticmethod
    def _decode(raw: bytes) -> dict:
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise APIError("non-JSON response from API")
        return data if isinstance(data, dict) else {"data": data}

    @staticmethod
    def _to_error(err: urllib.error.HTTPError, product: str | None) -> YlemisError:
        status = err.code
        try:
            detail = json.loads(err.read().decode("utf-8"))
        except Exception:
            detail = None
        message = (detail or {}).get("detail") if isinstance(detail, dict) else None
        message = message or f"HTTP {status}"
        cls = STATUS_MAP.get(status, APIError)
        kwargs = {"status": status, "product": product, "detail": detail}
        if cls in (ServiceBusy, RateLimited):
            kwargs["retry_after"] = _parse_retry_after(err.headers.get("Retry-After"))
        return cls(message, **kwargs)
