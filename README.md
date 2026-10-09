# ylemis — Python SDK for the Ylemis Trust Platform

One integration for all Ylemis guardrails: **PII Shield** (India-tuned PII detection/redaction,
98.68% F1, 0% false positives on the published benchmark), **Injection Guard**, and **GroundCheck**.
Zero dependencies — stdlib only.

```bash
pip install ylemis
```

## 30-second DPDP fix

You're piping customer data into an LLM. Aadhaar/PAN in a third-party model's logs is a
₹250-crore DPDP exposure. One line stops it at the door:

```python
from ylemis import TrustEngine

engine = TrustEngine(keys={"pii-shield": "sk_live_..."})

safe_prompt = engine.check_input(user_text).redacted_text   # PII never leaves your app
llm_response = call_your_llm(safe_prompt)
```

## The two hooks (full flow)

Guardrails belong at two points in the LLM lifecycle — before the prompt goes out, and after
the answer comes back:

```python
engine = TrustEngine(api_key="sk_live_...")    # one key everywhere (or keys={...} per product)

inp = engine.check_input(prompt)                # PII + injection, PRE-LLM
if inp.decision == "block":
    ...                                         # your policy
response = call_your_llm(inp.redacted_text)

out = engine.check_output(response, docs=retrieved_docs)   # PII + groundedness, POST-LLM
if out.decision == "allow":
    return response
```

`engine.scan(prompt=..., response=..., docs=...)` is batch/audit sugar over both hooks.

## Error handling — errors are honest

The API never masks infra errors as billing errors. The SDK encodes that contract as types:

```python
from ylemis import QuotaExceeded, RateLimited, ServiceBusy, InvalidAPIKey

try:
    r = engine.pii.scan(text)
except QuotaExceeded:   # 402 — genuinely out of quota, upgrade or wait for reset
    ...
except RateLimited:     # 429 — slow down (see .retry_after)
    ...
except ServiceBusy:     # 503 — transient; SDK already auto-retried per Retry-After
    ...
```

Requests are metered only on success — a `ServiceBusy` retry never double-bills.

## Per-product access

```python
engine.pii.scan(text, redaction_mode="mask")   # mask | replace | drop | hash
engine.pii.redact(text)
engine.pii.usage()
engine.injection.score(text)
engine.groundcheck.check(response, source=[...])
engine.health()                                # no-auth liveness, all three services
```

Products without a configured key are skipped by `check_*` (listed in `report.skipped`)
and raise `MissingKey` if called directly — so a PII-only key works fine today.

## Development status

All three adapters are exact, verified against the deployed services (2026-07-05),
including a live end-to-end run with a single key across all three products.

```bash
python -m unittest discover -s tests -v    # offline, no keys needed
```

The SDK is MIT-licensed client code. API access requires a Ylemis subscription and
key from [ylemis.com](https://ylemis.com).
