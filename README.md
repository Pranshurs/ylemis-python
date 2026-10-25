# ylemis — Python SDK for the Ylemis Trust Platform

[![PyPI](https://img.shields.io/pypi/v/ylemis)](https://pypi.org/project/ylemis/) [![tests](https://github.com/Pranshurs/ylemis-python/actions/workflows/tests.yml/badge.svg)](https://github.com/Pranshurs/ylemis-python/actions/workflows/tests.yml) [![Python](https://img.shields.io/pypi/pyversions/ylemis)](https://pypi.org/project/ylemis/) ![License: MIT](https://img.shields.io/badge/license-MIT-blue)

One integration for all Ylemis guardrails: **PII Shield** (India-tuned PII detection/redaction,
98.68% F1, 0% false positives on the [published benchmark](https://huggingface.co/datasets/Pranshurs/ylemis-india-pii-benchmark)),
**Injection Guard**, and **GroundCheck**. Use them as one pipeline, swap in your own guards, or call
any product on its own. Zero dependencies — stdlib only.

[Try PII redaction live, no sign-up](https://ylemis.com/solutions/aadhaar-pan-redaction?utm_source=github&utm_medium=organic_social&utm_campaign=python_readme#try) ·
[Docs](https://ylemis.com/docs) · [Free API key](https://ylemis.com/signup)

```bash
pip install ylemis
```

## Redact support text before sending it to an LLM

Support tickets can contain Aadhaar, PAN, phone numbers and other personal information.
PII Shield detects and redacts supported identifiers before your application passes the text
to an LLM. Start with synthetic examples in the [interactive demo](https://ylemis.com/solutions/aadhaar-pan-redaction#try),
then evaluate it on representative, authorized samples from your own use case.

```python
from ylemis import TrustEngine

engine = TrustEngine(keys={"pii-shield": "sk_live_..."})

redaction = engine.pii.redact(user_text)
llm_response = call_your_llm(redaction.redacted_text)
```

**Data flow:** your backend sends the original text to Ylemis's hosted API over HTTPS.
The SDK does not perform local-only redaction. Pass the returned redacted text, rather than
the original, to your LLM. Keep API keys on your backend and avoid logging raw customer text.
Detection can miss identifiers; review the output for your risk level. Redaction alone does
not establish legal compliance.

### Pick a starting point

| Your workflow | Start here |
| --- | --- |
| Support tickets or Indian identity-document text | [PII demo](https://ylemis.com/solutions/aadhaar-pan-redaction#try) and `engine.pii.redact(text)` |
| Untrusted prompts or retrieved instructions | [Injection Guard](https://ylemis.com/products/injection-guard) and `engine.injection.score(text)` |
| Answers that need checking against retrieved sources | [GroundCheck](https://ylemis.com/products/groundcheck) and `engine.groundcheck.check(answer, source=[...])` |

Use the [published benchmark and evaluation scripts](https://huggingface.co/datasets/Pranshurs/ylemis-india-pii-benchmark)
to inspect the reported PII results. Benchmark scores describe that evaluation, not a guarantee
for every language, document or production input.

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

## Pipelines: use ours, bring your own, or mix

Every step is a guard with one method, `check(text, context)`. Build the default chain, then
swap or drop steps. A guard you already run, such as a regex, an in-house classifier or another
vendor's SDK, becomes a step by wrapping a function.

```python
from ylemis import TrustEngine, FunctionGuard

engine = TrustEngine(api_key="sk_live_...")
pipe = engine.pipeline()        # input: PII Shield -> Injection Guard; output: PII Shield, GroundCheck

# Already have an injection filter? Keep it, use Ylemis for the rest:
pipe = pipe.replace("injection-guard", FunctionGuard("my-filter", lambda text: my_filter(text)))
pipe = pipe.without("groundcheck")                 # or drop a step

result = pipe.run(user_text, llm=call_your_llm, docs=retrieved_docs)
if result.blocked:
    ...                                            # blocked input never reaches the LLM
answer = result.safe_response                      # response after output guards
```

* A function guard may return `True`/`False`, `"allow" | "review" | "block"`, or
  `(decision, rewritten_text)` if it redacts. Add a second parameter to receive context
  (e.g. `docs`, `user_id`).
* Guards that rewrite text run first, in order. Detectors run in parallel on the original text.
* The strictest decision wins. A guard that raises **blocks** by default
  (`Pipeline(on_error="review" | "raise")` to change that).
* `llm` is any function from prompt to text: a hosted model API, a local model, or your own
  retry/fallback layer.
* PII Shield in a pipeline redacts and continues (`pii_mode="redact"`). Use
  `engine.pipeline(pii_mode="enforce")` to block on high-risk identifiers instead.

`check_input` / `check_output` below still work unchanged.

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
engine.pii.scan(text, redaction_mode="mask")   # mask | replace | drop | hash (keyed per account)
engine.pii.redact(text)
engine.pii.usage()
engine.injection.score(text)
engine.groundcheck.check(response, source=[...])
engine.health()                                # no-auth liveness, all three services
```

Products without a configured key are skipped by `check_*` (listed in `report.skipped`)
and raise `MissingKey` if called directly — so a PII-only key works fine today.

## Development status

All three adapters are exact, verified against the deployed services, including a live
end-to-end run with a single key across all three products.

```bash
python -m pytest            # offline, no keys needed
```

The SDK is MIT-licensed client code. API access requires a Ylemis subscription and
key from [ylemis.com](https://ylemis.com).
