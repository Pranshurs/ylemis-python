# Changelog

## 0.2.0

- **Pipelines.** `Pipeline`, `Guard`, `FunctionGuard` and `engine.pipeline()`: chain the hosted
  guards, wrap your own checks as guards, swap (`replace`) or drop (`without`) steps, and
  `run(prompt, llm=..., docs=...)` the whole flow. Blocked input never reaches the LLM;
  guards that raise block by default.
- Hosted guards: `PIIShieldGuard` (redact or enforce), `InjectionGuard`, `GroundCheckGuard`.
- `check_input`, `check_output`, `scan` and the per-product clients are unchanged.
- Package metadata: source, issues and changelog links; typed (`py.typed`); Python 3.9-3.13.
- The User-Agent now reports the real version.
- PII Shield `hash` redaction is now keyed per account on the server (no SDK change needed).

## 0.1.1

- First public release on PyPI.
