"""Composable guardrail pipeline: use Ylemis guards, your own, or both.

Every step is a *guard* with one method, ``check(text, context) -> GuardResult``.
Ylemis ships hosted guards (PII Shield, Injection Guard, GroundCheck). Anything
else, such as a regex, an in-house classifier or another vendor's SDK, becomes a
guard by wrapping a plain function with :class:`FunctionGuard`. Guards can be
added, removed, reordered or swapped without touching the rest of the chain.

    from ylemis import TrustEngine, FunctionGuard, Pipeline

    engine = TrustEngine(api_key="sk_live_...")
    pipe = engine.pipeline()                                  # Ylemis defaults

    # Keep your own injection filter, use Ylemis for PII and grounding:
    pipe = Pipeline(
        input=[engine.guards.pii(), FunctionGuard("my-injection-filter", my_filter)],
        output=[engine.guards.groundcheck()],
    )
    result = pipe.run(user_text, llm=lambda prompt: call_your_llm(prompt), docs=retrieved)
    if result.blocked:
        ...

Execution rules
---------------
* Guards that rewrite text (``transforms=True``, e.g. PII redaction) run first,
  in order, each on the previous one's output. The rest run in parallel on the
  original text, so a detector never sees text another guard has altered.
* The stage decision is the strictest of all guard decisions
  (block > review > allow).
* ``run()`` calls the LLM only if the input stage is not blocked, and passes it
  the rewritten (safe) text.
* A guard that raises is treated according to ``on_error``: ``"block"``
  (default, fail closed), ``"review"``, or ``"raise"``.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from .models import Decision, merge_decisions

Context = Dict[str, Any]


@dataclass
class GuardResult:
    """What one guard decided about one piece of text."""

    guard: str
    decision: Decision
    text: Optional[str] = None      # rewritten text, for guards that transform
    detail: Any = None              # the guard's native result object, if any
    error: Optional[str] = None     # set when the guard raised and on_error applied


class Guard:
    """Base class for a pipeline step. Subclass it, or use FunctionGuard."""

    name: str = "guard"
    transforms: bool = False        # True if check() may return rewritten text

    def check(self, text: str, context: Context) -> GuardResult:  # pragma: no cover
        raise NotImplementedError


GuardOutput = Union[bool, str, GuardResult, Tuple[str, Optional[str]], None]


class FunctionGuard(Guard):
    """Turn any function into a guard.

    The function receives ``(text, context)`` (or just ``text`` if it takes one
    argument) and may return:

    * ``True`` / ``False``: allow / block
    * ``"allow" | "review" | "block"``
    * ``(decision, rewritten_text)``: for a guard that also redacts
    * a :class:`GuardResult`
    """

    def __init__(self, name: str, fn: Callable[..., GuardOutput], *, transforms: bool = False):
        self.name = name
        self.fn = fn
        self.transforms = transforms
        try:
            import inspect

            params = inspect.signature(fn).parameters.values()
            positional = [p for p in params if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
            required = [p for p in positional if p.default is p.empty]
            # Pass context only to functions that require a second argument, so
            # helpers like `lambda text, limit=10: ...` keep working.
            self._takes_context = len(required) >= 2
        except (TypeError, ValueError):
            self._takes_context = False

    def check(self, text: str, context: Context) -> GuardResult:
        out = self.fn(text, context) if self._takes_context else self.fn(text)
        if isinstance(out, GuardResult):
            return out
        if isinstance(out, bool):
            return GuardResult(self.name, "allow" if out else "block")
        if isinstance(out, tuple):
            decision, rewritten = out
            return GuardResult(self.name, _decision(decision, self.name), text=rewritten)
        if out is None:
            return GuardResult(self.name, "allow")
        return GuardResult(self.name, _decision(out, self.name))


def _decision(value: Any, name: str) -> Decision:
    if value in ("allow", "review", "block"):
        return value  # type: ignore[return-value]
    raise ValueError(f"guard {name!r} returned {value!r}; expected allow, review or block")


@dataclass
class StageReport:
    """Result of running one stage (input or output) of a pipeline."""

    decision: Decision
    text: str                                   # final text after transforming guards
    results: List[GuardResult] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.decision == "block"

    def result(self, guard_name: str) -> Optional[GuardResult]:
        return next((r for r in self.results if r.guard == guard_name), None)


@dataclass
class RunResult:
    """Result of Pipeline.run(): input checks, the LLM call, output checks."""

    input: StageReport
    output: Optional[StageReport] = None        # None when the LLM was not called
    response: Optional[str] = None              # raw LLM response

    @property
    def decision(self) -> Decision:
        return merge_decisions(self.input.decision, self.output.decision if self.output else None)

    @property
    def blocked(self) -> bool:
        return self.decision == "block"

    @property
    def safe_response(self) -> Optional[str]:
        """The response after output guards (e.g. PII redacted), or None if blocked."""
        if self.output is None or self.output.blocked:
            return None
        return self.output.text


class Pipeline:
    """An ordered set of input guards and output guards."""

    def __init__(self, input: Sequence[Guard] = (), output: Sequence[Guard] = (), *,
                 on_error: str = "block", max_workers: int = 4):
        if on_error not in ("block", "review", "raise"):
            raise ValueError("on_error must be 'block', 'review' or 'raise'")
        self.input = list(input)
        self.output = list(output)
        self.on_error = on_error
        self.max_workers = max_workers

    def __repr__(self) -> str:
        names = lambda guards: [g.name for g in guards]  # noqa: E731
        return f"Pipeline(input={names(self.input)}, output={names(self.output)})"

    # -- composition ---------------------------------------------------------
    def replace(self, name: str, guard: Guard) -> "Pipeline":
        """Return a copy with the guard called `name` swapped for `guard`."""
        swap = lambda guards: [guard if g.name == name else g for g in guards]  # noqa: E731
        if not any(g.name == name for g in self.input + self.output):
            raise KeyError(f"no guard named {name!r} in {self!r}")
        return Pipeline(swap(self.input), swap(self.output), on_error=self.on_error,
                        max_workers=self.max_workers)

    def without(self, *names: str) -> "Pipeline":
        """Return a copy without the named guards."""
        keep = lambda guards: [g for g in guards if g.name not in names]  # noqa: E731
        return Pipeline(keep(self.input), keep(self.output), on_error=self.on_error,
                        max_workers=self.max_workers)

    # -- execution -------------------------------------------------------------
    def check_input(self, text: str, **context: Any) -> StageReport:
        return self._stage(self.input, text, context)

    def check_output(self, text: str, *, docs: Optional[Sequence[str]] = None, **context: Any) -> StageReport:
        if docs is not None:
            context["docs"] = list(docs)
        return self._stage(self.output, text, context)

    def run(self, prompt: str, *, llm: Callable[[str], str],
            docs: Optional[Sequence[str]] = None, **context: Any) -> RunResult:
        """Check the prompt, call `llm` with the safe prompt, check the response."""
        inbound = self.check_input(prompt, **context)
        if inbound.blocked:
            return RunResult(input=inbound)
        response = llm(inbound.text)
        outbound = self.check_output(response, docs=docs, **context)
        return RunResult(input=inbound, output=outbound, response=response)

    def _stage(self, guards: Sequence[Guard], text: str, context: Context) -> StageReport:
        results: List[GuardResult] = []
        current = text
        for guard in (g for g in guards if g.transforms):
            result = self._call(guard, current, context)
            results.append(result)
            if result.text is not None:
                current = result.text
        detectors = [g for g in guards if not g.transforms]
        if detectors:
            with ThreadPoolExecutor(max_workers=max(1, min(self.max_workers, len(detectors)))) as pool:
                results.extend(pool.map(lambda g: self._call(g, text, context), detectors))
        decision = merge_decisions(*(r.decision for r in results)) if results else "allow"
        return StageReport(decision=decision, text=current, results=results)

    def _call(self, guard: Guard, text: str, context: Context) -> GuardResult:
        try:
            return guard.check(text, context)
        except Exception as exc:  # noqa: BLE001 - policy decides what a failure means
            if self.on_error == "raise":
                raise
            return GuardResult(guard.name, self.on_error, error=f"{type(exc).__name__}: {exc}")  # type: ignore[arg-type]
