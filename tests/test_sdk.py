"""Offline unit tests — a fake Transport is injected; no network, no keys."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ylemis import (InvalidAPIKey, MissingKey, QuotaExceeded, ServiceBusy,
                    TrustEngine, merge_decisions)
from ylemis._http import Transport
from ylemis.exceptions import STATUS_MAP


PII_SCAN_RESPONSE = {
    "decision": "block",
    "risk_level": "critical",
    "entities": [{
        "type": "AADHAAR", "start": 20, "end": 34, "text_preview": "XXXX-…-9012",
        "confidence": 1.0, "source": "deterministic", "method": "deterministic",
        "recognizer": "aadhaar", "format_validated": True, "severity": "critical",
    }],
    "redacted_text": "my aadhaar card is [AADHAAR]",
    "counts": {"AADHAAR": 1},
    "latency_ms": 9.4,
    "model_version": "1.0",
    "hybrid": True,
    "quota_remaining": 41,
}


class FakeTransport(Transport):
    """Records requests; replays canned responses/exceptions per (method, path)."""

    def __init__(self):
        super().__init__("https://api.test")
        self.calls = []
        self.responses = {}

    def request(self, method, path, *, api_key=None, payload=None, product=None):
        self.calls.append({"method": method, "path": path, "api_key": api_key,
                           "payload": payload, "product": product})
        result = self.responses[(method, path)]
        if isinstance(result, Exception):
            raise result
        return result


def engine_with_fake(**kw) -> tuple[TrustEngine, FakeTransport]:
    engine = TrustEngine(**kw)
    fake = FakeTransport()
    engine._transport = fake
    for client in (engine.pii, engine.injection, engine.groundcheck):
        client._transport = fake
    return engine, fake


class TestKeyRouting(unittest.TestCase):
    def test_single_key_used_for_all_products(self):
        engine, fake = engine_with_fake(api_key="sk_live_one")
        fake.responses[("POST", "/pii-shield/v1/scan")] = PII_SCAN_RESPONSE
        fake.responses[("POST", "/injection-guard/v1/score")] = {"decision": "allow"}
        engine.check_input("hello")
        self.assertEqual({c["api_key"] for c in fake.calls}, {"sk_live_one"})

    def test_per_product_keys_override(self):
        engine, fake = engine_with_fake(api_key="sk_live_default",
                                        keys={"injection-guard": "sk_live_inj"})
        fake.responses[("POST", "/injection-guard/v1/score")] = {"decision": "allow"}
        engine.injection.score("hi")
        self.assertEqual(fake.calls[0]["api_key"], "sk_live_inj")

    def test_missing_key_raises_and_check_skips(self):
        engine, fake = engine_with_fake(keys={"pii-shield": "sk_live_p"})
        with self.assertRaises(MissingKey):
            engine.injection.score("hi")
        fake.responses[("POST", "/pii-shield/v1/scan")] = PII_SCAN_RESPONSE
        report = engine.check_input("hi")   # injection not configured -> skipped
        self.assertEqual(report.skipped, ["injection-guard"])
        self.assertEqual(report.decision, "block")  # PII decision still applies

    def test_repr_never_leaks_keys(self):
        engine, _ = engine_with_fake(api_key="sk_live_secret")
        self.assertNotIn("sk_live_secret", repr(engine))


class TestPIIContract(unittest.TestCase):
    def test_scan_parses_exact_shape(self):
        engine, fake = engine_with_fake(api_key="k")
        fake.responses[("POST", "/pii-shield/v1/scan")] = PII_SCAN_RESPONSE
        r = engine.pii.scan("my aadhaar card is 2345 6789 9012")
        self.assertTrue(r.has_pii)
        self.assertEqual(r.entities[0].type, "AADHAAR")
        self.assertTrue(r.entities[0].format_validated)
        self.assertEqual(r.quota_remaining, 41)
        self.assertEqual(r.raw["hybrid"], True)
        self.assertEqual(fake.calls[0]["payload"],
                         {"text": "my aadhaar card is 2345 6789 9012", "redaction_mode": "mask"})

    def test_usage(self):
        engine, fake = engine_with_fake(api_key="k")
        fake.responses[("GET", "/pii-shield/v1/usage")] = {
            "plan": "pro", "quota": 100000, "used": 1234, "unlimited": False}
        u = engine.pii.usage()
        self.assertEqual((u.plan, u.used), ("pro", 1234))


class TestDecisions(unittest.TestCase):
    def test_merge_most_restrictive_wins(self):
        self.assertEqual(merge_decisions("allow", "review", "block"), "block")
        self.assertEqual(merge_decisions("allow", None, "review"), "review")
        self.assertEqual(merge_decisions(), "allow")

    def test_check_output_skips_groundcheck_without_docs(self):
        engine, fake = engine_with_fake(api_key="k")
        fake.responses[("POST", "/pii-shield/v1/scan")] = PII_SCAN_RESPONSE
        report = engine.check_output("some model answer")   # no docs
        self.assertIsNone(report.groundcheck)
        self.assertNotIn("groundcheck", report.skipped)     # not skipped-for-key; simply N/A

    def test_scan_sugar_merges_both_hooks(self):
        engine, fake = engine_with_fake(api_key="k")
        fake.responses[("POST", "/pii-shield/v1/scan")] = PII_SCAN_RESPONSE
        fake.responses[("POST", "/injection-guard/v1/score")] = {"decision": "allow", "score": 0.01}
        fake.responses[("POST", "/groundcheck/v1/check")] = {"label": "hallucinated", "p_grounded": 0.2}
        report = engine.scan(prompt="p", response="r", docs=["d"])
        self.assertEqual(report.decision, "block")
        self.assertIsNotNone(report.groundcheck)
        self.assertEqual(report.groundcheck.decision, "review")

    def test_groundcheck_locked_request_shape(self):
        engine, fake = engine_with_fake(api_key="k")
        fake.responses[("POST", "/groundcheck/v1/check")] = {
            "label": "grounded", "p_grounded": 0.97, "threshold": 0.5,
            "engine": "model", "latency_ms": 12.0, "quota_remaining": 99}
        r = engine.groundcheck.check("Paris is the capital.", ["Paris is the capital of France."])
        self.assertTrue(r.grounded)
        self.assertEqual(r.decision, "allow")
        self.assertEqual(fake.calls[0]["payload"], {
            "source": "Paris is the capital of France.", "answer": "Paris is the capital.",
            "question": "", "threshold": 0.5, "granular": False})


class TestErrorMapping(unittest.TestCase):
    def test_status_map_covers_contract(self):
        self.assertIs(STATUS_MAP[401], InvalidAPIKey)
        self.assertIs(STATUS_MAP[402], QuotaExceeded)
        self.assertIs(STATUS_MAP[503], ServiceBusy)

    def test_quota_exceeded_surfaces(self):
        engine, fake = engine_with_fake(api_key="k")
        fake.responses[("POST", "/pii-shield/v1/scan")] = QuotaExceeded(
            "quota exceeded", status=402, product="pii-shield")
        with self.assertRaises(QuotaExceeded):
            engine.pii.scan("text")


class TestProvisionalAdapters(unittest.TestCase):
    def test_injection_decision_derivation(self):
        engine, fake = engine_with_fake(api_key="k")
        for raw, expected in [({"decision": "block"}, "block"),
                              ({"blocked": True}, "block"),
                              ({"label": "malicious"}, "review"),
                              ({"score": 0.1}, "allow")]:
            fake.responses[("POST", "/injection-guard/v1/score")] = raw
            self.assertEqual(engine.injection.score("x").decision, expected, raw)

    def test_groundcheck_payload_override(self):
        engine, fake = engine_with_fake(api_key="k")
        fake.responses[("POST", "/groundcheck/v1/check")] = {"decision": "allow"}
        engine.groundcheck.check("ans", payload={"custom": "shape"})
        self.assertEqual(fake.calls[0]["payload"], {"custom": "shape"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
