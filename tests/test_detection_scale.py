"""RegexDetector: overlap-precedence correctness + linear-time regression.

The verification detector used to resolve overlaps with a per-match linear
scan of everything already accepted — O(matches^2), which hung the pipeline
on large documents (an 8 MB chat export with tens of thousands of matches).
"""
from __future__ import annotations

import time

from anonymizer.core.detection import RegexDetector


def _types(text: str):  # noqa: ANN202
    return [(f.entity_type, f.start, f.end) for f in RegexDetector().detect(text)]


class TestOverlapPrecedence:
    def test_card_beats_phone_on_same_digits(self) -> None:
        # a valid (Luhn) credit card must win over the phone pattern
        # formatted (grouped) card — a valid card in real text carries spaces
        got = _types("pay 4532 0151 1283 0366 today")
        assert got == [("CREDIT_CARD", 4, 23)]

    def test_disjoint_matches_all_kept_and_sorted(self) -> None:
        got = _types("ssn 123-45-6789 mail a@b.co ph 555-123-4567")
        kinds = [t for t, _, _ in got]
        assert "SSN" in kinds and "EMAIL" in kinds and "PHONE" in kinds
        assert got == sorted(got, key=lambda x: x[1])  # returned in position order

    def test_bare_digit_run_not_flagged_as_phone_or_card(self) -> None:
        # ML-dataset coordinates / ids: bare digit runs must NOT be PII —
        # this is what made numeric files false-quarantine by the thousands.
        assert _types('{"bbox": [123456789012], "id": 4111111111111111}') == []

    def test_spans_are_exact(self) -> None:
        text = "reach me at alice@example.com please"
        (etype, s, e), = [g for g in _types(text) if g[0] == "EMAIL"]
        assert text[s:e] == "alice@example.com"

    def test_invalid_card_not_detected(self) -> None:
        # fails Luhn -> not a card; 16 digits also isn't a valid phone (>14)
        assert _types("num 1234567812345678 x") == []


class TestLinearTime:
    def test_many_matches_stay_fast(self) -> None:
        text = "Ravi +91 98765 43210 said hi. " * 40000  # ~40k phone matches, ~1MB
        t0 = time.perf_counter()
        found = RegexDetector().detect(text)
        elapsed = time.perf_counter() - t0
        assert len(found) == 40000
        assert elapsed < 3.0, f"RegexDetector took {elapsed:.1f}s — quadratic regression"
