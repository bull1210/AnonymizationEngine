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


class TestTemporalFalsePositives:
    """Dates and timestamps defeat the `formatted` heuristic: they carry the
    very dashes and spaces that make a digit run look dialable.
    `"date_captured": "2020-06-24 12:34:56"` yields the 10-digit run
    `2020-06-24 12`. A COCO annotation file full of these produced 3302 phantom
    PHONE "leaks", and the verification pass quarantined the file — 11 documents
    were withheld from delivery on one real run over a Kaggle dataset."""

    def test_timestamp_is_not_a_phone_number(self) -> None:
        assert _types('{"date_captured": "2020-06-24 12:34:56"}') == []

    def test_date_forms_are_not_phone_numbers(self) -> None:
        for text in (
            "created 2020-06-24 12:00:00 UTC",
            "window 2019/01/31 08:00:00",
            "run at 06/24/2020 11:45:30",
            "logged 24-06-2020 09:15:00",
        ):
            assert _types(text) == [], text

    def test_real_phone_numbers_still_detected(self) -> None:
        """The guard must not blind the safety net: verification exists to
        catch what detection missed, so a false negative here is a leak."""
        for text, surface in (
            ("call me on +91 98765 43210 today", "+91 98765 43210"),
            ("tel 415-555-2671", "415-555-2671"),
            ("contact 020 7946 0958", "020 7946 0958"),
        ):
            got = [g for g in _types(text) if g[0] == "PHONE"]
            assert len(got) == 1, text
            assert text[got[0][1]:got[0][2]] == surface

    def test_phone_at_end_of_text_still_detected(self) -> None:
        """Regression: the neighbour check compared with `in ":/."`, and the
        empty string (no character after the match) is a substring of every
        string — which silently rejected every phone number that ended a
        document."""
        assert [g[0] for g in _types("reach me on 415-555-2671")] == ["PHONE"]

    def test_valid_card_inside_a_date_context_still_detected(self) -> None:
        """A card is validated by Luhn, so it must survive next to a date."""
        got = _types("on 2020-06-24 he paid with 4532 0151 1283 0366")
        assert [g[0] for g in got] == ["CREDIT_CARD"]


class TestLinearTime:
    def test_many_matches_stay_fast(self) -> None:
        text = "Ravi +91 98765 43210 said hi. " * 40000  # ~40k phone matches, ~1MB
        t0 = time.perf_counter()
        found = RegexDetector().detect(text)
        elapsed = time.perf_counter() - t0
        assert len(found) == 40000
        assert elapsed < 3.0, f"RegexDetector took {elapsed:.1f}s — quadratic regression"
