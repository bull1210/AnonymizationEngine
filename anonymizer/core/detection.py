"""Detectors for the verification pass.

RegexDetector = built-in Tier-1-style structured detector (always available).
HTTPDetector  = client for the real on-prem detection engine (Tier 1 + Tier 3
+ sampled NER) — used in production; same interface.
"""
from __future__ import annotations

import bisect
import json
import re
import urllib.request
from typing import Protocol

from .checkdigits import luhn_valid, verhoeff_valid
from .types import Finding


class Detector(Protocol):
    def detect(self, text: str) -> list[Finding]: ...


_PATTERNS: list[tuple[str, re.Pattern, float]] = [
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), 0.97),
    ("CREDIT_CARD", re.compile(r"(?<![\dA-Za-z_])(?:\d[ \-]?){12,18}\d(?![\dA-Za-z_])"), 0.95),
    ("AADHAAR", re.compile(r"(?<![\dA-Za-z_])\d{4}[ \-]?\d{4}[ \-]?\d{4}(?![\dA-Za-z_])"), 0.95),
    ("SSN", re.compile(r"(?<![\dA-Za-z_])\d{3}-\d{2}-\d{4}(?![\dA-Za-z_])"), 0.9),
    ("PAN", re.compile(r"(?<![A-Za-z0-9_])[A-Z]{5}\d{4}[A-Z](?![A-Za-z0-9_])"), 0.9),
    (
        "PHONE",
        re.compile(r"(?<![\dA-Za-z_])(?:\+\d{1,3}[ \-]?)?(?:\d[ \-]?){9,11}\d(?![\dA-Za-z_])"),
        0.7,
    ),
]


#: Dates and timestamps are the other big source of digit-run false positives,
#: and the `formatted` guard below cannot catch them: a date carries exactly the
#: dashes and spaces that make a digit run "look like" a phone number.
#: `"date_captured": "2020-06-24 12:34:56"` yields the 10-digit run
#: `2020-06-24 12` — formatted, in range, and utterly not a phone. One COCO
#: annotation file quarantined on 3302 of these.
_DATE_LIKE = re.compile(
    r"""^(?:
          \d{4}[-/. ]\d{1,2}[-/. ]\d{1,2}    # 2020-06-24, 2020/06/24
        | \d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}    # 24-06-2020, 06/24/20
    )""",
    re.VERBOSE,
)


def _is_temporal(text: str, start: int, end: int, surface: str) -> bool:
    """True when a digit run is part of a date or clock time, not a number
    someone could dial. Checked on the surface AND its immediate neighbours:
    the run `2020-06-24 12` is only recognisable as a timestamp by the `:`
    that follows it."""
    if _DATE_LIKE.match(surface):
        return True
    # A clock time continues through ':' on either side (12:34:56); a date or
    # version string continues through '/' or '.'. Compare against a set, not
    # with `in ":/."` — an empty neighbour (start/end of text) is a substring of
    # any string, which would reject every phone number that ends a document.
    neighbours = {"/", ":", "."}
    before = text[start - 1] if start > 0 else ""
    after = text[end] if end < len(text) else ""
    return before in neighbours or after in neighbours


class RegexDetector:
    """Structured-type detector. Validator-gated where possible (Luhn,
    Verhoeff) so confidence is meaningful. Priority order suppresses
    lower-priority matches overlapping an accepted higher-priority span
    (a credit card is not also a phone number)."""

    def detect(self, text: str) -> list[Finding]:
        # Collect every validated candidate first, tagged with its pattern's
        # priority rank; then resolve overlaps high-priority-first. The
        # overlap test bisects a sorted list of accepted intervals instead of
        # scanning them all — the old per-match linear scan was O(matches^2)
        # and took ~35s on a chat export with tens of thousands of matches.
        cands: list[tuple[int, int, int, str, float]] = []  # start, end, rank, type, conf
        for rank, (etype, pattern, conf) in enumerate(_PATTERNS):
            for m in pattern.finditer(text):
                surface = m.group()
                digits = "".join(c for c in surface if c.isdigit())
                # Require phone/card matches to look FORMATTED (a separator or a
                # leading +). A bare run of digits is far more likely a
                # coordinate, id, or measurement than a phone/card — this is
                # what made numeric data files (ML datasets, logs) false-
                # quarantine by the thousands. Real phones/cards in text
                # almost always carry spaces, dashes, or a country-code +.
                formatted = ("+" in surface) or any(c in " -()." for c in surface)
                # ...but "formatted" is exactly what a date looks like, so the
                # numeric types also have to rule out dates and clock times.
                if etype in ("CREDIT_CARD", "AADHAAR", "PHONE") and _is_temporal(
                    text, m.start(), m.end(), surface
                ):
                    continue
                if etype == "CREDIT_CARD" and not (
                    formatted and 13 <= len(digits) <= 19 and luhn_valid(digits)
                ):
                    continue
                if etype == "AADHAAR" and not (
                    formatted and len(digits) == 12 and verhoeff_valid(digits)
                ):
                    continue
                if etype == "PHONE" and not (formatted and 10 <= len(digits) <= 14):
                    continue
                cands.append((m.start(), m.end(), rank, etype, conf))

        # Priority order (lower rank wins), then position — same precedence as
        # the original pattern-by-pattern greedy.
        cands.sort(key=lambda c: (c[2], c[0]))
        starts: list[int] = []                 # accepted starts, kept sorted
        intervals: list[tuple[int, int]] = []  # parallel (start, end), sorted by start
        accepted: list[Finding] = []
        for start, end, _rank, etype, conf in cands:
            i = bisect.bisect_right(starts, start)
            overlaps = (i > 0 and intervals[i - 1][1] > start) or (
                i < len(intervals) and intervals[i][0] < end
            )
            if overlaps:
                continue
            starts.insert(i, start)
            intervals.insert(i, (start, end))
            accepted.append(
                Finding(entity_type=etype, start=start, end=end, confidence=conf, tier="T1")
            )
        return sorted(accepted, key=lambda f: f.start)


class HTTPDetector:
    """Calls the on-prem detection engine: POST {url}/detect {"text": ...} ->
    {"findings": [{entity_type,start,end,confidence,tier}, ...]}"""

    def __init__(self, url: str, timeout: float = 30.0) -> None:
        self._url = url.rstrip("/") + "/detect"
        self._timeout = timeout

    def detect(self, text: str) -> list[Finding]:
        body = json.dumps({"text": text}).encode()
        req = urllib.request.Request(
            self._url, data=body, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310 (on-prem)
            payload = json.loads(resp.read().decode())
        out = []
        for d in payload.get("findings", []):
            out.append(
                Finding(
                    entity_type=str(d["entity_type"]).upper(),
                    start=int(d["start"]),
                    end=int(d["end"]),
                    confidence=float(d.get("confidence", 1.0)),
                    tier=str(d.get("tier", "T1")),
                )
            )
        return out


class CompositeDetector:
    def __init__(self, *detectors: Detector) -> None:
        self._detectors = detectors

    def detect(self, text: str) -> list[Finding]:
        out: list[Finding] = []
        for d in self._detectors:
            out.extend(d.detect(text))
        return sorted(out, key=lambda f: f.start)
