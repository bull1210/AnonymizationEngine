"""Detectors for the verification pass.

RegexDetector = built-in Tier-1-style structured detector (always available).
HTTPDetector  = client for the real on-prem detection engine (Tier 1 + Tier 3
+ sampled NER) — used in production; same interface.
"""
from __future__ import annotations

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


class RegexDetector:
    """Structured-type detector. Validator-gated where possible (Luhn,
    Verhoeff) so confidence is meaningful. Priority order suppresses
    lower-priority matches overlapping an accepted higher-priority span
    (a credit card is not also a phone number)."""

    def detect(self, text: str) -> list[Finding]:
        accepted: list[Finding] = []
        taken: list[tuple[int, int]] = []
        for etype, pattern, conf in _PATTERNS:
            for m in pattern.finditer(text):
                start, end = m.start(), m.end()
                if any(s < end and start < e for s, e in taken):
                    continue
                surface = m.group()
                digits = "".join(c for c in surface if c.isdigit())
                if etype == "CREDIT_CARD" and not (13 <= len(digits) <= 19 and luhn_valid(digits)):
                    continue
                if etype == "AADHAAR" and not (len(digits) == 12 and verhoeff_valid(digits)):
                    continue
                if etype == "PHONE" and not 10 <= len(digits) <= 14:
                    continue
                accepted.append(
                    Finding(entity_type=etype, start=start, end=end, confidence=conf, tier="T1")
                )
                taken.append((start, end))
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
