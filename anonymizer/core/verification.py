"""Mandatory verification pass: re-scan masked output before delivery.

A detection at/above threshold in the masked text is a leak UNLESS:
  * the policy for that (target, type) is `keep` (intentionally retained), or
  * the detected span lies fully inside a replacement span (format-preserving
    ciphertexts legitimately still look like cards/phones — they are
    transformation artifacts, not leaks).
Any leak ⇒ status LEAK_DETECTED, quarantined, never delivered.
"""
from __future__ import annotations

import bisect

from .detection import Detector
from .types import JobSpec, LeakFinding, PolicyTable, Replacement, Strategy


def verify(
    masked_text: str,
    replacements: list[Replacement],
    policy: PolicyTable,
    job: JobSpec,
    detector: Detector,
) -> list[LeakFinding]:
    # Replacement ranges are already sorted by new_start and non-overlapping,
    # so a detected span is "inside a replacement" iff it fits within the one
    # range whose start is the greatest start <= the detection's start.
    # Binary-search that range instead of scanning all of them (O(k log n)
    # not O(k*n) — the linear scan is quadratic and hangs when a document
    # yields tens of thousands of findings).
    starts = [r.new_start for r in replacements]
    ends = [r.new_end for r in replacements]

    def inside_replacement(start: int, end: int) -> bool:
        i = bisect.bisect_right(starts, start) - 1
        return i >= 0 and end <= ends[i]

    leaks: list[LeakFinding] = []
    for f in detector.detect(masked_text):
        if f.confidence < job.threshold_for(f.entity_type):
            continue
        entry = policy.lookup(job.target, f.entity_type)
        if entry.strategy == Strategy.KEEP:
            continue
        if inside_replacement(f.start, f.end):
            continue  # inside a replacement: expected artifact (e.g. FPE output)
        leaks.append(
            LeakFinding(
                entity_type=f.entity_type, start=f.start, end=f.end, confidence=f.confidence
            )
        )
    return leaks
