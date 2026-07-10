"""Mandatory verification pass: re-scan masked output before delivery.

A detection at/above threshold in the masked text is a leak UNLESS:
  * the policy for that (target, type) is `keep` (intentionally retained), or
  * the detected span lies fully inside a replacement span (format-preserving
    ciphertexts legitimately still look like cards/phones — they are
    transformation artifacts, not leaks).
Any leak ⇒ status LEAK_DETECTED, quarantined, never delivered.
"""
from __future__ import annotations

from .detection import Detector
from .types import JobSpec, LeakFinding, PolicyTable, Replacement, Strategy


def verify(
    masked_text: str,
    replacements: list[Replacement],
    policy: PolicyTable,
    job: JobSpec,
    detector: Detector,
) -> list[LeakFinding]:
    replaced_ranges = [(r.new_start, r.new_end) for r in replacements]
    leaks: list[LeakFinding] = []
    for f in detector.detect(masked_text):
        if f.confidence < job.threshold_for(f.entity_type):
            continue
        entry = policy.lookup(job.target, f.entity_type)
        if entry.strategy == Strategy.KEEP:
            continue
        if any(f.start >= s and f.end <= e for s, e in replaced_ranges):
            continue  # inside a replacement: expected artifact (e.g. FPE output)
        leaks.append(
            LeakFinding(
                entity_type=f.entity_type, start=f.start, end=f.end, confidence=f.confidence
            )
        )
    return leaks
