"""Span resolution and right-to-left application.

Offsets from detection are the single source of truth. This module never
re-detects or shifts spans heuristically; it only merges/normalizes the
provided findings and applies replacements so offsets stay valid.
"""
from __future__ import annotations

from .types import Finding, JobSpec, Replacement


def filter_by_threshold(findings: list[Finding], job: JobSpec) -> list[Finding]:
    """Keep findings at/above the (per-type) confidence threshold.

    Below-threshold findings are left untouched ('keep' direction); the
    threshold default of 0.5 errs toward masking — over-masking is safe.
    """
    return [f for f in findings if f.confidence >= job.threshold_for(f.entity_type)]


def resolve_overlaps(findings: list[Finding]) -> list[Finding]:
    """Produce a non-overlapping, sorted list of spans to replace.

    Rules:
      * overlapping same-type spans are merged (union);
      * nested different-type spans: the OUTERMOST span wins with the outer
        type (an ADDRESS containing a PERSON masks as ADDRESS);
      * partially overlapping different-type spans are merged to their union
        under the leftmost/outermost span's type (conservative: masks more).
    Confidence of a merged span is the max of its parts.
    """
    if not findings:
        return []
    ordered = sorted(findings, key=lambda f: (f.start, -f.end))
    out: list[Finding] = []
    cur = ordered[0]
    for f in ordered[1:]:
        if f.start >= cur.end:  # disjoint
            out.append(cur)
            cur = f
            continue
        # Overlap. Nested (f.end <= cur.end): keep cur as-is (outer wins).
        # Partial: extend cur to the union; cur's (outer) type wins.
        cur = Finding(
            entity_type=cur.entity_type,
            start=cur.start,
            end=max(cur.end, f.end),
            confidence=max(cur.confidence, f.confidence),
            tier=cur.tier,
            validated=cur.validated or f.validated,
        )
    out.append(cur)
    return out


def apply_replacements(
    text: str, plan: list[tuple[Finding, str, str]], *, redact_originals: bool
) -> tuple[str, list[Replacement]]:
    """Apply (finding, replacement_text, strategy_name) right-to-left.

    Applying from the highest offset first means earlier spans' offsets are
    never invalidated by a length-changing replacement.

    Returns the masked text and Replacement records carrying both original
    and new offsets. When redact_originals is True (training mode) the
    original surface text is NOT recorded anywhere.
    """
    ordered = sorted(plan, key=lambda p: p[0].start)
    for (a, _, _), (b, _, _) in zip(ordered, ordered[1:]):
        if b.start < a.end:
            raise ValueError("apply_replacements requires non-overlapping spans")
    if ordered and ordered[-1][0].end > len(text):
        raise ValueError("span exceeds text length: offsets do not match canonical text")

    # Right-to-left application.
    masked = text
    for finding, rep_text, _ in reversed(ordered):
        masked = masked[: finding.start] + rep_text + masked[finding.end :]

    # New offsets via cumulative delta (equivalent to the RTL result).
    replacements: list[Replacement] = []
    delta = 0
    for finding, rep_text, strategy in ordered:
        new_start = finding.start + delta
        new_end = new_start + len(rep_text)
        replacements.append(
            Replacement(
                entity_type=finding.entity_type,
                strategy=strategy,
                orig_start=finding.start,
                orig_end=finding.end,
                new_start=new_start,
                new_end=new_end,
                replacement=rep_text,
                original=None if redact_originals else text[finding.start : finding.end],
            )
        )
        delta += len(rep_text) - (finding.end - finding.start)
    return masked, replacements
