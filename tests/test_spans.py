"""Offset integrity after right-to-left application (property-based) and
overlap/nesting resolution rules."""
import random
import string

from anonymizer.core.spans import apply_replacements, filter_by_threshold, resolve_overlaps
from anonymizer.core.types import Finding, JobSpec, Target

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st

    HAVE_HYPOTHESIS = True
except ImportError:
    HAVE_HYPOTHESIS = False


def _check_integrity(text: str, spans: list[tuple[int, int]], reps: list[str]) -> None:
    findings = [Finding("X", s, e, 0.9) for s, e in spans]
    plan = [(f, r, "test") for f, r in zip(findings, reps)]
    masked, replacements = apply_replacements(text, plan, redact_originals=False)

    # 1. Each replacement text sits exactly at its recorded new offsets.
    for r in replacements:
        assert masked[r.new_start : r.new_end] == r.replacement
        assert r.original == text[r.orig_start : r.orig_end]

    # 2. Untouched segments survive byte-for-byte, in order.
    ordered = sorted(zip(spans, reps), key=lambda p: p[0][0])
    expected = []
    cursor = 0
    for (s, e), rep in ordered:
        expected.append(text[cursor:s])
        expected.append(rep)
        cursor = e
    expected.append(text[cursor:])
    assert masked == "".join(expected)


def _random_case(rng: random.Random) -> tuple[str, list[tuple[int, int]], list[str]]:
    text = "".join(rng.choice(string.ascii_letters + "   .,") for _ in range(rng.randint(10, 400)))
    spans, cursor = [], 0
    while cursor < len(text) - 2 and len(spans) < 20:
        start = cursor + rng.randint(0, 25)
        end = start + rng.randint(1, 15)
        if end > len(text):
            break
        spans.append((start, end))
        cursor = end
    reps = ["".join(rng.choice("<>_ABCdef123") for _ in range(rng.randint(0, 12)))
            for _ in spans]
    return text, spans, reps


def test_offset_integrity_randomized():
    rng = random.Random(1234)
    for _ in range(300):
        text, spans, reps = _random_case(rng)
        if spans:
            _check_integrity(text, spans, reps)


if HAVE_HYPOTHESIS:

    @settings(max_examples=200, deadline=None)
    @given(data=st.data(), text=st.text(min_size=5, max_size=300))
    def test_offset_integrity_hypothesis(data, text):
        n = data.draw(st.integers(min_value=1, max_value=8))
        bounds = sorted(
            data.draw(
                st.lists(
                    st.integers(min_value=0, max_value=len(text)),
                    min_size=2 * n, max_size=2 * n,
                )
            )
        )
        spans = [
            (bounds[2 * i], bounds[2 * i + 1])
            for i in range(n)
            if bounds[2 * i] < bounds[2 * i + 1]
        ]
        # enforce strict disjointness
        spans = [s for i, s in enumerate(spans) if i == 0 or s[0] >= spans[i - 1][1]]
        if not spans:
            return
        reps = data.draw(
            st.lists(st.text(max_size=10), min_size=len(spans), max_size=len(spans))
        )
        _check_integrity(text, spans, reps)


def test_same_type_overlap_merges():
    f = resolve_overlaps([Finding("PERSON", 0, 10, 0.8), Finding("PERSON", 5, 15, 0.9)])
    assert len(f) == 1 and (f[0].start, f[0].end) == (0, 15) and f[0].confidence == 0.9


def test_nested_different_type_outer_wins():
    f = resolve_overlaps([Finding("ADDRESS", 0, 40, 0.9), Finding("PERSON", 10, 20, 0.95)])
    assert len(f) == 1
    assert f[0].entity_type == "ADDRESS" and (f[0].start, f[0].end) == (0, 40)


def test_partial_overlap_different_type_union():
    f = resolve_overlaps([Finding("ADDRESS", 0, 20, 0.9), Finding("PERSON", 15, 30, 0.95)])
    assert len(f) == 1
    assert f[0].entity_type == "ADDRESS" and (f[0].start, f[0].end) == (0, 30)


def test_disjoint_spans_untouched():
    f = resolve_overlaps([Finding("A", 0, 5, 0.9), Finding("B", 10, 15, 0.9)])
    assert len(f) == 2


def test_threshold_filter_per_type():
    job = JobSpec(job_id="j", target=Target.TRAINING, confidence_threshold=0.5,
                  type_thresholds={"PHONE": 0.9})
    fs = [Finding("PERSON", 0, 5, 0.6), Finding("PHONE", 6, 10, 0.6),
          Finding("PHONE", 11, 15, 0.95)]
    kept = filter_by_threshold(fs, job)
    assert [(f.entity_type, f.start) for f in kept] == [("PERSON", 0), ("PHONE", 11)]


def test_span_beyond_text_rejected():
    try:
        apply_replacements("short", [(Finding("X", 0, 99, 0.9), "r", "s")],
                           redact_originals=True)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_overlapping_plan_rejected():
    plan = [(Finding("X", 0, 5, 0.9), "a", "s"), (Finding("Y", 3, 8, 0.9), "b", "s")]
    try:
        apply_replacements("0123456789", plan, redact_originals=True)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
