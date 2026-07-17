"""Image box-redaction tests (docs/11 phase 1).

The geometry and fail-closed classification are stdlib-only and always run.
Painting/container-strip tests need Pillow and skip cleanly without it,
matching the repo's optional-extra test philosophy.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
from anonymizer.imageredact import (
    DEFAULT_CONF_FLOOR,
    Region,
    plan_redaction,
    redact_image,
    verify_redacted_image,
)


@dataclass(frozen=True)
class W:  # duck-typed word span, mirrors ExtractionService's WordSpan
    start: int
    end: int
    page: int
    bbox: tuple[int, int, int, int]
    conf: float


#          0123456789012345678901234567
# text  = "Patient Priya Sharma x99blur"
WORDS = [
    W(0, 7, 0, (10, 10, 80, 22), 0.98),    # Patient
    W(8, 13, 0, (90, 10, 140, 22), 0.97),  # Priya
    W(14, 20, 0, (150, 10, 210, 22), 0.95),  # Sharma
    W(21, 28, 0, (10, 40, 80, 52), 0.30),  # x99blur — low confidence
]


class TestPlanRedaction:
    def test_masked_span_paints_overlapping_words_with_padding(self) -> None:
        plan = plan_redaction(WORDS, [(8, 20)], pad=2)  # "Priya Sharma"
        assert plan.mappable
        assert plan.paint == [
            Region(0, (88, 8, 142, 24)),
            Region(0, (148, 8, 212, 24)),
        ]

    def test_partial_overlap_still_paints_whole_word(self) -> None:
        plan = plan_redaction(WORDS, [(11, 16)])  # "ya Sh" straddles two words
        assert [r.bbox[0] for r in plan.paint] == [88, 148]

    def test_unmappable_span_fails_closed(self) -> None:
        plan = plan_redaction(WORDS, [(100, 110)])
        assert not plan.mappable
        assert plan.unmappable == [(100, 110)]

    def test_low_confidence_unpainted_word_needs_review(self) -> None:
        plan = plan_redaction(WORDS, [(8, 13)], conf_floor=DEFAULT_CONF_FLOOR)
        assert plan.review_regions == [Region(0, (10, 40, 80, 52))]

    def test_low_confidence_word_that_is_painted_needs_no_review(self) -> None:
        plan = plan_redaction(WORDS, [(21, 28)])
        assert plan.review_regions == []
        assert plan.paint[0].page == 0

    def test_word_painted_once_even_under_two_spans(self) -> None:
        plan = plan_redaction(WORDS, [(8, 13), (8, 20)])
        assert len([r for r in plan.paint if r.bbox[0] == 88]) == 1


class TestRedactImageFailClosed:
    def test_unmappable_writes_nothing(self, tmp_path: Path) -> None:
        src = tmp_path / "scan.png"
        src.write_bytes(b"src")
        out = tmp_path / "out" / "scan.png"
        outcome = redact_image(src, out, WORDS, [(500, 510)])
        assert outcome.status == "UNMAPPABLE_FINDING"
        assert outcome.out_path is None
        assert not out.exists()
        assert src.read_bytes() == b"src"  # original untouched, always


class TestVerify:
    def test_clean_reocr_yields_no_findings(self, tmp_path: Path) -> None:
        p = tmp_path / "redacted.png"
        p.write_bytes(b"x")
        assert verify_redacted_image(p, lambda _: "Patient [REDACTED] visited") == []

    def test_leaked_structured_pii_is_found(self, tmp_path: Path) -> None:
        p = tmp_path / "redacted.png"
        p.write_bytes(b"x")
        findings = verify_redacted_image(p, lambda _: "call me at john.doe@corp.com")
        assert any(f.entity_type == "EMAIL" for f in findings)

    def test_empty_reocr_is_clean(self, tmp_path: Path) -> None:
        p = tmp_path / "redacted.png"
        p.write_bytes(b"x")
        assert verify_redacted_image(p, lambda _: "  ") == []


class TestPaintingWithPillow:
    def test_paint_destroys_pixels_and_strips_exif(self, tmp_path: Path) -> None:
        PIL = pytest.importorskip("PIL")  # noqa: N806
        from PIL import Image

        src = tmp_path / "scan.jpg"
        img = Image.new("RGB", (220, 60), "white")
        exif = Image.Exif()
        exif[0x010E] = "patient chart — J. Doe"  # ImageDescription
        img.save(src, exif=exif)

        out = tmp_path / "out.jpg"
        outcome = redact_image(src, out, WORDS, [(8, 20)])
        assert outcome.status == "REDACTED"
        assert outcome.pages == 1

        with Image.open(out) as red:
            assert dict(red.getexif()) == {}, "EXIF must not survive redaction"
            # center of "Priya"'s box is painted black; far corner is not
            assert red.getpixel((115, 16)) == (0, 0, 0)
            assert red.getpixel((215, 55)) == (255, 255, 255)

    def test_multiframe_tiff_keeps_frames_and_paints_right_page(
        self, tmp_path: Path
    ) -> None:
        PIL = pytest.importorskip("PIL")  # noqa: N806
        from PIL import Image, ImageSequence

        src = tmp_path / "scan.tif"
        f0 = Image.new("RGB", (100, 40), "white")
        f1 = Image.new("RGB", (100, 40), "white")
        f0.save(src, save_all=True, append_images=[f1])

        words = [W(0, 4, 1, (10, 10, 40, 20), 0.9)]  # word lives on page 1
        out = tmp_path / "out.tif"
        outcome = redact_image(src, out, words, [(0, 4)])
        assert outcome.pages == 2
        with Image.open(out) as red:
            frames = [fr.convert("RGB") for fr in ImageSequence.Iterator(red)]
            assert frames[0].getpixel((20, 15)) == (255, 255, 255)
            assert frames[1].getpixel((20, 15)) == (0, 0, 0)
