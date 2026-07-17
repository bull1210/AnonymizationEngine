"""Image box redaction — docs/11 Approach A, phase 1 (the render stage).

Input: an image, its OCR structure map (word spans → pixel boxes, produced
by ExtractionService's OCR extractor), and the char spans the policy says
must disappear. Output: a NEW image (originals are never touched) with those
words' pixels painted out — true redaction, the bytes are destroyed — and
every container channel stripped (EXIF, embedded thumbnails: a thumbnail
keeps the UNREDACTED image).

Fail-closed rules (docs/11 §7 — "not-confidently-clean never ships"):

- A masked span that overlaps NO word box is **unmappable**: we cannot
  destroy pixels we cannot locate, so NO output is written and the caller
  quarantines the file. Never "best effort" on pixels.
- Words *below the OCR confidence floor* may be misread PII ("Jhon Okafr"
  matches nothing). They are reported as ``review_regions`` so the caller
  routes the file to human review instead of shipping silently.
- Round-trip verification re-OCRs the redacted image and re-scans that text
  with the same ``RegexDetector`` used for text output; any finding ⇒
  the caller quarantines as LEAK_DETECTED, exactly like the text flow.

The geometry (span→box mapping, classification) is pure stdlib and always
importable; only ``paint`` needs Pillow — install with: pip install ".[image]".

Duck typing: ``word_spans`` items need ``.start .end .page .bbox .conf``
(ExtractionService's ``StructureMap.spans`` satisfies this); no cross-repo
import, the repos stay independent.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from anonymizer.core.detection import Finding, RegexDetector

#: Default OCR-confidence floor (confidences are normalized 0–1 by the
#: extractor). Below it a word is a review region. Tesseract's own scale puts
#: clearly-printed text at 0.85+; 0.60 catches smudges/handwriting without
#: flagging every scan. Per-run policy overrides come later (docs/11 §8).
DEFAULT_CONF_FLOOR = 0.60

#: Pixels of padding painted around each word box — OCR boxes hug glyphs
#: tightly and antialiased edges can survive an exact-box fill.
DEFAULT_PAD = 2


@dataclass(frozen=True)
class Region:
    """A pixel rectangle on one page/frame."""

    page: int
    bbox: tuple[int, int, int, int]  # x0, y0, x1, y1


@dataclass
class RedactionPlan:
    """Pure-geometry outcome: what to paint, what can't be, what needs eyes."""

    paint: list[Region] = field(default_factory=list)
    unmappable: list[tuple[int, int]] = field(default_factory=list)
    review_regions: list[Region] = field(default_factory=list)

    @property
    def mappable(self) -> bool:
        return not self.unmappable


def plan_redaction(
    word_spans: Iterable[object],
    masked_spans: Sequence[tuple[int, int]],
    *,
    conf_floor: float = DEFAULT_CONF_FLOOR,
    pad: int = DEFAULT_PAD,
) -> RedactionPlan:
    """Map masked char spans onto word boxes. Stdlib-only, fully testable.

    A word is painted when its span overlaps any masked span. A masked span
    overlapping no word is unmappable (fail closed — caller must not ship).
    Surviving words under ``conf_floor`` become review regions.
    """
    words = list(word_spans)
    plan = RedactionPlan()
    painted_idx: set[int] = set()
    for m_start, m_end in masked_spans:
        hit = False
        for i, word in enumerate(words):
            if word.start < m_end and m_start < word.end:  # type: ignore[attr-defined]
                hit = True
                if i not in painted_idx:
                    painted_idx.add(i)
                    x0, y0, x1, y1 = word.bbox  # type: ignore[attr-defined]
                    plan.paint.append(Region(
                        page=word.page,  # type: ignore[attr-defined]
                        bbox=(x0 - pad, y0 - pad, x1 + pad, y1 + pad),
                    ))
        if not hit:
            plan.unmappable.append((m_start, m_end))
    for i, word in enumerate(words):
        if i not in painted_idx and word.conf < conf_floor:  # type: ignore[attr-defined]
            plan.review_regions.append(
                Region(page=word.page, bbox=tuple(word.bbox))  # type: ignore[attr-defined,arg-type]
            )
    return plan


@dataclass
class ImageRedactionOutcome:
    status: str                       # "REDACTED" | "UNMAPPABLE_FINDING"
    plan: RedactionPlan
    out_path: str | None              # written only when status == "REDACTED"
    pages: int = 0


def redact_image(
    source_path: str | Path,
    out_path: str | Path,
    word_spans: Iterable[object],
    masked_spans: Sequence[tuple[int, int]],
    *,
    conf_floor: float = DEFAULT_CONF_FLOOR,
    pad: int = DEFAULT_PAD,
) -> ImageRedactionOutcome:
    """Plan + paint. Writes ``out_path`` (a NEW file) only when every masked
    span mapped to pixels; otherwise returns UNMAPPABLE_FINDING with nothing
    written, and the caller quarantines. Needs Pillow (".[image]" extra)."""
    plan = plan_redaction(word_spans, masked_spans, conf_floor=conf_floor, pad=pad)
    if not plan.mappable:
        return ImageRedactionOutcome(status="UNMAPPABLE_FINDING", plan=plan, out_path=None)
    pages = _paint(Path(source_path), Path(out_path), plan.paint)
    return ImageRedactionOutcome(status="REDACTED", plan=plan,
                                 out_path=str(out_path), pages=pages)


def _paint(src: Path, dst: Path, regions: list[Region]) -> int:
    try:
        from PIL import Image, ImageDraw, ImageSequence  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "image redaction needs Pillow — install with: pip install \".[image]\""
        ) from exc

    by_page: dict[int, list[Region]] = {}
    for r in regions:
        by_page.setdefault(r.page, []).append(r)

    frames: list[object] = []
    with Image.open(src) as img:
        for page_idx, frame in enumerate(ImageSequence.Iterator(img)):
            rgb = frame.convert("RGB")
            # Rebuild from raw pixels: guarantees EXIF, embedded thumbnails,
            # ICC blobs and every other container channel are gone — the
            # thumbnail trap is that it retains the UNREDACTED image.
            clean = Image.frombytes("RGB", rgb.size, rgb.tobytes())
            draw = ImageDraw.Draw(clean)
            for region in by_page.get(page_idx, []):
                x0, y0, x1, y1 = region.bbox
                draw.rectangle(
                    (max(0, x0), max(0, y0),
                     min(clean.width - 1, x1), min(clean.height - 1, y1)),
                    fill=(0, 0, 0),
                )
            frames.append(clean)

    dst.parent.mkdir(parents=True, exist_ok=True)
    first, rest = frames[0], frames[1:]
    if rest:  # multi-frame TIFF stays multi-frame
        first.save(dst, save_all=True, append_images=rest)  # type: ignore[attr-defined]
    else:
        first.save(dst)  # type: ignore[attr-defined]
    return len(frames)


def verify_redacted_image(
    redacted_path: str | Path, reocr: Callable[[Path], str]
) -> list[Finding]:
    """Round-trip verification: re-OCR the redacted image (``reocr`` is
    injected — the console passes the extraction engine, keeping this repo
    OCR-free) and re-scan with the SAME structured detector the text flow
    uses. Non-empty result ⇒ caller quarantines as LEAK_DETECTED.

    What OCR cannot read, this cannot catch (docs/11 §1) — which is exactly
    why unmappable findings and low-confidence regions fail closed above
    instead of leaning on this check.
    """
    text = reocr(Path(redacted_path))
    if not text.strip():
        return []
    return RegexDetector().detect(text)
