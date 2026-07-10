"""Date parsing/formatting for generalization and per-document date shifting.

Tries an explicit format list first so the ORIGINAL format can be preserved on
output; falls back to dateutil (if installed) with ISO output. Unparseable
dates always fall back to a bare placeholder — never left untouched.
"""
from __future__ import annotations

from datetime import datetime, timedelta

_FORMATS = [
    "%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%d-%m-%Y", "%Y/%m/%d", "%d.%m.%Y",
    "%d %B %Y", "%d %b %Y", "%B %d, %Y", "%b %d, %Y", "%B %d %Y", "%b %d %Y",
    "%d %B, %Y", "%Y-%m-%dT%H:%M:%S", "%d/%m/%y", "%m/%d/%y",
]


def parse_date(surface: str) -> tuple[datetime, str | None] | None:
    s = surface.strip()
    for fmt in _FORMATS:
        try:
            return datetime.strptime(s, fmt), fmt
        except ValueError:
            continue
    try:  # optional dependency; core stays importable without it
        from dateutil import parser as _du  # type: ignore

        return _du.parse(s, fuzzy=False), None
    except Exception:
        return None


def shift_date(surface: str, days: int) -> str | None:
    """Shift a date surface by `days`, preserving its format when known."""
    parsed = parse_date(surface)
    if parsed is None:
        return None
    dt, fmt = parsed
    shifted = dt + timedelta(days=days)
    return shifted.strftime(fmt or "%Y-%m-%d")


def year_only(surface: str) -> str | None:
    parsed = parse_date(surface)
    if parsed is None:
        return None
    return str(parsed[0].year)
