"""Per-strategy replacement text computation.

Training-mode strategies are irreversible: indexed placeholders scoped to one
document, generalization, and per-document date shifting. No salts, no keys,
no mapping storage — the DocContext lives only for the duration of one
document and is never persisted.
"""
from __future__ import annotations

import secrets as _secrets
from dataclasses import dataclass, field

from . import dates
from .canonicalize import canonicalize, entity_class
from .types import PolicyEntry

# Default placeholder token names per entity type (else the type itself).
_TOKEN_NAME = {
    "PERSON": "NAME",
    "ORGANIZATION": "ORG",
    "LOCATION": "LOC",
    "ADDRESS": "ADDR",
}

# Types carrying identity: indexed so local coreference survives.
# Types without identity semantics (MEDICATION, DIAGNOSIS) default to bare tokens.
_UNINDEXED_DEFAULT = {"MEDICATION", "DIAGNOSIS", "TREATMENT", "PROCEDURE"}


@dataclass
class DocContext:
    """Per-document state. Index counters reset with each new document so no
    placeholder links entities across documents."""

    labels: dict = field(default_factory=dict)     # (token, canonical) -> label
    counters: dict = field(default_factory=dict)   # token -> last index
    date_shift_days: int | None = None

    def shift_days(self) -> int:
        if self.date_shift_days is None:
            # Cryptographically random, uniform ±365d excluding 0, applied to
            # every date in this document (intervals preserved). Stored
            # nowhere: unrecoverable by design.
            d = 0
            while d == 0:
                d = _secrets.randbelow(731) - 365
            self.date_shift_days = d
        return self.date_shift_days


def token_name(entity_type: str, entry: PolicyEntry) -> str:
    if entry.token:
        return entry.token.upper()
    return _TOKEN_NAME.get(entity_type.upper(), entity_type.upper())


def placeholder(ctx: DocContext, entity_type: str, surface: str, entry: PolicyEntry) -> str:
    token = token_name(entity_type, entry)
    indexed = entry.indexed and entity_type.upper() not in _UNINDEXED_DEFAULT
    if not indexed:
        return f"<{token}>"
    canonical = canonicalize(entity_type, surface)
    key = (f"{entity_class(entity_type)}:{token}", canonical)
    label = ctx.labels.get(key)
    if label is None:
        idx = ctx.counters.get(token, 0) + 1
        ctx.counters[token] = idx
        label = f"<{token}_{idx}>"
        ctx.labels[key] = label
    return label


def generalize(entity_type: str, surface: str, entry: PolicyEntry) -> str:
    et = entity_type.upper()
    params = entry.params
    if et in ("DATE", "DOB", "DATE_OF_BIRTH"):
        year = dates.year_only(surface)
        return year if year is not None else "<DATE>"
    if et in ("ZIP", "PIN", "PINCODE", "POSTAL_CODE", "ZIPCODE"):
        digits = "".join(c for c in surface if c.isdigit())
        if len(digits) >= 4:
            return digits[:3] + "X" * (len(digits) - 3)
        return "<ZIP>"
    if et == "AGE":
        digits = "".join(c for c in surface if c.isdigit())
        if not digits:
            return "<AGE>"
        age = int(digits)
        if age > 89:
            return "90+"  # HIPAA Safe Harbor: ages over 89 bracketed
        if params.get("bracket_5y", True):
            lo = (age // 5) * 5
            return f"{lo}-{lo + 4}"
        return str(age)
    return f"<{token_name(entity_type, entry)}>"


def date_shift(ctx: DocContext, surface: str) -> str:
    shifted = dates.shift_date(surface, ctx.shift_days())
    return shifted if shifted is not None else "<DATE>"
