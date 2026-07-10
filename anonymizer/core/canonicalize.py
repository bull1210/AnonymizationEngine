"""Versioned canonicalizer — a pure function; changing it changes pseudonyms.

CANONICALIZER_VERSION is salted into the HMAC context and recorded in every
receipt. Bump it on ANY behavior change, and expect a full corpus re-run.

Alias policy is conservative by design: exact match after normalization always
links; fuzzy linking (initials, partial names) requires explicit opt-in rules.
Failure asymmetry: prefer missing an alias over wrongly merging two people.
"""
from __future__ import annotations

import re
import unicodedata

CANONICALIZER_VERSION = "1.0.0"

_HONORIFICS = {
    "dr", "mr", "mrs", "ms", "miss", "mx", "prof", "professor", "sir",
    "madam", "shri", "smt", "kum", "rev", "hon",
}
_ORG_SUFFIXES = {
    "ltd", "limited", "inc", "incorporated", "pvt", "private", "llc", "llp",
    "plc", "gmbh", "corp", "corporation", "co", "company", "sa", "ag", "pte",
    "bv", "oy", "ab",
}
# Types whose canonical form is the bare alphanumeric payload (separators stripped).
_STRUCTURED_TYPES = {
    "PHONE", "CREDIT_CARD", "SSN", "AADHAAR", "PAN", "ACCOUNT", "ACCOUNT_NUMBER",
    "NATIONAL_ID", "PASSPORT", "IBAN", "ROUTING_NUMBER", "MRN", "IP",
}

_WS = re.compile(r"\s+")
_PUNCT = re.compile(r"[^\w\s]", re.UNICODE)
_NON_ALNUM = re.compile(r"[^0-9a-zA-Z]")


def canonicalize(entity_type: str, surface: str) -> str:
    """Normalize a raw entity surface into its canonical linking form."""
    etype = entity_type.upper()
    s = unicodedata.normalize("NFKC", surface)

    if etype in _STRUCTURED_TYPES:
        return _NON_ALNUM.sub("", s).casefold()

    s = s.casefold().strip()

    if etype == "PERSON":
        return _person(s)
    if etype in ("ORG", "ORGANIZATION", "COMPANY"):
        return _org(s)
    if etype == "EMAIL":
        return _WS.sub("", s)

    # Default: strip punctuation, collapse whitespace.
    s = _PUNCT.sub(" ", s)
    return _WS.sub(" ", s).strip()


def _person(s: str) -> str:
    # "Last, First" -> "First Last" (single comma only; multiple commas are
    # ambiguous and left in reading order rather than guessed at).
    if s.count(",") == 1:
        last, _, first = s.partition(",")
        s = f"{first.strip()} {last.strip()}"
    s = _PUNCT.sub(" ", s)
    tokens = s.split()
    while tokens and tokens[0] in _HONORIFICS:
        tokens.pop(0)
    return " ".join(tokens)


def _org(s: str) -> str:
    s = _PUNCT.sub(" ", s)
    tokens = s.split()
    # Strip trailing legal suffixes ("Acme Widgets Pvt Ltd" -> "acme widgets"),
    # but never strip down to nothing.
    while len(tokens) > 1 and tokens[-1] in _ORG_SUFFIXES:
        tokens.pop()
    return " ".join(tokens)


# Entity classes group synonymous detector labels so "ORG" and "ORGANIZATION"
# link, while PERSON and ORG can never share a pseudonym space.
_ENTITY_CLASS = {
    "PERSON": "person", "PER": "person", "NAME": "person",
    "ORG": "org", "ORGANIZATION": "org", "COMPANY": "org",
    "LOCATION": "loc", "LOC": "loc", "GPE": "loc", "ADDRESS": "loc",
    "EMAIL": "email",
}


def entity_class(entity_type: str) -> str:
    et = entity_type.upper()
    return _ENTITY_CLASS.get(et, et.lower())
