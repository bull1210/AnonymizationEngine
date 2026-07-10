"""Layout preservation for format-preserving encryption.

FF3-1 operates on the bare digit string; this module extracts digits, and
re-inserts ciphertext digits into the original separator layout so
'4111 1111 1111 1111' becomes e.g. '5217 8348 9010 3374'.
"""
from __future__ import annotations

# FF3-1 domain bounds for radix 10 (NIST SP 800-38G rev.1: radix^minlen >= 1e6).
FF3_MIN_DIGITS = 6
FF3_MAX_DIGITS = 56


def extract_digits(surface: str) -> str:
    return "".join(ch for ch in surface if ch.isdigit())


def reinsert_layout(surface: str, cipher_digits: str) -> str:
    """Place cipher digits back into the surface's non-digit layout."""
    it = iter(cipher_digits)
    out = []
    for ch in surface:
        out.append(next(it) if ch.isdigit() else ch)
    return "".join(out)


def fpe_domain_ok(digits: str) -> bool:
    return FF3_MIN_DIGITS <= len(digits) <= FF3_MAX_DIGITS
