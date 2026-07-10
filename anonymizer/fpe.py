"""FF3-1 format-preserving encryption (NIST SP 800-38G) via the vetted `ff3`
library. Encrypts digits only, re-inserts separators, and recomputes check
digits (Luhn/Verhoeff) — FPE does not preserve checksums.

FF3-1 keys come from the KMS per tenant and are NEVER derived from the HMAC
salt (independent compromise domains).
"""
from __future__ import annotations

from .core.checkdigits import recompute_check_digit
from .core.fpelayout import extract_digits, fpe_domain_ok, reinsert_layout


class FF3Cipher:
    """Implements the engine's FpeCipher protocol."""

    def __init__(self, key_hex: str, tweak_hex: str) -> None:
        try:
            from ff3 import FF3Cipher as _FF3  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("pip install ff3 — required for the fpe strategy") from exc
        self._cipher = _FF3(key_hex, tweak_hex)  # radix 10 default

    def encrypt(self, entity_type: str, surface: str) -> str | None:
        digits = extract_digits(surface)
        if not fpe_domain_ok(digits):
            return None  # engine falls back to a safe placeholder
        ct = self._cipher.encrypt(digits)
        ct = recompute_check_digit(entity_type, ct)
        return reinsert_layout(surface, ct)
