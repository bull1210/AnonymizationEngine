"""Check-digit algorithms. FPE does not preserve checksums, so ciphertexts for
types with downstream validation get their check digit recomputed (Luhn for
cards, Verhoeff for Aadhaar)."""
from __future__ import annotations


def luhn_check_digit(payload: str) -> str:
    """Check digit for a digit-string payload (digit that would be appended)."""
    total = 0
    for i, ch in enumerate(reversed(payload)):
        d = int(ch)
        if i % 2 == 0:  # positions counted with the check digit occupying slot 0
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def luhn_valid(number: str) -> bool:
    return len(number) >= 2 and number.isdigit() and luhn_check_digit(number[:-1]) == number[-1]


def luhn_fix(number: str) -> str:
    """Replace the final digit so the whole number is Luhn-valid."""
    return number[:-1] + luhn_check_digit(number[:-1])


_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_check_digit(payload: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(payload), start=1):
        c = _D[c][_P[i % 8][int(ch)]]
    return str(_INV[c])


def verhoeff_valid(number: str) -> bool:
    if not number.isdigit() or len(number) < 2:
        return False
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_fix(number: str) -> str:
    return number[:-1] + verhoeff_check_digit(number[:-1])


def recompute_check_digit(entity_type: str, digits: str) -> str:
    """Recompute the check digit appropriate to the entity type, if any."""
    et = entity_type.upper()
    if et == "CREDIT_CARD" and len(digits) >= 2:
        return luhn_fix(digits)
    if et == "AADHAAR" and len(digits) == 12:
        return verhoeff_fix(digits)
    return digits
