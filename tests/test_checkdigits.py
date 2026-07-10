import random

from anonymizer.core.checkdigits import (
    luhn_fix, luhn_valid, recompute_check_digit, verhoeff_fix, verhoeff_valid,
)
from anonymizer.core.fpelayout import extract_digits, fpe_domain_ok, reinsert_layout


def test_luhn_known():
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")


def test_luhn_fix_property():
    rng = random.Random(7)
    for _ in range(200):
        n = "".join(str(rng.randint(0, 9)) for _ in range(rng.choice([13, 15, 16, 19])))
        assert luhn_valid(luhn_fix(n))


def test_verhoeff_fix_property():
    rng = random.Random(8)
    for _ in range(200):
        n = "".join(str(rng.randint(0, 9)) for _ in range(12))
        assert verhoeff_valid(verhoeff_fix(n))


def test_recompute_dispatch():
    assert luhn_valid(recompute_check_digit("CREDIT_CARD", "4000123456789010"))
    assert verhoeff_valid(recompute_check_digit("AADHAAR", "123412341234"))
    assert recompute_check_digit("PHONE", "9840123456") == "9840123456"  # untouched


def test_layout_roundtrip():
    surface = "4111 1111 1111 1111"
    digits = extract_digits(surface)
    assert digits == "4111111111111111"
    out = reinsert_layout(surface, "5217834890103374")
    assert out == "5217 8348 9010 3374"
    assert [c.isdigit() for c in out] == [c.isdigit() for c in surface]


def test_fpe_domain_bounds():
    assert not fpe_domain_ok("12345")      # too short for FF3-1 radix 10
    assert fpe_domain_ok("123456")
    assert not fpe_domain_ok("1" * 57)
