"""Golden tests for the canonicalizer — behavior changes require a version
bump and full re-run; these tests pin current behavior exactly."""
from anonymizer.core.canonicalize import CANONICALIZER_VERSION, canonicalize, entity_class

GOLDEN = [
    # PERSON
    ("PERSON", "Dr. Priya Sharma", "priya sharma"),
    ("PERSON", "SHARMA, Priya", "priya sharma"),
    ("PERSON", "priya   sharma ", "priya sharma"),
    ("PERSON", "Mr. Rahul K. Gupta", "rahul k gupta"),
    ("PERSON", "Prof. Anita Desai", "anita desai"),
    ("PERSON", "O'Brien, Mary", "mary o brien"),
    # ORG
    ("ORG", "Acme Widgets Pvt Ltd", "acme widgets"),
    ("ORG", "ACME WIDGETS LIMITED", "acme widgets"),
    ("ORG", "Acme Widgets, Inc.", "acme widgets"),
    ("ORG", "Acme Widgets", "acme widgets"),
    ("ORG", "Ltd", "ltd"),  # never strip to nothing
    # STRUCTURED
    ("PHONE", "+91 98401-23456", "919840123456"),
    ("PHONE", "98401 23456", "9840123456"),
    ("CREDIT_CARD", "4111 1111 1111 1111", "4111111111111111"),
    ("PAN", "abcpd 1234 f", "abcpd1234f"),
    # EMAIL
    ("EMAIL", " Priya.Sharma@Example.COM ", "priya.sharma@example.com"),
    # DEFAULT
    ("LOCATION", "  New   Delhi, India ", "new delhi india"),
]


def test_golden():
    for etype, raw, expected in GOLDEN:
        got = canonicalize(etype, raw)
        assert got == expected, f"{etype} {raw!r}: {got!r} != {expected!r}"


def test_aliases_link_exactly():
    forms = ["Dr. Priya Sharma", "SHARMA, Priya", "PRIYA SHARMA", "priya sharma"]
    assert len({canonicalize("PERSON", f) for f in forms}) == 1


def test_no_fuzzy_linking_by_default():
    # Initials must NOT merge with the full name (failure asymmetry).
    assert canonicalize("PERSON", "P. Sharma") != canonicalize("PERSON", "Priya Sharma")


def test_nfkc_normalization():
    # fullwidth latin normalizes to ascii
    assert canonicalize("PERSON", "Ｐriya Sharma") == "priya sharma"


def test_entity_class_grouping():
    assert entity_class("ORG") == entity_class("ORGANIZATION") == "org"
    assert entity_class("PERSON") != entity_class("ORG")


def test_version_pinned():
    assert CANONICALIZER_VERSION == "1.0.0"


def test_pure_function():
    for _ in range(3):
        assert canonicalize("PERSON", "Dr. Priya Sharma") == "priya sharma"
