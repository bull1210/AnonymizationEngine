"""Stateless determinism, salt isolation, and truncation-collision handling."""
from anonymizer.core.pseudonym import (
    MemoryCollisionRegistry, PseudonymEngine, full_digest, type_prefix,
)

SALT = b"\x42" * 32


def test_stateless_determinism_across_instances():
    a = PseudonymEngine(SALT)
    b = PseudonymEngine(SALT)  # independent "worker"
    assert a.token("PERSON", "priya sharma") == b.token("PERSON", "priya sharma")


def test_prefixes():
    assert PseudonymEngine(SALT).token("PERSON", "x").startswith("User_")
    assert PseudonymEngine(SALT).token("ORG", "x").startswith("Org_")
    assert PseudonymEngine(SALT).token("LOCATION", "x").startswith("Loc_")
    assert type_prefix("ORGANIZATION") == "Org"


def test_salt_changes_everything():
    a = PseudonymEngine(SALT)
    b = PseudonymEngine(b"\x43" * 32)
    assert a.token("PERSON", "priya sharma") != b.token("PERSON", "priya sharma")


def test_entity_class_separates_pseudonym_spaces():
    e = PseudonymEngine(SALT)
    assert e.token("PERSON", "mercury") != e.token("ORG", "mercury")


def test_canonicalizer_version_salted_into_context():
    d1 = full_digest("PERSON", "priya sharma", SALT, "1.0.0")
    d2 = full_digest("PERSON", "priya sharma", SALT, "2.0.0")
    assert d1 != d2


def test_short_salt_rejected():
    try:
        PseudonymEngine(b"short")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def _find_colliding_pair(length: int) -> tuple[str, str]:
    """Two distinct canonicals whose digests share the first `length` hex chars."""
    seen: dict[str, str] = {}
    i = 0
    while True:
        c = f"entity-{i}"
        p = full_digest("PERSON", c, SALT)[:length]
        if p in seen and seen[p] != c:
            return seen[p], c
        seen[p] = c
        i += 1


def test_truncation_collision_never_silently_merges():
    c1, c2 = _find_colliding_pair(2)
    registry = MemoryCollisionRegistry()
    e = PseudonymEngine(SALT, length=2, registry=registry)
    t1, t2 = e.token("PERSON", c1), e.token("PERSON", c2)
    assert t1 != t2, "collision silently merged two identities"
    assert e.collisions >= 1
    assert len(t2) > len(t1)  # second identity got an extended token
    # Stability after extension: both resolve identically forever after.
    assert e.token("PERSON", c1) == t1
    assert e.token("PERSON", c2) == t2
    # ...including from a fresh worker sharing the registry.
    e2 = PseudonymEngine(SALT, length=2, registry=registry)
    assert e2.token("PERSON", c1) == t1
    assert e2.token("PERSON", c2) == t2


def test_registry_stores_no_sensitive_text():
    registry = MemoryCollisionRegistry()
    e = PseudonymEngine(SALT, length=8, registry=registry)
    e.token("PERSON", "priya sharma")
    for (cls, prefix), digest in registry._d.items():
        assert "priya" not in prefix and "priya" not in digest and "priya" not in cls
