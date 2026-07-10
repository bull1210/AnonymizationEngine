"""End-to-end engine behavior for both modes, including the negative test
proving training mode emits no recoverable artifact."""
import re

from anonymizer.core.detection import RegexDetector
from anonymizer.core.engine import Engine
from anonymizer.core.policyload import build_policy_table
from anonymizer.core.pseudonym import MemoryCollisionRegistry
from anonymizer.core.storage import Database, ReceiptStore, VaultStore
from anonymizer.core.types import (
    Finding, JobSpec, PolicyViolation, Status, Strategy, Target,
)

POLICY = build_policy_table({
    "version": "test-1",
    "policies": {
        "training": {
            "PERSON": {"strategy": "placeholder_indexed", "token": "NAME"},
            "ORG": {"strategy": "placeholder_indexed", "token": "ORG"},
            "MEDICATION": {"strategy": "placeholder_indexed"},
            "EMAIL": "suppress",
            "DATE": {"strategy": "generalize"},
            "ZIP": {"strategy": "generalize"},
            "AGE": {"strategy": "generalize"},
            "NOTE": "keep",
        },
        "rag": {
            "PERSON": "hmac_pseudonym",
            "ORG": "hmac_pseudonym",
            "EMAIL": "hmac_pseudonym",
            "CREDIT_CARD": "fpe",
            "DATE": "keep",
        },
    },
})

SALT = b"\x07" * 32

TEXT = "Dr. Priya Sharma met Anil Rao. Later SHARMA, Priya emailed Anil Rao at anil.rao@x.com."
FINDINGS = [
    Finding("PERSON", 0, 16, 0.98),    # Dr. Priya Sharma
    Finding("PERSON", 21, 29, 0.97),   # Anil Rao
    Finding("PERSON", 37, 50, 0.95),   # SHARMA, Priya
    Finding("PERSON", 59, 67, 0.97),   # Anil Rao
    Finding("EMAIL", 71, 85, 0.99),    # anil.rao@x.com
]


def _job(target, **kw):
    return JobSpec(job_id="t1", target=target, **kw)


def test_training_local_coreference_and_receipt_redaction():
    engine = Engine(POLICY, detector=RegexDetector())
    res = engine.transform(TEXT, FINDINGS, _job(Target.TRAINING), "f1")
    masked = res.masked_text
    # Same canonical entity -> same index within the document.
    assert masked.count("<NAME_1>") == 2  # Priya Sharma + alias "SHARMA, Priya"
    assert masked.count("<NAME_2>") == 2  # Anil Rao twice
    assert "anil.rao@x.com" not in masked and "Priya" not in masked
    assert res.receipt.status == Status.VERIFIED.value
    # Irreversibility: receipt carries offsets and types but NO original text.
    for r in res.receipt.replacements:
        assert r.original is None
    receipt_str = str(res.receipt.to_dict())
    for fragment in ("Priya", "Sharma", "Anil", "anil.rao"):
        assert fragment not in receipt_str


def test_training_counters_reset_per_document():
    engine = Engine(POLICY)
    r1 = engine.transform("Priya Sharma", [Finding("PERSON", 0, 12, 0.9)],
                          _job(Target.TRAINING), "d1")
    r2 = engine.transform("Anil Rao", [Finding("PERSON", 0, 8, 0.9)],
                          _job(Target.TRAINING), "d2")
    # Different people in different docs both get index 1: no cross-doc token linking.
    assert r1.masked_text == "<NAME_1>" and r2.masked_text == "<NAME_1>"


def test_training_unindexed_types_get_bare_tokens():
    engine = Engine(POLICY)
    res = engine.transform("Took Metformin and Metformin again",
                           [Finding("MEDICATION", 5, 14, 0.9),
                            Finding("MEDICATION", 19, 28, 0.9)],
                           _job(Target.TRAINING), "d3")
    assert res.masked_text == "Took <MEDICATION> and <MEDICATION> again"


def test_generalization():
    engine = Engine(POLICY)
    res = engine.transform("DOB 1990-04-12, ZIP 560034, age 93",
                           [Finding("DATE", 4, 14, 0.9), Finding("ZIP", 20, 26, 0.9),
                            Finding("AGE", 32, 34, 0.9)],
                           _job(Target.TRAINING), "d4")
    assert res.masked_text == "DOB 1990, ZIP 560XXX, age 90+"


def test_unknown_entity_type_fails_closed():
    engine = Engine(POLICY)
    res = engine.transform("secret BLOB9 here", [Finding("WEIRD_NEW_TYPE", 7, 12, 0.9)],
                           _job(Target.TRAINING), "d5")
    assert res.masked_text == "secret  here"  # suppressed entirely


def test_below_threshold_kept():
    engine = Engine(POLICY)
    res = engine.transform("maybe Priya here", [Finding("PERSON", 6, 11, 0.3)],
                           _job(Target.TRAINING), "d6")
    assert res.masked_text == "maybe Priya here"
    assert res.receipt.replacements == []


def test_training_runtime_guard_against_linkable_override():
    engine = Engine(POLICY)
    job = _job(Target.TRAINING, strategy_overrides={"PERSON": Strategy.HMAC_PSEUDONYM})
    try:
        engine.transform("Priya Sharma", [Finding("PERSON", 0, 12, 0.9)], job, "d7")
        raise AssertionError("expected PolicyViolation")
    except PolicyViolation:
        pass


def test_policy_loader_rejects_linkable_training_strategy():
    try:
        build_policy_table({"version": "x", "policies": {"training": {"PERSON": "fpe"}}})
        raise AssertionError("expected PolicyViolation")
    except PolicyViolation:
        pass


def test_rag_cross_document_and_cross_worker_consistency():
    db = Database()
    from anonymizer.core.storage import SqliteCollisionRegistry
    registry = SqliteCollisionRegistry(db)
    # Two independent engine instances = two parallel workers sharing only
    # the collision table.
    w1 = Engine(POLICY, salt_provider=lambda j: SALT, collision_registry=registry)
    w2 = Engine(POLICY, salt_provider=lambda j: SALT, collision_registry=registry)
    job = _job(Target.RAG)

    r1 = w1.transform("Dr. Priya Sharma called.", [Finding("PERSON", 0, 16, 0.9)], job, "a")
    r2 = w2.transform("SHARMA, Priya answered.", [Finding("PERSON", 0, 13, 0.9)], job, "b")
    tok1 = r1.receipt.replacements[0].replacement
    tok2 = r2.receipt.replacements[0].replacement
    assert tok1 == tok2, "alias of same entity got different pseudonyms across workers"
    assert re.fullmatch(r"User_[0-9a-f]{8,}", tok1)


def test_rag_receipts_may_carry_originals_but_training_never():
    engine = Engine(POLICY, salt_provider=lambda j: SALT)
    res = engine.transform("Priya Sharma", [Finding("PERSON", 0, 12, 0.9)],
                           _job(Target.RAG), "d8")
    assert res.receipt.replacements[0].original == "Priya Sharma"


class _FakeFpe:
    """Deterministic digit rotation standing in for FF3-1 (layout-true)."""

    def encrypt(self, entity_type, surface):
        from anonymizer.core.checkdigits import recompute_check_digit
        from anonymizer.core.fpelayout import extract_digits, fpe_domain_ok, reinsert_layout

        digits = extract_digits(surface)
        if not fpe_domain_ok(digits):
            return None
        ct = "".join(str((int(d) + 3) % 10) for d in digits)
        return reinsert_layout(surface, recompute_check_digit(entity_type, ct))


def test_rag_fpe_output_not_flagged_as_leak():
    engine = Engine(POLICY, salt_provider=lambda j: SALT, fpe=_FakeFpe(),
                    detector=RegexDetector())
    text = "Card: 4111 1111 1111 1111 ok"
    res = engine.transform(text, [Finding("CREDIT_CARD", 6, 25, 0.99)],
                           _job(Target.RAG), "d9")
    new_card = res.receipt.replacements[0].replacement
    assert new_card != "4111 1111 1111 1111"
    assert len(new_card) == 19 and new_card[4] == " "
    # Detector re-finds a valid card in the masked text, but it's inside the
    # replacement span: transformation artifact, not a leak.
    assert res.receipt.status == Status.VERIFIED.value


def test_verification_quarantines_missed_entity():
    engine = Engine(POLICY, detector=RegexDetector())
    # Detection upstream MISSED the email — verification must catch it.
    res = engine.transform("Contact anil.rao@x.com now", [], _job(Target.TRAINING), "d10")
    assert res.receipt.status == Status.LEAK_DETECTED.value
    assert res.receipt.leaks and res.receipt.leaks[0].entity_type == "EMAIL"


def test_training_emits_no_recoverable_artifact():
    """Negative test: with vault + registry wired in, a training job must
    still write NO vault rows, NO collision entries, and NO originals."""
    db = Database()
    from anonymizer.core.storage import SqliteCollisionRegistry
    vault_store = VaultStore(db)
    receipts = ReceiptStore(db)
    engine = Engine(POLICY, detector=RegexDetector(), receipt_store=receipts,
                    collision_registry=SqliteCollisionRegistry(db))
    res = engine.transform(TEXT, FINDINGS, _job(Target.TRAINING, reversible=True), "f-neg")
    assert vault_store.count() == 0
    assert db.execute("SELECT COUNT(*) FROM pseudonym_collisions")[0][0] == 0
    stored = receipts.get("f-neg", "t1")
    assert stored is not None
    flat = str(stored)
    for fragment in ("Priya", "Sharma", "Anil", "anil.rao@x.com"):
        assert fragment not in flat
    assert "Priya" not in res.masked_text


def test_idempotent_reprocessing():
    engine = Engine(POLICY, salt_provider=lambda j: SALT)
    job = _job(Target.RAG)
    a = engine.transform(TEXT, FINDINGS, job, "f-idem").masked_text
    b = engine.transform(TEXT, FINDINGS, job, "f-idem").masked_text
    assert a == b
