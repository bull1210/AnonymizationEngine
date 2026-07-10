"""Re-identification vault (break-glass), receipt idempotency, audit trail."""
from anonymizer.core.storage import AuditLog, Database, ReceiptStore, VaultStore

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

if HAVE_CRYPTO:
    from anonymizer.core.vault import BreakGlassDenied, ReidVault

KEY = b"\x01" * 32


def _vault(db):
    return ReidVault(KEY, VaultStore(db), AuditLog(db))


def test_vault_roundtrip():
    if not HAVE_CRYPTO:
        return
    db = Database()
    v = _vault(db)
    v.put("User_91a4b2c3", "Priya Sharma", "PERSON")
    got = v.reveal("User_91a4b2c3", actor="alice", role="privacy_officer",
                   reason="court order #124-B re: subpoena")
    assert got == "Priya Sharma"


def test_vault_role_denied_and_audited():
    if not HAVE_CRYPTO:
        return
    db = Database()
    v = _vault(db)
    v.put("User_x", "Secret Name", "PERSON")
    try:
        v.reveal("User_x", actor="mallory", role="intern", reason="just curious please")
        raise AssertionError("expected BreakGlassDenied")
    except BreakGlassDenied:
        pass
    entries = AuditLog(db).entries()
    assert any(e[2] == "reveal_denied" for e in entries)


def test_vault_reason_mandatory():
    if not HAVE_CRYPTO:
        return
    db = Database()
    v = _vault(db)
    v.put("User_y", "N", "PERSON")
    try:
        v.reveal("User_y", actor="alice", role="dpo", reason="ok")
        raise AssertionError("expected BreakGlassDenied")
    except BreakGlassDenied:
        pass


def test_vault_ciphertext_not_plaintext():
    if not HAVE_CRYPTO:
        return
    db = Database()
    v = _vault(db)
    v.put("User_z", "Priya Sharma", "PERSON")
    blob, _ = VaultStore(db).get("User_z")
    assert b"Priya" not in blob


def test_receipt_idempotency_key():
    db = Database()
    store = ReceiptStore(db)
    r = {"file_id": "f", "job_id": "j", "mode": "rag", "policy_version": "1",
         "canonicalizer_version": "1.0.0", "status": "VERIFIED",
         "replacements": [], "leaks": [], "created_at": "2026-01-01T00:00:00+00:00"}
    store.save(r)
    store.save(dict(r, status="VERIFIED"))  # re-run: replaces, no duplicate
    rows = db.execute("SELECT COUNT(*) FROM transform_receipts")
    assert rows[0][0] == 1
