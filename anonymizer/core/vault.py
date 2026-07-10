"""Optional re-identification vault (RAG mode, `reversible: true` only).

AES-256-GCM with a dedicated vault key (independent from HMAC salts and FPE
keys). Access only via break-glass API with mandatory reason logging and role
checks. Vault writes are async side effects — pseudonym computation NEVER
depends on the vault. With reversible=false (default) no rows are written.
"""
from __future__ import annotations

import os

from .storage import AuditLog, VaultStore

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover
    AESGCM = None  # type: ignore


class BreakGlassDenied(PermissionError):
    pass


class ReidVault:
    def __init__(
        self,
        key: bytes,
        store: VaultStore,
        audit: AuditLog,
        allowed_roles: frozenset[str] = frozenset({"privacy_officer", "dpo"}),
    ) -> None:
        if AESGCM is None:
            raise RuntimeError("cryptography package required for the re-id vault")
        if len(key) != 32:
            raise ValueError("vault key must be 256-bit")
        self._aes = AESGCM(key)
        self._store = store
        self._audit = audit
        self._allowed = allowed_roles

    def put(self, pseudonym: str, original: str, entity_type: str) -> None:
        nonce = os.urandom(12)
        ct = self._aes.encrypt(nonce, original.encode(), pseudonym.encode())
        self._store.put(pseudonym, nonce + ct, entity_type)

    def reveal(self, pseudonym: str, *, actor: str, role: str, reason: str) -> str:
        """Break-glass re-identification. Every attempt is audit-logged."""
        if role not in self._allowed:
            self._audit.append(actor, "reveal_denied", {"pseudonym": pseudonym, "role": role})
            raise BreakGlassDenied(f"role '{role}' may not re-identify")
        if not reason or len(reason.strip()) < 10:
            self._audit.append(actor, "reveal_denied", {"pseudonym": pseudonym, "why": "no reason"})
            raise BreakGlassDenied("a substantive reason is mandatory")
        row = self._store.get(pseudonym)
        self._audit.append(
            actor, "reveal", {"pseudonym": pseudonym, "role": role, "reason": reason.strip()}
        )
        if row is None:
            raise KeyError(f"pseudonym not in vault: {pseudonym}")
        blob, _etype = row
        nonce, ct = blob[:12], blob[12:]
        return self._aes.decrypt(nonce, ct, pseudonym.encode()).decode()
