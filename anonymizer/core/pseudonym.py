"""Stateless deterministic pseudonyms (RAG mode primary mechanism).

pseudonym = f"{prefix}_{HMAC_SHA256(version|class|canonical, key=salt)[:N]}"

Stateless: any parallel worker computes the identical token with no
coordination. The only shared state is the truncation-collision registry,
which stores (class, prefix) -> FULL digest — never the canonical text — so
two distinct identities are never silently merged and nothing sensitive is
persisted here.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Protocol

from .canonicalize import CANONICALIZER_VERSION, entity_class

log = logging.getLogger(__name__)

_TYPE_PREFIX = {
    "person": "User",
    "org": "Org",
    "loc": "Loc",
    "email": "Email",
}
_EXTEND_STEP = 4  # hex chars added per collision round


def type_prefix(entity_type: str) -> str:
    cls = entity_class(entity_type)
    return _TYPE_PREFIX.get(cls, cls.title().replace("_", "")[:12] or "Ent")


def full_digest(
    entity_type: str,
    canonical: str,
    salt: bytes,
    canonicalizer_version: str = CANONICALIZER_VERSION,
) -> str:
    """64-hex-char HMAC digest. canonicalizer_version is salted into the
    context: a canonicalizer change intentionally changes every pseudonym."""
    msg = f"{canonicalizer_version}|{entity_class(entity_type)}|{canonical}".encode()
    return hmac.new(salt, msg, hashlib.sha256).hexdigest()


class CollisionRegistry(Protocol):
    def get(self, entity_class_: str, prefix: str) -> str | None:
        """Return the full digest registered under (class, prefix), if any."""
        ...

    def put(self, entity_class_: str, prefix: str, digest: str, length: int) -> None: ...


class MemoryCollisionRegistry:
    def __init__(self) -> None:
        self._d: dict[tuple[str, str], str] = {}

    def get(self, entity_class_: str, prefix: str) -> str | None:
        return self._d.get((entity_class_, prefix))

    def put(self, entity_class_: str, prefix: str, digest: str, length: int) -> None:
        self._d.setdefault((entity_class_, prefix), digest)


class PseudonymEngine:
    def __init__(
        self,
        salt: bytes,
        *,
        length: int = 8,
        registry: CollisionRegistry | None = None,
        canonicalizer_version: str = CANONICALIZER_VERSION,
    ) -> None:
        if len(salt) < 16:
            raise ValueError("tenant salt must be at least 128 bits (256 recommended)")
        self._salt = salt
        self._length = length
        self._registry = registry
        self._version = canonicalizer_version
        self.collisions = 0

    def token(self, entity_type: str, canonical: str) -> str:
        digest = full_digest(entity_type, canonical, self._salt, self._version)
        cls = entity_class(entity_type)
        length = self._length
        if self._registry is not None:
            while True:
                prefix = digest[:length]
                existing = self._registry.get(cls, prefix)
                if existing is None:
                    self._registry.put(cls, prefix, digest, length)
                    # Re-read: under concurrency first writer wins deterministically.
                    existing = self._registry.get(cls, prefix)
                if existing == digest:
                    break
                # Truncation collision with a DIFFERENT identity: extend, log,
                # never silently merge.
                self.collisions += 1
                log.warning(
                    "pseudonym truncation collision (class=%s len=%d); extending", cls, length
                )
                length += _EXTEND_STEP
        return f"{type_prefix(entity_type)}_{digest[:length]}"
