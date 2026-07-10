"""SQLite-backed stores (receipts, collision registry, re-id vault, audit log).

SQLite is the zero-dependency default so the engine runs anywhere; production
deployments point the same interfaces at Postgres (see migrations/001_init.sql
and anonymizer/pgstorage.py notes). All stores are thread-safe.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS transform_receipts (
    file_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    canonicalizer_version TEXT NOT NULL,
    status TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (file_id, job_id, policy_version, canonicalizer_version)
);
CREATE TABLE IF NOT EXISTS pseudonym_collisions (
    entity_class TEXT NOT NULL,
    prefix TEXT NOT NULL,
    digest TEXT NOT NULL,
    token_length INTEGER NOT NULL,
    PRIMARY KEY (entity_class, prefix)
);
CREATE TABLE IF NOT EXISTS reid_vault (
    pseudonym TEXT PRIMARY KEY,
    ciphertext BLOB NOT NULL,
    entity_type TEXT NOT NULL,
    first_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def execute(self, sql: str, params: tuple = ()) -> list[tuple]:
        with self._lock:
            cur = self._conn.execute(sql, params)
            rows = cur.fetchall()
            self._conn.commit()
            return rows


class ReceiptStore:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, receipt_dict: dict) -> None:
        """Idempotent by (file_id, job_id, policy_version, canonicalizer_version)."""
        self._db.execute(
            "INSERT OR REPLACE INTO transform_receipts VALUES (?,?,?,?,?,?,?,?)",
            (
                receipt_dict["file_id"],
                receipt_dict["job_id"],
                receipt_dict["mode"],
                receipt_dict["policy_version"],
                receipt_dict["canonicalizer_version"],
                receipt_dict["status"],
                json.dumps(receipt_dict),
                receipt_dict.get("created_at", _now()),
            ),
        )

    def get(self, file_id: str, job_id: str) -> dict | None:
        rows = self._db.execute(
            "SELECT receipt_json FROM transform_receipts WHERE file_id=? AND job_id=? "
            "ORDER BY created_at DESC LIMIT 1",
            (file_id, job_id),
        )
        return json.loads(rows[0][0]) if rows else None


class SqliteCollisionRegistry:
    """Shared truncation-collision registry (implements CollisionRegistry).
    Stores full digests only — no canonical/original text."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def get(self, entity_class_: str, prefix: str) -> str | None:
        rows = self._db.execute(
            "SELECT digest FROM pseudonym_collisions WHERE entity_class=? AND prefix=?",
            (entity_class_, prefix),
        )
        return rows[0][0] if rows else None

    def put(self, entity_class_: str, prefix: str, digest: str, length: int) -> None:
        self._db.execute(
            "INSERT OR IGNORE INTO pseudonym_collisions VALUES (?,?,?,?)",
            (entity_class_, prefix, digest, length),
        )


class VaultStore:
    def __init__(self, db: Database) -> None:
        self._db = db

    def put(self, pseudonym: str, ciphertext: bytes, entity_type: str) -> None:
        self._db.execute(
            "INSERT OR IGNORE INTO reid_vault VALUES (?,?,?,?)",
            (pseudonym, ciphertext, entity_type, _now()),
        )

    def get(self, pseudonym: str) -> tuple[bytes, str] | None:
        rows = self._db.execute(
            "SELECT ciphertext, entity_type FROM reid_vault WHERE pseudonym=?", (pseudonym,)
        )
        return (rows[0][0], rows[0][1]) if rows else None

    def count(self) -> int:
        return self._db.execute("SELECT COUNT(*) FROM reid_vault")[0][0]


class AuditLog:
    def __init__(self, db: Database) -> None:
        self._db = db

    def append(self, actor: str, action: str, detail: dict) -> None:
        self._db.execute(
            "INSERT INTO audit_log VALUES (?,?,?,?)",
            (_now(), actor, action, json.dumps(detail)),
        )

    def entries(self) -> list[tuple]:
        return self._db.execute("SELECT * FROM audit_log ORDER BY ts")
