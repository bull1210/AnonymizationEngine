"""Kafka bridge: turn per-chunk detection scan results into anonymizer jobs.

Consumes ``files.scan.results`` (one ScanResult JSON per scanned chunk),
groups chunks by ``doc_id``, shifts each finding by its chunk's offset into
the canonical extracted text, fetches that text from the extraction service
(``GET {text_store_url}/text/{doc_id}``), maps detection entity names onto
the masking-policy vocabulary, and writes one complete job message
(``{"file_id","text","findings","job"}``) into the worker's directory queue.

A document is emitted the moment results for all ``total_chunks`` chunks have
arrived; documents stuck incomplete (a chunk lost upstream) are flushed after
``flush_after_s`` with the findings seen so far — fail-safe toward masking,
and the verification pass still quarantines anything that leaks.

Requires messages produced by an extraction service that sets
doc_id/offset/total_chunks; results lacking a doc_id are logged and skipped.

Run: ``anonymizer bridge --text-store-url http://extraction-api:8081``
"""
from __future__ import annotations

import json
import logging
import re
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

log = logging.getLogger(__name__)

#: Detection engine entity names -> masking-policy entity names. Unmapped
#: names pass through unchanged; types unknown to the policy fail closed
#: (suppressed), so a mapping gap over-masks rather than leaks.
ENTITY_MAP = {
    "US_SSN": "SSN",
    "IN_AADHAAR": "AADHAAR",
    "IN_PAN": "PAN",
    "UK_NHS": "MRN",
    "IP_ADDRESS": "IP",
    "DATE_OF_BIRTH": "DOB",
    "MEDICAL_DIAGNOSIS": "DIAGNOSIS",
    "MEDICAL_CONDITION": "DIAGNOSIS",
    "PATIENT_NAME": "PERSON",
    "FINANCIAL_ACCOUNT": "ACCOUNT_NUMBER",
    "IBAN": "ACCOUNT_NUMBER",
}

_CHUNK_INDEX_RE = re.compile(r"#c(\d+)$")


@dataclass
class _DocState:
    file_id: str
    total: int
    chunks: dict = field(default_factory=dict)   # chunk index -> list[finding dict]
    last_update: float = field(default_factory=time.time)


class JobAssembler:
    """Pure aggregation core — no Kafka, fully unit-testable. ``fetch_text``
    resolves a doc_id to the canonical extracted text (HTTP in production)."""

    def __init__(self, fetch_text: Callable[[str], str], out_dir: str | Path,
                 job: dict, flush_after_s: float = 300.0) -> None:
        self._fetch_text = fetch_text
        self._out_dir = Path(out_dir)
        self._out_dir.mkdir(parents=True, exist_ok=True)
        self._job = job
        self._flush_after_s = flush_after_s
        self._docs: dict[str, _DocState] = {}
        self.emitted = 0

    def add(self, result: dict) -> None:
        """Ingest one ScanResult dict; emit the document if now complete."""
        doc_id = result.get("doc_id") or ""
        if not doc_id:
            log.warning("scan result without doc_id skipped (old producer?): %s",
                        result.get("chunk_id"))
            return
        m = _CHUNK_INDEX_RE.search(result.get("chunk_id", ""))
        if m is None:
            log.warning("chunk_id without index skipped: %s", result.get("chunk_id"))
            return
        index = int(m.group(1))
        offset = int(result.get("chunk_offset", 0))

        state = self._docs.setdefault(doc_id, _DocState(
            file_id=str(result.get("file_id", doc_id)),
            total=int(result.get("total_chunks", 1)),
        ))
        state.chunks[index] = [
            {
                "entity_type": ENTITY_MAP.get(f["entity"], f["entity"]),
                "start": f["start"] + offset,
                "end": f["end"] + offset,
                "confidence": f.get("confidence", 1.0),
                "tier": f.get("tier", "T1"),
                "validated": f.get("validated", False),
            }
            for f in result.get("findings", [])
        ]
        state.last_update = time.time()
        if len(state.chunks) >= state.total:
            self._emit(doc_id)

    def flush_stale(self) -> None:
        """Emit documents idle beyond flush_after_s even if incomplete —
        fail-safe: partial findings still mask, and downstream verification
        quarantines anything the missing chunk would have caught."""
        now = time.time()
        for doc_id, state in list(self._docs.items()):
            if now - state.last_update > self._flush_after_s:
                log.warning("flushing incomplete doc %s (%d/%d chunks)",
                            doc_id, len(state.chunks), state.total)
                self._emit(doc_id)

    def _emit(self, doc_id: str) -> None:
        state = self._docs.pop(doc_id)
        text = self._fetch_text(doc_id)
        findings = [f for _, fs in sorted(state.chunks.items()) for f in fs]
        safe_id = f"{Path(state.file_id).stem}-{doc_id[:8]}"
        message = {
            "file_id": safe_id,
            "source_path": state.file_id,
            "doc_id": doc_id,
            "text": text,
            "findings": findings,
            "job": self._job,
        }
        # tmp + rename: DirectorySource globs *.json — never sees half a file
        tmp = self._out_dir / f"{safe_id}.tmp"
        tmp.write_text(json.dumps(message, indent=2), encoding="utf-8")
        tmp.replace(self._out_dir / f"{safe_id}.json")
        self.emitted += 1
        log.info("job emitted file=%s findings=%d", safe_id, len(findings))


def http_text_fetcher(base_url: str, timeout: float = 30.0) -> Callable[[str], str]:
    def fetch(doc_id: str) -> str:
        url = f"{base_url.rstrip('/')}/text/{doc_id}"
        with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310
            return r.read().decode("utf-8")
    return fetch


def run_bridge(bootstrap: str, topic: str, group: str, text_store_url: str,
               out_dir: str, job: dict, flush_after_s: float = 300.0) -> int:
    from confluent_kafka import Consumer  # optional dep: pip install ".[kafka]"

    assembler = JobAssembler(
        http_text_fetcher(text_store_url), out_dir, job, flush_after_s
    )
    consumer = Consumer({
        "bootstrap.servers": bootstrap,
        "group.id": group,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
    })
    consumer.subscribe([topic])
    log.info("bridge started topic=%s -> %s (text store: %s)",
             topic, out_dir, text_store_url)
    last_flush = time.time()
    try:
        while True:
            msg = consumer.poll(1.0)
            if msg is not None and not msg.error():
                try:
                    assembler.add(json.loads(msg.value()))
                except Exception:
                    log.exception("bad scan result skipped")
                consumer.commit(msg)  # at-least-once; re-adds are idempotent
            if time.time() - last_flush > 30:
                assembler.flush_stale()
                last_flush = time.time()
    except KeyboardInterrupt:
        return 0
    finally:
        consumer.close()
