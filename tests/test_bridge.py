"""JobAssembler: per-doc aggregation, offset shifting, entity mapping,
completion detection, stale flush — the Kafka-free core of the bridge."""
from __future__ import annotations

import json
import time
from pathlib import Path

from anonymizer.bridge import ENTITY_MAP, JobAssembler

JOB = {"job_id": "bridge-training", "downstream_target": "training",
       "tenant_id": "default", "confidence_threshold": 0.5}

TEXTS = {"a" * 64: "chunk-zero text.chunk-one text."}


def _fetch(doc_id: str) -> str:
    return TEXTS[doc_id]


def _result(doc_id: str, index: int, total: int, offset: int,
            findings: list[dict] | None = None) -> dict:
    return {
        "file_id": "/data/sources/report.txt",
        "chunk_id": f"report.txt#c{index}",
        "doc_id": doc_id,
        "chunk_offset": offset,
        "total_chunks": total,
        "findings": findings or [],
    }


def _finding(entity: str, start: int, end: int) -> dict:
    return {"entity": entity, "start": start, "end": end,
            "confidence": 0.9, "tier": "regex_checksum", "validated": True}


class TestAssembly:
    def test_emits_only_when_all_chunks_seen(self, tmp_path: Path) -> None:
        a = JobAssembler(_fetch, tmp_path, JOB)
        a.add(_result("a" * 64, 0, total=2, offset=0))
        assert list(tmp_path.glob("*.json")) == []          # half a doc: hold
        a.add(_result("a" * 64, 1, total=2, offset=16))
        assert len(list(tmp_path.glob("*.json"))) == 1      # complete: emit

    def test_spans_shifted_by_chunk_offset(self, tmp_path: Path) -> None:
        a = JobAssembler(_fetch, tmp_path, JOB)
        # out-of-order arrival; chunk 1 starts at offset 16 in canonical text
        a.add(_result("a" * 64, 1, total=2, offset=16,
                      findings=[_finding("EMAIL", 0, 9)]))
        a.add(_result("a" * 64, 0, total=2, offset=0,
                      findings=[_finding("US_SSN", 6, 10)]))

        msg = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
        assert msg["text"] == TEXTS["a" * 64]
        spans = {(f["entity_type"], f["start"], f["end"]) for f in msg["findings"]}
        assert ("SSN", 6, 10) in spans          # chunk 0: unshifted, mapped name
        assert ("EMAIL", 16, 25) in spans       # chunk 1: shifted by 16

    def test_entity_names_mapped_to_policy_vocabulary(self, tmp_path: Path) -> None:
        a = JobAssembler(_fetch, tmp_path, JOB)
        a.add(_result("a" * 64, 0, total=1, offset=0, findings=[
            _finding("MEDICAL_CONDITION", 0, 5), _finding("IP_ADDRESS", 6, 10),
            _finding("PHONE", 11, 15),  # unmapped: passes through
        ]))
        msg = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
        assert [f["entity_type"] for f in msg["findings"]] == ["DIAGNOSIS", "IP", "PHONE"]

    def test_job_and_safe_file_id(self, tmp_path: Path) -> None:
        a = JobAssembler(_fetch, tmp_path, JOB)
        a.add(_result("a" * 64, 0, total=1, offset=0))
        path = next(tmp_path.glob("*.json"))
        msg = json.loads(path.read_text(encoding="utf-8"))
        assert msg["job"] == JOB
        assert msg["file_id"] == f"report-{'a' * 8}"   # stem + doc_id prefix
        assert "/" not in msg["file_id"] and "\\" not in msg["file_id"]
        assert msg["source_path"] == "/data/sources/report.txt"

    def test_missing_doc_id_skipped(self, tmp_path: Path) -> None:
        a = JobAssembler(_fetch, tmp_path, JOB)
        a.add({"file_id": "x", "chunk_id": "x#c0", "findings": []})
        assert a.emitted == 0
        assert list(tmp_path.iterdir()) == []

    def test_duplicate_chunk_is_idempotent(self, tmp_path: Path) -> None:
        a = JobAssembler(_fetch, tmp_path, JOB)
        a.add(_result("a" * 64, 0, total=2, offset=0,
                      findings=[_finding("EMAIL", 1, 2)]))
        a.add(_result("a" * 64, 0, total=2, offset=0,
                      findings=[_finding("EMAIL", 1, 2)]))  # redelivery
        a.add(_result("a" * 64, 1, total=2, offset=16))
        msg = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
        assert len(msg["findings"]) == 1  # not doubled


class TestStaleFlush:
    def test_incomplete_doc_flushed_after_timeout(self, tmp_path: Path) -> None:
        a = JobAssembler(_fetch, tmp_path, JOB, flush_after_s=0.01)
        a.add(_result("a" * 64, 0, total=2, offset=0,
                      findings=[_finding("EMAIL", 1, 2)]))
        time.sleep(0.05)
        a.flush_stale()
        msg = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
        assert len(msg["findings"]) == 1  # partial, but emitted (fail-safe)

    def test_fresh_doc_not_flushed(self, tmp_path: Path) -> None:
        a = JobAssembler(_fetch, tmp_path, JOB, flush_after_s=60.0)
        a.add(_result("a" * 64, 0, total=2, offset=0))
        a.flush_stale()
        assert list(tmp_path.glob("*.json")) == []


class TestEntityMapCoverage:
    def test_high_risk_detection_types_all_mapped_or_native(self) -> None:
        """Every entity the detection engine emits must either map to a policy
        name or already BE a policy name that doesn't fall to suppress-by-
        accident. (Unknown types suppress — safe — but these should be exact.)"""
        policy_names = {"PERSON", "ORG", "ORGANIZATION", "LOCATION", "ADDRESS",
                        "EMAIL", "PHONE", "URL", "IP", "MEDICATION", "DIAGNOSIS",
                        "PROCEDURE", "DATE", "DOB", "ZIP", "PINCODE", "AGE",
                        "CREDIT_CARD", "SSN", "AADHAAR", "PAN", "PASSPORT",
                        "ACCOUNT_NUMBER", "MRN"}
        detection_types = ["CREDIT_CARD", "IBAN", "US_SSN", "IN_AADHAAR",
                           "IN_PAN", "UK_NHS", "MEDICAL_DIAGNOSIS",
                           "MEDICAL_CONDITION", "MEDICATION", "PATIENT_NAME",
                           "DATE_OF_BIRTH", "PERSON", "ADDRESS", "EMAIL",
                           "PHONE", "ORG", "IP_ADDRESS", "FINANCIAL_ACCOUNT"]
        for t in detection_types:
            assert ENTITY_MAP.get(t, t) in policy_names, t
