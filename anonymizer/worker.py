"""Stateless worker: consume scan results, fetch text, transform, verify,
write masked artifacts to /output/{job_id}/{file_id}, publish files.masked.

Sources: Kafka (production, optional dependency) or a JSON directory queue
(dev/air-gapped). Quarantined (LEAK_DETECTED) documents are written under
quarantine/ and never to the output store. Idempotent by
(file_id, job_id, policy_version, canonicalizer_version) via the receipt PK.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Iterator

from .core import metrics
from .core.types import Status, finding_from_dict, jobspec_from_dict
from .runtime import Runtime

log = logging.getLogger(__name__)


class DirectorySource:
    """Reads job files: {"file_id", "text", "findings": [...], "job": {...}}.
    Processed files are moved to .done/.failed suffixes."""

    def __init__(self, input_dir: str | Path) -> None:
        self._dir = Path(input_dir)

    def poll(self) -> Iterator[tuple[dict, Path]]:
        for path in sorted(self._dir.glob("*.json")):
            try:
                yield json.loads(path.read_text(encoding="utf-8")), path
            except (json.JSONDecodeError, OSError) as exc:
                log.error("unreadable message %s: %s", path, exc)
                path.rename(path.with_suffix(".failed"))


class KafkaSource:  # pragma: no cover - requires broker
    def __init__(self, bootstrap: str, topic: str = "files.scan.results",
                 group: str = "anonymizer-workers") -> None:
        from confluent_kafka import Consumer  # type: ignore

        self._consumer = Consumer(
            {"bootstrap.servers": bootstrap, "group.id": group,
             "auto.offset.reset": "earliest", "enable.auto.commit": False}
        )
        self._consumer.subscribe([topic])

    def poll(self) -> Iterator[tuple[dict, None]]:
        while True:
            msg = self._consumer.poll(1.0)
            if msg is None:
                return
            if msg.error():
                log.error("kafka error: %s", msg.error())
                continue
            yield json.loads(msg.value()), None
            self._consumer.commit(msg)


class Worker:
    def __init__(self, runtime: Runtime) -> None:
        self.rt = runtime

    def process(self, message: dict) -> str:
        job = jobspec_from_dict(message["job"])
        file_id = str(message["file_id"])
        findings = [finding_from_dict(d) for d in message.get("findings", [])]
        text = message.get("text")
        if text is None:
            text = self._fetch_text(file_id)  # canonical text store — never re-extract

        engine = self.rt.engine_for(job)
        with metrics.TRANSFORM_SECONDS.time():
            result = engine.transform(text, findings, job, file_id)
        receipt = result.receipt

        metrics.DOCS_PROCESSED.labels(mode=receipt.mode).inc()
        for r in receipt.replacements:
            metrics.SPANS_REPLACED.labels(
                mode=receipt.mode, entity_type=r.entity_type, strategy=r.strategy
            ).inc()

        if receipt.status == Status.LEAK_DETECTED.value:
            for leak in receipt.leaks:
                metrics.LEAKS.labels(entity_type=leak.entity_type).inc()
            qdir = self.rt.output_dir / "quarantine" / job.job_id
            qdir.mkdir(parents=True, exist_ok=True)
            (qdir / f"{file_id}.receipt.json").write_text(
                json.dumps(receipt.to_dict(), indent=2), encoding="utf-8"
            )
            log.error("quarantined file=%s job=%s (leak)", file_id, job.job_id)
            return receipt.status

        out = self.rt.output_dir / job.job_id
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{file_id}.txt").write_text(result.masked_text, encoding="utf-8")
        (out / f"{file_id}.receipt.json").write_text(
            json.dumps(receipt.to_dict(), indent=2), encoding="utf-8"
        )
        self._publish_masked(file_id, job.job_id, receipt.status)
        return receipt.status

    def _fetch_text(self, file_id: str) -> str:
        import urllib.request

        base = self.rt.cfg.get("text_store", {}).get("url")
        if not base:
            raise RuntimeError("message lacked inline text and no text_store.url configured")
        with urllib.request.urlopen(f"{base.rstrip('/')}/text/{file_id}", timeout=30) as r:  # noqa: S310
            return r.read().decode("utf-8")

    def _publish_masked(self, file_id: str, job_id: str, status: str) -> None:
        event = {"event": "files.masked", "file_id": file_id, "job_id": job_id,
                 "status": status, "ts": time.time()}
        events = self.rt.output_dir / "events.jsonl"
        with events.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")
        # Kafka producer integration mirrors KafkaSource; enabled when
        # cfg["kafka"]["bootstrap_servers"] is set and confluent-kafka installed.

    def run_forever(self, source: DirectorySource, poll_interval: float = 2.0) -> None:
        log.info("worker started")
        while True:
            processed = 0
            for message, path in source.poll():
                try:
                    status = self.process(message)
                    if path is not None:
                        path.rename(path.with_suffix(f".done.{status.lower()}"))
                except Exception:  # keep the worker alive; message parked
                    log.exception("failed processing %s", path)
                    if path is not None:
                        path.rename(path.with_suffix(".failed"))
                processed += 1
            if processed == 0:
                time.sleep(poll_interval)
