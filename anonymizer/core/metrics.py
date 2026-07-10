"""Prometheus metrics with a no-op fallback when prometheus_client is absent.
Metric values never include original sensitive text."""
from __future__ import annotations

try:
    from prometheus_client import Counter, Histogram  # type: ignore

    DOCS_PROCESSED = Counter("anonymizer_docs_processed_total", "Documents processed", ["mode"])
    SPANS_REPLACED = Counter(
        "anonymizer_spans_replaced_total", "Spans replaced", ["mode", "entity_type", "strategy"]
    )
    LEAKS = Counter("anonymizer_leaks_total", "Verification leaks", ["entity_type"])
    COLLISIONS = Counter("anonymizer_pseudonym_collisions_total", "Truncation collisions")
    VAULT_WRITES = Counter("anonymizer_vault_writes_total", "Re-id vault writes")
    TRANSFORM_SECONDS = Histogram("anonymizer_transform_seconds", "Transform latency")
except ImportError:  # pragma: no cover

    class _Noop:
        def labels(self, *a, **k):  # noqa: D401
            return self

        def inc(self, *a, **k) -> None:
            pass

        def observe(self, *a, **k) -> None:
            pass

        def time(self):
            import contextlib

            return contextlib.nullcontext()

    DOCS_PROCESSED = SPANS_REPLACED = LEAKS = COLLISIONS = VAULT_WRITES = _Noop()  # type: ignore
    TRANSFORM_SECONDS = _Noop()  # type: ignore
