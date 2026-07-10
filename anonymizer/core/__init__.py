"""Stdlib-only core: every algorithm lives here, free of third-party imports.

Boundary layers (pydantic models, FastAPI, ff3, Kafka) live one package up and
convert external input into these core dataclasses. This keeps validation at
the edge and the transformation logic pure, deterministic, and testable.
"""
