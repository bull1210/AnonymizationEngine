"""Dual-mode anonymization engine.

Mode 1 (training): deterministic, irreversible masking for LLM training corpora.
Mode 2 (rag):      consistent, stateless HMAC pseudonymization for RAG indexes.

The two modes intentionally share NO pseudonym mechanism. See README.
"""

__version__ = "1.0.0"
