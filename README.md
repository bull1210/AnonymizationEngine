# Anonymization Engine

Dual-mode transformation service for an on-premise file-intelligence platform.
Consumes exact entity findings from the upstream detection pipeline plus the
canonical extracted text, and produces sanitized output for the configured
downstream target. Fully offline; no external network calls.

| Mode | Guarantee | Mechanism |
|---|---|---|
| `training` | **Irreversible.** No artifact exists from which originals can be recovered. | Per-document indexed placeholders, generalization, per-document date shift. No salts, no keys, no mapping storage. |
| `rag` | **Consistent.** Same real-world entity ⇒ bit-identical pseudonym across all files/workers/runs (within salt scope). | Stateless `HMAC-SHA256(canonical, tenant_salt)` surrogates + FF3-1 FPE for structured numbers. |

New to the project? Start with `docs/GUIDE_FOR_NEW_USERS.md` (jargon-free).
Deployment: `docs/DEPLOYMENT_GUIDE.md` (bare metal) / `docs/DOCKER_DEPLOYMENT.md`.

## Architecture

```
 files.scan.results          ┌────────────────────────────────────────────┐
 (Kafka / dir queue) ──────► │  Worker (stateless, scale horizontally)     │
                             │                                            │
 text store ───────────────► │  1 threshold filter (mask at ≥0.5, per-type)│
 (canonical text by file_id) │  2 overlap/nesting resolution               │
                             │  3 strategy per span (policy engine)        │
 masking_policy.yaml ──────► │  4 apply RIGHT-TO-LEFT (offset integrity)   │
 (pydantic-validated)        │  5 TransformReceipt -> Postgres/SQLite      │
                             │  6 VERIFICATION PASS (re-detect masked text)│
 KMS / HashiCorp Vault ────► │       leak ⇒ LEAK_DETECTED, quarantined     │
 (RAG mode only)             └───────┬───────────────────────┬────────────┘
                                     ▼                       ▼
                          /output/{job}/{file}         files.masked event
```

Package layout: `anonymizer/core/` is stdlib-only (all algorithms, fully
testable anywhere); boundary layers (`models.py` pydantic contracts,
`policy.py` strict YAML validation, `fpe.py` ff3, `api.py` FastAPI,
`worker.py` Kafka/dir intake) convert at the edge.

## Quickstart

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"                 # full install
pytest                                  # or, stdlib-only: python scripts/run_tests.py

python -m anonymizer.cli demo           # side-by-side view of both modes
python -m anonymizer.cli eval --docs 60 # KPI report (leak/consistency/false-merge)

cp config/app.example.yaml config/app.yaml
anonymizer validate-config --app config/app.yaml --policy config/masking_policy.yaml
anonymizer dry-run --input examples/sample_message.json --redline preview.html
anonymizer worker --config config/app.yaml   # dir-queue worker
anonymizer serve                             # FastAPI dry-run/preview API :8000
anonymizer bridge --text-store-url http://extraction-api:8081   # Kafka scan-results -> jobs
```

Docker: `cp .env.example .env`, fill hex keys, `docker compose up -d --build`.

## Placeholder token vocabulary (training mode)

Register these as special tokens in the training pipeline:
`<NAME_n> <ORG_n> <LOC_n> <ADDR_n>` (indexed, n resets per document) and bare
`<EMAIL> <PHONE> <URL> <IP> <MEDICATION> <DIAGNOSIS> <PROCEDURE> <DATE> <ZIP> <AGE>`.
Index scope is per document: `<NAME_1>` in two different documents are
unrelated people by construction.

## Key management & rotation runbook

Three independent secrets per tenant — never derive one from another:

| Secret | Used for | Rotation consequence |
|---|---|---|
| `hmac_salt` (256-bit) | RAG pseudonyms | **Every pseudonym changes ⇒ full corpus re-run.** Schedule as batch; never rotate mid-run. |
| `ff31_key` + `ff31_tweak` | FF3-1 FPE | All FPE ciphertexts change ⇒ re-run affected corpora. |
| `vault_key` (256-bit) | Re-id vault AES-256-GCM | Re-encrypt vault rows (`reid_vault`); pseudonyms unaffected. |

Rotation procedure: 1) create new secret version in KMS/Vault; 2) freeze
intake for the tenant; 3) re-run all jobs (idempotency key includes
`policy_version`/`canonicalizer_version` — bump job ids or versions);
4) verify eval-harness consistency = 100% on the new run; 5) retire old salt.
Training mode uses **no keys at all** and is unaffected by any rotation.

`salt_scope: run` derives a per-job salt — cross-run consistency is
intentionally destroyed; use only for one-off exports.

A canonicalizer change (bump `CANONICALIZER_VERSION`) also changes pseudonyms:
same full-re-run requirement. The version is recorded in every receipt and
salted into the HMAC context so mixed-version output cannot silently collide.

## HIPAA Safe Harbor mapping

| Safe Harbor identifier | Engine handling (training) |
|---|---|
| Names | `<NAME_n>` indexed placeholders |
| Geographic subdivisions < state | `<LOC_n>`/`<ADDR_n>`; ZIP → first 3 digits (`560XXX`) |
| Dates (except year) | `date_shift` (±365d/doc, intervals kept) or year-only |
| Ages > 89 | `90+` bracket |
| Phone / fax | `<PHONE>` |
| Email | `<EMAIL>` |
| SSN / MRN / account / license | `suppress` (removed) |
| Card/device/vehicle identifiers | `suppress` |
| URLs / IPs | `<URL>` / `<IP>` |
| Biometric identifiers | detection-side; `suppress` on unknown types (fail closed) |
| Any other unique identifier | unknown types default to `suppress` |

## Why training and RAG must never share pseudonym mechanisms

Training mode's guarantee is *unlinkability*: model weights may memorize
tokens, so no token may correlate with an identity beyond one document —
placeholder counters reset per document precisely to destroy cross-document
signal, and no salt/key/mapping exists that could reconnect them.

RAG mode's guarantee is the opposite: *stable linkage* under a secret salt.
`User_91a4b` deliberately identifies the same person everywhere; security
rests on the salt staying secret, and reversibility (if enabled) lives in an
encrypted vault. If training data ever used salted stable pseudonyms, (a) a
salt leak would retroactively de-anonymize the trained model's memorized
text, and (b) cross-document tokens would let the model learn identity
graphs. Conversely, RAG cannot use per-document placeholders — retrieval
would lose every cross-document relationship. The two mechanisms are
mutually exclusive by policy validation (`fpe`/`hmac_pseudonym` are rejected
under `training` at load time AND at runtime) and by construction (training
engines are wired with no salt provider, no FPE cipher, no vault, no
collision registry — see `Runtime.engine_for`).

## Verification pass & KPIs

Every transformed document is re-scanned (built-in Tier-1 regex detector
and/or the real detection engine over HTTP). Findings ≥ threshold outside
replacement spans, whose policy is not `keep`, quarantine the document
(`LEAK_DETECTED`) — it is never delivered. `anonymizer eval` ships the KPI
harness: residual-leak rate, quarantine rate, RAG cross-document consistency
rate, and false-merge rate (current synthetic-corpus results: 0 leaks, 100%
consistency, 0 false merges).

## Implementation status / extension points

- State stores default to SQLite (zero-dependency, thread-safe). The Postgres
  schema ships in `migrations/001_init.sql`; production Postgres adapters
  implement the same 4 small interfaces in `core/storage.py`.
- Kafka intake (`confluent-kafka`) and HashiCorp Vault secrets (`hvac`) are
  optional extras: `pip install -e ".[kafka,vault,postgres]"`.
- `anonymizer bridge` (`anonymizer/bridge.py`) is the event-driven intake for
  the full platform: it consumes per-chunk detection results from
  `files.scan.results`, reassembles them per document (spans shifted by chunk
  offset), fetches the canonical extracted text from the extraction service
  (`GET /text/{doc_id}`), maps detection entity names onto the policy
  vocabulary, and feeds the worker's directory queue.
- Regulation packs (`anonymizer/policyengine.py` + `config/regulations/`):
  versioned per-regulation rules — entity, per-entity `min_confidence`,
  action — selected per job via `anonymizer bridge --regulations
  hipaa_safe_harbor`. Compiled into JobSpec levers (zero engine changes),
  provenance recorded in every receipt, unknown entities fail closed,
  gray-zone findings land in a review sink. Design: platform
  `docs/07_POLICY_ENGINE_DESIGN.md`.
- The `files.masked` event is appended to `output/events.jsonl`; wire the
  Kafka producer in `Worker._publish_masked` when a broker is configured.
- Tests: `pytest` runs 56+ tests incl. Hypothesis property tests; air-gapped
  boxes can run `python scripts/run_tests.py` (stdlib only).
