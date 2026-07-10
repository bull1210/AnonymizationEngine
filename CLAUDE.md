# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

Dual-mode anonymization engine (stage 3 of the DataGuard platform). Consumes
exact entity findings from the upstream detection pipeline plus the canonical
extracted text, and produces sanitized output. Fully offline; no external
network calls.

Two modes with opposite, mutually exclusive guarantees (see README for why):
`training` = irreversible (indexed placeholders, no salts/keys/mappings —
structurally, not by policy); `rag` = consistent (HMAC-SHA256 pseudonyms +
FF3-1 FPE under per-tenant secrets). Every output is re-scanned; leaks →
`LEAK_DETECTED` + quarantine, never delivered. `VERIFIED`/`TRANSFORMED` are
both success statuses.

Sibling repos: `../ExtractionService` (stage 1), `../DocClassification`
(stage 2). Platform compose/docs/harness: `../platform`, `../docs`.

## Commands

```bash
pip install -e ".[dev]"                 # kafka/vault/postgres are separate extras
pytest                                  # ~65 tests incl. Hypothesis; no infra needed
python scripts/run_tests.py             # stdlib-only fallback (air-gapped boxes)

anonymizer worker --config config/app.yaml        # dir-queue worker
anonymizer serve                                  # dry-run/preview API :8000
anonymizer bridge --text-store-url http://extraction-api:8081   # Kafka intake (below)
anonymizer demo | eval | dry-run | validate-config
```

Docker: image installs the `[kafka]` extra (bridge + worker + serve from one
image). Dev secrets via `.env` (`ANON_DEFAULT_HMAC_SALT` etc.); training mode
needs none.

## Layout

- `anonymizer/core/` — stdlib-only algorithms (engine, strategies, spans,
  pseudonyms, checkdigits, dates, vault, verification, storage interfaces)
- boundary layers convert at the edge: `models.py` (pydantic), `policy.py`
  (strict YAML), `fpe.py` (ff3), `api.py` (FastAPI), `worker.py`
  (dir/Kafka intake), `bridge.py` (scan-results assembly), `runtime.py`
  (wires an Engine per job; training engines get NO salt/FPE/vault at all)
- `config/masking_policy.yaml` — (target, ENTITY_TYPE) → strategy;
  `default_strategy: suppress` means unknown types fail closed (over-mask,
  never leak); `hmac_pseudonym`/`fpe` are rejected under `training` at load
  AND runtime

## The bridge (event-driven intake, added 2026-07-10)

`anonymizer/bridge.py` + `anonymizer bridge` CLI subcommand + the
`anonymizer-bridge` service in `../platform/docker-compose.yml`:

- consumes per-chunk `ScanResult` JSON from Kafka `files.scan.results`
- groups by `doc_id`, emits when all `total_chunks` seen (chunk index parsed
  from `chunk_id` suffix `#c{N}`); stale incomplete docs flushed after
  `--flush-after` (default 300s) with partial findings — fail-safe, the
  verification pass still catches anything missed
- shifts each finding by its `chunk_offset` into canonical-text coordinates
- fetches canonical text: `GET {text_store_url}/text/{doc_id}` (extraction API)
- maps detection entity names → policy names via **`ENTITY_MAP`**
  (`US_SSN→SSN`, `IP_ADDRESS→IP`, `MEDICAL_CONDITION→DIAGNOSIS`,
  `PATIENT_NAME→PERSON`, `FINANCIAL_ACCOUNT/IBAN→ACCOUNT_NUMBER`, `UK_NHS→MRN`…)
  — this map is deliberately duplicated in
  `../platform/run_local_pipeline.py`; keep both in sync
- writes `{file_id, source_path, doc_id, text, findings, job}` JSON into the
  worker's directory queue (tmp+rename = atomic for the `*.json` glob);
  `file_id` is sanitized (`{stem}-{doc_id[:8]}`) because it becomes a filename
- `JobAssembler` is the Kafka-free testable core (`tests/test_bridge.py`);
  confluent_kafka is imported only inside `run_bridge`
- keep the bridge at 1 replica (in-memory aggregation state); default job id
  `bridge-{target}` is stable on purpose — receipt idempotency
  (file_id, job_id, policy_version, canonicalizer_version) dedups replays

## Worker message contract

`Worker.process` expects `{"file_id", "text"?, "findings": [{entity_type,
start, end, confidence, tier, validated}], "job": {job_id,
downstream_target, ...}}`; without inline `text` it fetches
`{text_store.url}/text/{file_id}`. Spans are offsets into the canonical
extracted text — replacements applied right-to-left to preserve offsets.

## Rules

- Never let training and rag share pseudonym mechanisms (README explains the
  attack). Never store raw matched text. Never weaken fail-closed defaults.
- Rotation of `hmac_salt`/`ff31_key` ⇒ full corpus re-run; see README runbook.
