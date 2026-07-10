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

## Policy engine (regulation packs, Phase 1 — platform docs/07)

`anonymizer/policyengine.py` + `config/regulations/*.yaml`: versioned
regulation packs decide an action per entity at a per-entity confidence bar,
replacing the single global threshold. Selected via `anonymizer bridge
--regulations name1,name2` (also `--packs-dir`, `--policy`, `--review-dir`)
or the platform harness `--regulations`.

Shipped catalog (SHIPPED_PACKS in tests/test_policyengine.py pins it —
extend the tuple when adding a pack): `training_default` / `rag_default`
(bit-identical conversions of masking_policy.yaml), `hipaa_safe_harbor`,
`gdpr_pseudonymization`, `pii_protection` (strict NIST-style baseline,
mask_anyway), `india_dpdp` (DPDP 2023 + UIDAI/RBI/CBDT norms — Aadhaar
suppressed outright), `pci_dss` (PAN unreadable; out-of-scope content kept —
compose with a privacy pack), `ccpa_deidentification`. All except
rag_default are dual-target (guarantee-aware actions only). Packs compose
strictest-wins, so selecting several (e.g. GDPR + PCI) is the intended way
to satisfy overlapping law.

- **Zero engine changes**: `compile_job_policy(packs, target, base_entities)`
  folds packs into existing JobSpec levers — `type_thresholds`,
  `strategy_overrides` (same-strategy overrides preserve the base entry's
  token/indexed/params via `Engine._entry_for`), and `policy_version`
  (pack provenance → lands in receipts AND the idempotency key).
- **Composition** across packs: strictest wins — action severity lattice
  `keep < generalize < tokenize < hash_irreversible < suppress`, lowest
  min_confidence, most aggressive below_threshold (`mask_anyway > review >
  keep`).
- **Fail closed twice**: entities no pack covers compile to
  suppress-at-any-confidence via `base_entities` (execution must match
  `resolve()` decisions — a pack is a complete policy, not an overlay);
  `default_action` must be `suppress` (validator).
- **Guarantee-aware actions**: `hmac_tokenize` → placeholder_indexed
  (training) / hmac_pseudonym (rag); `hash_irreversible` → suppress in
  Phase 1 (render templates like `[REDACTED-SSN-a8f3]` are Phase 2); linkable
  strategies for training raise at compile.
- **Bit-identical defaults**: `training_default`/`rag_default` are mechanical
  conversions of masking_policy.yaml — tests prove output equality with and
  without them; keep all three (masking_policy + the two packs) in sync.
- **Review sink**: gray-zone findings (below min_confidence,
  `below_threshold: review`) append to `review.jsonl`; the document still
  proceeds with that span unmasked (keep semantics + audit trail).
- Pack authoring note: regulations should explicitly `keep` non-identifier
  content they intend to preserve (HIPAA keeps MEDICATION/DIAGNOSIS/
  PROCEDURE — de-identification removes identifiers, not clinical facts).

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
