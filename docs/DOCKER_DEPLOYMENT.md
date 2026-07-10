# Docker Deployment Guide — Anonymization Engine

Runs the engine and supporting services as containers using the **shipped**
`Dockerfile` and `docker-compose.yaml` at the repo root (this guide matches
them exactly). Optional profiles add Kafka and observability.

---

## 1. Prerequisites

- Docker Engine 24+ with Compose v2 (`docker compose version`)
- 4 GB RAM for the core stack; +4 GB with the kafka/observability profiles

Images:

| Service | Image | Profile |
|---|---|---|
| anonymizer-worker ×2 / anonymizer-api | `anonymizer:latest` (built locally) | core |
| Kafka (KRaft) + topic init | `bitnami/kafka:3.7` | `kafka` |
| Prometheus / Grafana | `prom/prometheus:v2.53.0` / `grafana/grafana:11.1.0` | `observability` |

The detection engine and text store are optional externals: the built-in
regex detector and inline-text messages work with zero extra services.

---

## 2. Bring it up

```bash
cp .env.example .env
# fill the hex keys (dev secrets; production -> section 5):
#   openssl rand -hex 32  -> ANON_DEFAULT_HMAC_SALT, ANON_DEFAULT_FF31_KEY
#   openssl rand -hex 7   -> ANON_DEFAULT_FF31_TWEAK

docker compose up -d --build
docker compose ps

# smoke test
curl http://localhost:8000/health
curl -X POST http://localhost:8000/dry-run -H 'Content-Type: application/json' \
  -d @examples/sample_message.json
```

Configuration flows through two mounted files (`config/app.docker.yaml`,
`config/masking_policy.yaml`) — not through ad-hoc env vars. The only env
the engine reads are the `ANON_<TENANT>_*` dev secrets and `ANON_VAULT_TOKEN`.

Feed documents by copying message JSONs into the input volume:

```bash
docker compose cp mydoc.json anonymizer-worker:/data/input/
docker compose exec anonymizer-worker ls /data/output
```

Scale workers (stateless): `docker compose up -d --scale anonymizer-worker=6`

Optional profiles:

```bash
docker compose --profile kafka up -d           # broker + files.scan.results/files.masked
docker compose --profile observability up -d   # Prometheus :9090, Grafana :3000
```

With Kafka, switch the worker input in `config/app.docker.yaml`:

```yaml
input:
  mode: kafka
  bootstrap_servers: "kafka:9092"
```

(The image already installs the `[kafka]` extra.)

**Full-platform intake (recommended):** when running alongside the extraction
and detection services, don't point the worker at Kafka directly — run the
**bridge** as a sidecar container instead. It consumes raw per-chunk
detection results from `files.scan.results`, reassembles them per document,
fetches the canonical extracted text, and feeds the worker's directory queue
with complete job messages:

```yaml
  anonymizer-bridge:
    image: anonymizer:latest
    command: ["bridge", "--bootstrap", "kafka:9092",
              "--text-store-url", "http://extraction-api:8081",
              "--out-dir", "/data/input", "--target", "training"]
    volumes: [input:/data/input]
```

(The umbrella `platform/docker-compose.yml` ships exactly this wiring.)

---

## 3. Air-gapped installation

```bash
# connected machine
docker build -t anonymizer:latest .
docker save anonymizer:latest bitnami/kafka:3.7 prom/prometheus:v2.53.0 \
  grafana/grafana:11.1.0 -o anonymizer-stack.tar

# target machine
docker load -i anonymizer-stack.tar
docker compose up -d
```

---

## 4. Verify

```bash
# both modes end-to-end inside the container
docker compose exec anonymizer-worker anonymizer eval --docs 40
# expect: 0 residual leaks, 100% consistency, 0 false merges

# metrics (worker serves Prometheus on :9100 in-container)
docker compose exec anonymizer-worker sh -c "wget -qO- localhost:9100/metrics | grep anonymizer_"

# cross-worker consistency: same entity via two replicas -> identical pseudonym
```

---

## 5. Production hardening

1. **Secrets:** replace `secrets.provider: env` with `file` (mounted 0600
   JSON) or `vault` (HashiCorp; set `vault_addr` in app.docker.yaml, supply
   `ANON_VAULT_TOKEN` via a Docker/K8s secret, build image with `.[vault]`).
   Never bake keys into images or compose files.
2. **State:** `db_path` sits on the `state` volume (SQLite). Back it up —
   receipts are the audit trail. For multi-host scale-out, move the state
   interfaces to Postgres (`migrations/001_init.sql` ships the schema;
   implement the 4 interfaces in `anonymizer/core/storage.py`). The
   collision registry is the only shared mutable state RAG workers need.
3. **TLS everywhere:** Kafka (SASL_SSL), Vault, and put the API behind your
   reverse proxy with TLS + authn.
4. **Kafka:** the compose broker is single-node (RF=1) — evaluation only.
   Production: 3 brokers, RF=3, and wire the `files.masked` producer in
   `Worker._publish_masked`.
5. **Alerting:** page on any increase of `anonymizer_leaks_total`; warn on
   `anonymizer_pseudonym_collisions_total` and consumer lag.
6. **Key rotation:** tenant salt rotation ⇒ every pseudonym changes ⇒ full
   corpus re-run (README runbook). Never rotate mid-run.
7. **Resource limits:** add `mem_limit`/`cpus`; workers are CPU-bound.

---

## 6. Troubleshooting

| Symptom | Fix |
|---|---|
| Worker exits: policy validation error | Bad `masking_policy.yaml` mount — `docker compose logs anonymizer-worker` names the field |
| RAG job: "requires a salt provider" | `.env` keys missing/blank, or provider misconfigured in app.docker.yaml |
| `FPE unavailable` warning, `<PHONE>`/`<CREDIT_CARD>` placeholders in RAG output | `ff3` missing from the image — it's in the default deps; rebuild the image |
| Pseudonyms changed between runs | Salt changed (fresh `.env`?) or `salt_scope: run` — both documented behaviors |
| All docs `LEAK_DETECTED` | Findings' offsets don't match the text being transformed — feed the canonical text, never re-extract |
| Nothing consumed from `/data/input` | Files must be `*.json` messages; failures are renamed `*.failed` with logs |
