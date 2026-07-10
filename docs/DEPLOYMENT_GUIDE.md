# Deployment Guide — Anonymization Engine (Bare-Metal / VM Install)

Step-by-step instructions to install and run the engine on a new machine
**without Docker**. For containers, see `DOCKER_DEPLOYMENT.md`.
This guide matches the shipped code exactly.

---

## 1. Prerequisites

| Requirement | Minimum | Notes |
|---|---|---|
| OS | Linux (Ubuntu 22.04+/RHEL 9) or Windows | Fully offline network is fine |
| Python | **3.10+** (3.11 recommended) | Pydantic v2, FastAPI, ff3 via pip |
| State store | none (SQLite built in) | Postgres optional: schema in `migrations/001_init.sql`; adapters implement the 4 interfaces in `anonymizer/core/storage.py` |
| Kafka | optional | Directory-queue input works out of the box; Kafka consumer via `pip install ".[kafka]"` |
| Secrets | env (dev) / JSON KMS file / HashiCorp Vault | RAG mode only — training mode uses no keys at all |
| RAM / CPU | 2 GB / 1 core per worker | Stateless; scale horizontally |

No internet access is required at runtime. For offline installs, build a
wheelhouse on a connected machine: `pip wheel . -w wheelhouse/`.

---

## 2. Install

```bash
sudo mkdir -p /opt/anonymizer && sudo chown "$USER" /opt/anonymizer
cd /opt/anonymizer
git clone <your-repo-url> .          # or unpack the release tarball

python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"              # add: .[kafka,vault] as needed
# offline: pip install --no-index --find-links wheelhouse -e .

pytest                               # full suite (56+ tests)
# constrained boxes without pytest:
python scripts/run_tests.py
```

---

## 3. Configure secrets (RAG jobs only)

Three independent secrets per tenant — never derive one from another.
Training jobs need none of this.

```bash
# Option A — dev only: environment variables (tenant "default")
export ANON_DEFAULT_HMAC_SALT=$(openssl rand -hex 32)
export ANON_DEFAULT_FF31_KEY=$(openssl rand -hex 32)
export ANON_DEFAULT_FF31_TWEAK=$(openssl rand -hex 7)
export ANON_DEFAULT_VAULT_KEY=$(openssl rand -hex 32)   # only if reversible: true

# Option B — local KMS file (chmod 600), config: secrets.provider: file
cat > /etc/anonymizer/kms.json <<EOF
{"default": {"hmac_salt": "$(openssl rand -hex 32)",
             "ff31_key": "$(openssl rand -hex 32)",
             "ff31_tweak": "$(openssl rand -hex 7)",
             "vault_key": "$(openssl rand -hex 32)"}}
EOF
chmod 600 /etc/anonymizer/kms.json

# Option C — HashiCorp Vault (production), config: secrets.provider: vault
vault kv put secret/anonymizer/tenants/default \
  hmac_salt=$(openssl rand -hex 32) ff31_key=$(openssl rand -hex 32) \
  ff31_tweak=$(openssl rand -hex 7) vault_key=$(openssl rand -hex 32)
export ANON_VAULT_TOKEN=<approle-or-token>     # read by the engine
```

**Rotating `hmac_salt` re-keys every pseudonym ⇒ full corpus re-run** (see
README runbook).

---

## 4. Application configuration

```bash
cp config/app.example.yaml /etc/anonymizer/app.yaml
cp config/masking_policy.yaml /etc/anonymizer/masking_policy.yaml
```

`app.yaml` (authoritative schema — matches `config/app.example.yaml`):

```yaml
policy_path: /etc/anonymizer/masking_policy.yaml
db_path: /var/lib/anonymizer/anonymizer.db   # SQLite state (receipts/collisions/vault)
output_dir: /output                          # masked artifacts: /output/{job_id}/
input:
  mode: dir                                  # dir | kafka
  dir: /var/lib/anonymizer/input
  # mode: kafka
  # bootstrap_servers: "broker1:9092,broker2:9092"
text_store:
  # url: "http://text-store:8080"            # optional; else messages carry inline text
detection:
  mode: regex                                # regex (built-in) | http (real engine) | none
  # url: "http://detection:8080"             # when mode: http
secrets:
  provider: env                              # env | file | vault
  # path: /etc/anonymizer/kms.json           # provider: file
  # vault_addr: "https://vault.internal:8200" # provider: vault
```

Validate before starting (refuses invalid policy; unknown types fail closed):

```bash
anonymizer validate-config --app /etc/anonymizer/app.yaml \
  --policy /etc/anonymizer/masking_policy.yaml
```

---

## 5. Run

```bash
# ad-hoc / batch
anonymizer run --in /path/to/folder --target training --config /etc/anonymizer/app.yaml

# services
anonymizer worker --config /etc/anonymizer/app.yaml      # queue consumer
anonymizer serve  --config /etc/anonymizer/app.yaml      # dry-run/preview API :8000
```

### systemd units

`/etc/systemd/system/anonymizer-worker@.service`:

```ini
[Unit]
Description=Anonymizer worker %i
After=network.target

[Service]
User=anonymizer
Environment=PROMETHEUS_PORT=91%i
ExecStart=/opt/anonymizer/.venv/bin/anonymizer worker --config /etc/anonymizer/app.yaml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`anonymizer-api.service`: same pattern with
`ExecStart=/opt/anonymizer/.venv/bin/anonymizer serve --config /etc/anonymizer/app.yaml`.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now anonymizer-worker@{01..04} anonymizer-api
```

---

## 6. Verify the installation

```bash
curl http://localhost:8000/health

# CLI dry run (writes no artifacts; produces redline HTML)
anonymizer dry-run --input examples/sample_message.json --redline preview.html

# API dry run — body carries text + findings + job (see examples/sample_message.json)
curl -X POST http://localhost:8000/dry-run -H 'Content-Type: application/json' \
  -d @examples/sample_message.json

# End-to-end: drop a message into the input dir, then check
#   /output/{job_id}/{file_id}.txt + .receipt.json, output/events.jsonl,
#   and that status is VERIFIED (LEAK_DETECTED docs land in output/quarantine/)

# Metrics (worker exposes Prometheus when prometheus-client is installed)
curl http://localhost:9101/metrics | grep anonymizer_

# KPIs on the synthetic corpus
anonymizer eval --docs 60
```

---

## 7. Operational checklist

- [ ] Policy signed off via dry-run redline; confidence thresholds reviewed
- [ ] `salt_scope` confirmed (`tenant` unless one-off export)
- [ ] `reversible` explicitly set (default false ⇒ zero vault rows)
- [ ] Prometheus scraping worker ports; alert on `anonymizer_leaks_total` > 0
- [ ] `db_path` on backed-up storage (receipts = audit trail)
- [ ] Key-rotation runbook filed (README): salt rotation ⇒ full re-run

## Troubleshooting

| Symptom | Fix |
|---|---|
| Startup: policy validation error | Fix the named field in `masking_policy.yaml`; never bypass |
| Everything `LEAK_DETECTED` | Engine and detector reading different text than the offsets were computed against — never re-extract |
| Same entity, different pseudonyms | Mixed salts/`salt_scope: run`/different `CANONICALIZER_VERSION` across workers — align builds and secrets |
| `FPE unavailable` warning | `pip install ff3`; until then fpe-types fall back to safe placeholders |
| RAG job: "requires a salt provider" | Secrets not configured — see section 3 |
