"""Wire an Engine from app config (shared by worker, API and CLI)."""
from __future__ import annotations

from pathlib import Path

from .core.detection import HTTPDetector, RegexDetector
from .core.engine import Engine
from .core.policyload import load_policy_yaml
from .core.storage import AuditLog, Database, ReceiptStore, SqliteCollisionRegistry, VaultStore
from .core.types import JobSpec, PolicyTable
from .core.vault import ReidVault
from .secrets import BaseProvider, provider_from_config


def load_app_config(path: str) -> dict:
    import yaml

    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


class Runtime:
    def __init__(self, cfg: dict) -> None:
        self.cfg = cfg
        self.policy: PolicyTable = self._load_policy()
        self.db = Database(cfg.get("db_path", "anonymizer.db"))
        self.receipts = ReceiptStore(self.db)
        self.registry = SqliteCollisionRegistry(self.db)
        self.audit = AuditLog(self.db)
        self.secrets: BaseProvider = provider_from_config(cfg.get("secrets", {"provider": "env"}))
        self.output_dir = Path(cfg.get("output_dir", "output"))
        self._vault_cache: dict[str, ReidVault] = {}
        self._fpe_cache: dict[str, object] = {}

        det_cfg = cfg.get("detection", {"mode": "regex"})
        if det_cfg.get("mode") == "http":
            self.detector = HTTPDetector(det_cfg["url"])
        elif det_cfg.get("mode") == "none":  # dev only — documents stay UNVERIFIED
            self.detector = None
        else:
            self.detector = RegexDetector()

    def _load_policy(self) -> PolicyTable:
        path = self.cfg.get("policy_path", "config/masking_policy.yaml")
        try:  # strict pydantic loader when available
            from .policy import load_policy

            return load_policy(path)
        except ImportError:
            return load_policy_yaml(path)

    # ------------------------------------------------------------------ #

    def vault_for(self, tenant_id: str) -> ReidVault:
        if tenant_id not in self._vault_cache:
            self._vault_cache[tenant_id] = ReidVault(
                self.secrets.vault_key(tenant_id), VaultStore(self.db), self.audit
            )
        return self._vault_cache[tenant_id]

    def fpe_for(self, tenant_id: str):
        if tenant_id not in self._fpe_cache:
            try:
                from .fpe import FF3Cipher

                key, tweak = self.secrets.fpe_key(tenant_id)
                self._fpe_cache[tenant_id] = FF3Cipher(key, tweak)
            except (RuntimeError, ImportError) as exc:
                # Safe direction: without ff3 the engine falls back to
                # placeholders for fpe-strategy types (over-masking).
                import logging

                logging.getLogger(__name__).warning(
                    "FPE unavailable (%s); fpe-strategy types fall back to placeholders", exc
                )
                self._fpe_cache[tenant_id] = None
        return self._fpe_cache[tenant_id]

    def engine_for(self, job: JobSpec) -> Engine:
        """Training jobs get an engine with NO salts, NO FPE, NO vault wired
        in at all — the irreversibility invariant is structural, not advisory."""
        if job.target.value == "training":
            return Engine(
                self.policy,
                detector=self.detector,
                receipt_store=self.receipts,
            )
        needs_fpe = any(
            e.strategy.value == "fpe" for (t, _), e in self.policy.entries.items() if t == "rag"
        )
        return Engine(
            self.policy,
            salt_provider=self.secrets.hmac_salt,
            fpe=self.fpe_for(job.tenant_id) if needs_fpe else None,
            vault=self.vault_for(job.tenant_id) if job.reversible else None,
            detector=self.detector,
            receipt_store=self.receipts,
            collision_registry=self.registry,
        )
