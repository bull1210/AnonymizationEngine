"""Secrets providers. Keys never live in config files.

Providers: env (dev only), file-KMS (0600 JSON, local KMS stand-in), and
HashiCorp Vault (production). Per-tenant keys, three independent secrets:
  hmac_salt (RAG pseudonyms) | ff31_key+tweak (FPE) | vault_key (re-id vault)
Never derive one from another. salt_scope=corpus|run derives a scoped salt
via HMAC(tenant_salt, scope) — 'run' deliberately breaks cross-run
consistency (one-off exports only).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from pathlib import Path

from .core.types import JobSpec


class SecretsError(RuntimeError):
    pass


class BaseProvider:
    def _tenant(self, tenant_id: str) -> dict:  # pragma: no cover - abstract
        raise NotImplementedError

    def hmac_salt(self, job: JobSpec) -> bytes:
        raw = bytes.fromhex(self._require(job.tenant_id, "hmac_salt"))
        if job.salt_scope == "tenant":
            return raw
        if job.salt_scope == "corpus":
            scope = f"corpus|{job.corpus_id or 'default'}"
        elif job.salt_scope == "run":
            scope = f"run|{job.job_id}"
        else:
            raise SecretsError(f"unknown salt_scope '{job.salt_scope}'")
        return hmac.new(raw, scope.encode(), hashlib.sha256).digest()

    def fpe_key(self, tenant_id: str) -> tuple[str, str]:
        return self._require(tenant_id, "ff31_key"), self._require(tenant_id, "ff31_tweak")

    def vault_key(self, tenant_id: str) -> bytes:
        return bytes.fromhex(self._require(tenant_id, "vault_key"))

    def _require(self, tenant_id: str, name: str) -> str:
        val = self._tenant(tenant_id).get(name)
        if not val:
            raise SecretsError(f"secret '{name}' missing for tenant '{tenant_id}'")
        return val


class EnvProvider(BaseProvider):
    """Dev only: ANON_<TENANT>_HMAC_SALT etc. (hex)."""

    def _tenant(self, tenant_id: str) -> dict:
        prefix = f"ANON_{tenant_id.upper()}_"
        return {
            "hmac_salt": os.environ.get(prefix + "HMAC_SALT", ""),
            "ff31_key": os.environ.get(prefix + "FF31_KEY", ""),
            "ff31_tweak": os.environ.get(prefix + "FF31_TWEAK", ""),
            "vault_key": os.environ.get(prefix + "VAULT_KEY", ""),
        }


class FileKmsProvider(BaseProvider):
    """Local KMS stand-in: JSON file {tenant: {hmac_salt,...}}, mode 0600."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        mode = stat.S_IMODE(self._path.stat().st_mode)
        if mode & 0o077:
            raise SecretsError(f"{path}: must be readable by owner only (chmod 600)")
        self._data = json.loads(self._path.read_text())

    def _tenant(self, tenant_id: str) -> dict:
        if tenant_id not in self._data:
            raise SecretsError(f"tenant '{tenant_id}' not in KMS file")
        return self._data[tenant_id]


class HashicorpVaultProvider(BaseProvider):
    """Production: secret/anonymizer/tenants/<tenant_id> in HashiCorp Vault."""

    def __init__(self, addr: str, token: str, mount: str = "secret") -> None:
        try:
            import hvac  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise SecretsError("pip install 'anonymizer[vault]' for HashiCorp Vault") from exc
        self._client = hvac.Client(url=addr, token=token)
        self._mount = mount
        self._cache: dict[str, dict] = {}

    def _tenant(self, tenant_id: str) -> dict:
        if tenant_id not in self._cache:
            resp = self._client.secrets.kv.v2.read_secret_version(
                path=f"anonymizer/tenants/{tenant_id}", mount_point=self._mount
            )
            self._cache[tenant_id] = resp["data"]["data"]
        return self._cache[tenant_id]


def provider_from_config(cfg: dict) -> BaseProvider:
    kind = cfg.get("provider", "env")
    if kind == "env":
        return EnvProvider()
    if kind == "file":
        return FileKmsProvider(cfg["path"])
    if kind == "vault":
        return HashicorpVaultProvider(
            cfg["vault_addr"], cfg.get("vault_token") or os.environ["ANON_VAULT_TOKEN"]
        )
    raise SecretsError(f"unknown secrets provider '{kind}'")
