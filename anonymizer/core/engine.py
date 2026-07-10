"""The transformation engine shared by both modes.

Pipeline: threshold filter -> overlap/nesting resolution -> per-span strategy
-> right-to-left application -> receipt -> mandatory verification pass.

Mode invariants enforced here (again, besides policy-load validation):
  * training: no salt is ever fetched, no vault is ever written, receipts
    carry no original surface text;
  * rag: pseudonyms are computed statelessly (HMAC) so parallel workers agree
    bit-for-bit; the collision registry is the only shared state.
"""
from __future__ import annotations

import logging
from typing import Callable, Protocol

from .canonicalize import CANONICALIZER_VERSION, canonicalize
from .detection import Detector
from .pseudonym import CollisionRegistry, PseudonymEngine
from .spans import apply_replacements, filter_by_threshold, resolve_overlaps
from .storage import ReceiptStore
from .strategies import DocContext, date_shift, generalize, placeholder, token_name
from .types import (
    LINKABLE_STRATEGIES,
    Finding,
    JobSpec,
    PolicyEntry,
    PolicyTable,
    PolicyViolation,
    Receipt,
    Status,
    Strategy,
    Target,
    TransformResult,
)
from .vault import ReidVault
from .verification import verify

log = logging.getLogger(__name__)


class FpeCipher(Protocol):
    def encrypt(self, entity_type: str, surface: str) -> str | None:
        """Format-preserving encrypt; None if the value is outside the FPE
        domain (caller falls back to a safe placeholder)."""
        ...


SaltProvider = Callable[[JobSpec], bytes]


class Engine:
    def __init__(
        self,
        policy: PolicyTable,
        *,
        salt_provider: SaltProvider | None = None,
        fpe: FpeCipher | None = None,
        vault: ReidVault | None = None,
        detector: Detector | None = None,
        receipt_store: ReceiptStore | None = None,
        collision_registry: CollisionRegistry | None = None,
    ) -> None:
        policy.validate_mode_invariants()
        self._policy = policy
        self._salt_provider = salt_provider
        self._fpe = fpe
        self._vault = vault
        self._detector = detector
        self._receipts = receipt_store
        self._registry = collision_registry

    # ------------------------------------------------------------------ #

    def transform(
        self, text: str, findings: list[Finding], job: JobSpec, file_id: str
    ) -> TransformResult:
        training = job.target == Target.TRAINING
        ctx = DocContext()
        pseud: PseudonymEngine | None = None
        vault_pending: list[tuple[str, str, str]] = []  # (pseudonym, original, type)

        spans = resolve_overlaps(filter_by_threshold(findings, job))

        plan: list[tuple[Finding, str, str]] = []
        for f in spans:
            entry = self._entry_for(job, f.entity_type)
            if entry.strategy == Strategy.KEEP:
                continue
            if training and entry.strategy in LINKABLE_STRATEGIES:
                raise PolicyViolation(
                    f"{entry.strategy.value} requested in training mode for {f.entity_type}"
                )
            surface = text[f.start : f.end]

            if entry.strategy == Strategy.SUPPRESS:
                rep = ""
            elif entry.strategy == Strategy.PLACEHOLDER_INDEXED:
                rep = placeholder(ctx, f.entity_type, surface, entry)
            elif entry.strategy == Strategy.GENERALIZE:
                rep = generalize(f.entity_type, surface, entry)
            elif entry.strategy == Strategy.DATE_SHIFT:
                rep = date_shift(ctx, surface)
            elif entry.strategy == Strategy.HMAC_PSEUDONYM:
                if pseud is None:
                    pseud = self._pseudonym_engine(job)
                canonical = canonicalize(f.entity_type, surface)
                rep = pseud.token(f.entity_type, canonical)
                if job.reversible and self._vault is not None:
                    vault_pending.append((rep, surface, f.entity_type))
            elif entry.strategy == Strategy.FPE:
                rep = self._fpe_encrypt(f.entity_type, surface, entry)
            else:  # unreachable; fail closed anyway
                rep = ""
            plan.append((f, rep, entry.strategy.value))

        masked, replacements = apply_replacements(text, plan, redact_originals=training)

        receipt = Receipt(
            file_id=file_id,
            job_id=job.job_id,
            mode=job.target.value,
            policy_version=job.policy_version or self._policy.version,
            canonicalizer_version=CANONICALIZER_VERSION,
            status=Status.UNVERIFIED.value,
            replacements=replacements,
        )

        # Mandatory verification pass.
        if self._detector is not None:
            leaks = verify(masked, replacements, self._policy, job, self._detector)
            receipt.leaks = leaks
            receipt.status = (
                Status.LEAK_DETECTED.value if leaks else Status.VERIFIED.value
            )
            if leaks:
                log.error(
                    "LEAK_DETECTED file=%s job=%s types=%s",
                    file_id,
                    job.job_id,
                    sorted({leak.entity_type for leak in leaks}),
                )

        # Vault writes: async side effect, never on the pseudonym hot path,
        # and only for verified, reversible RAG jobs.
        if vault_pending and receipt.status != Status.LEAK_DETECTED.value:
            for pseudonym, original, etype in vault_pending:
                self._vault.put(pseudonym, original, etype)  # type: ignore[union-attr]

        if self._receipts is not None:
            self._receipts.save(receipt.to_dict())
        return TransformResult(masked_text=masked, receipt=receipt)

    # ------------------------------------------------------------------ #

    def _entry_for(self, job: JobSpec, entity_type: str) -> PolicyEntry:
        override = job.strategy_overrides.get(entity_type.upper())
        entry = self._policy.lookup(job.target, entity_type)
        if override is not None:
            entry = PolicyEntry(
                strategy=override, indexed=entry.indexed, token=entry.token, params=entry.params
            )
        return entry

    def _pseudonym_engine(self, job: JobSpec) -> PseudonymEngine:
        if self._salt_provider is None:
            raise PolicyViolation("RAG pseudonymization requires a salt provider (KMS)")
        salt = self._salt_provider(job)
        return PseudonymEngine(
            salt, length=job.pseudonym_len, registry=self._registry
        )

    def _fpe_encrypt(self, entity_type: str, surface: str, entry: PolicyEntry) -> str:
        if self._fpe is not None:
            ct = self._fpe.encrypt(entity_type, surface)
            if ct is not None:
                return ct
        # Out-of-domain or FPE unavailable: fall back to a safe placeholder.
        return f"<{token_name(entity_type, entry)}>"
