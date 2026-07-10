"""Core datatypes (stdlib dataclasses; pydantic mirrors live in anonymizer.models)."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Target(str, Enum):
    TRAINING = "training"
    RAG = "rag"


class Strategy(str, Enum):
    PLACEHOLDER_INDEXED = "placeholder_indexed"
    GENERALIZE = "generalize"
    DATE_SHIFT = "date_shift"
    HMAC_PSEUDONYM = "hmac_pseudonym"
    FPE = "fpe"
    SUPPRESS = "suppress"
    KEEP = "keep"


#: Strategies that produce stable, cross-document identifiers. They are
#: FORBIDDEN in training mode — enforced at policy load AND again at runtime.
LINKABLE_STRATEGIES = frozenset({Strategy.HMAC_PSEUDONYM, Strategy.FPE})


class Status(str, Enum):
    VERIFIED = "VERIFIED"
    LEAK_DETECTED = "LEAK_DETECTED"
    UNVERIFIED = "UNVERIFIED"  # verification pass not configured (dev only)


class PolicyViolation(Exception):
    """Raised when a policy would break a mode invariant (fail closed)."""


@dataclass(frozen=True)
class Finding:
    entity_type: str
    start: int
    end: int
    confidence: float
    tier: str = "T1"
    validated: bool = False

    def __post_init__(self) -> None:
        if self.start < 0 or self.end <= self.start:
            raise ValueError(f"invalid span [{self.start},{self.end})")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence out of range: {self.confidence}")


def finding_from_dict(d: dict) -> Finding:
    return Finding(
        entity_type=str(d["entity_type"]).upper(),
        start=int(d["start"]),
        end=int(d["end"]),
        confidence=float(d.get("confidence", 1.0)),
        tier=str(d.get("tier", "T1")),
        validated=bool(d.get("validated", False)),
    )


@dataclass
class PolicyEntry:
    strategy: Strategy
    indexed: bool = True          # placeholder_indexed: numbered vs bare token
    token: str | None = None      # placeholder token name override
    params: dict = field(default_factory=dict)


@dataclass
class PolicyTable:
    """Resolved policy: (target, ENTITY_TYPE) -> entry. Unknown types fail closed."""

    version: str
    entries: dict[tuple[str, str], PolicyEntry]
    default_strategy: Strategy = Strategy.SUPPRESS

    def lookup(self, target: Target | str, entity_type: str) -> PolicyEntry:
        t = target.value if isinstance(target, Target) else str(target)
        entry = self.entries.get((t, entity_type.upper()))
        if entry is None:
            # Fail closed: unknown entity types are removed entirely.
            return PolicyEntry(strategy=self.default_strategy)
        return entry

    def validate_mode_invariants(self) -> None:
        for (target, etype), entry in self.entries.items():
            if target == Target.TRAINING.value and entry.strategy in LINKABLE_STRATEGIES:
                raise PolicyViolation(
                    f"training policy for {etype} uses {entry.strategy.value}: linkable/"
                    "reversible strategies are forbidden in training mode"
                )


@dataclass
class JobSpec:
    job_id: str
    target: Target
    tenant_id: str = "default"
    confidence_threshold: float = 0.5
    type_thresholds: dict = field(default_factory=dict)  # ENTITY_TYPE -> float
    strategy_overrides: dict = field(default_factory=dict)  # ENTITY_TYPE -> Strategy
    salt_scope: str = "tenant"  # tenant | corpus | run ('run' breaks cross-run consistency)
    corpus_id: str = ""
    reversible: bool = False
    pseudonym_len: int = 8
    policy_version: str = "0"

    def threshold_for(self, entity_type: str) -> float:
        return float(self.type_thresholds.get(entity_type.upper(), self.confidence_threshold))


def jobspec_from_dict(d: dict) -> JobSpec:
    return JobSpec(
        job_id=str(d["job_id"]),
        target=Target(d["downstream_target"]),
        tenant_id=str(d.get("tenant_id", "default")),
        confidence_threshold=float(d.get("confidence_threshold", 0.5)),
        type_thresholds={k.upper(): float(v) for k, v in d.get("type_thresholds", {}).items()},
        strategy_overrides={
            k.upper(): Strategy(v) for k, v in d.get("strategy_overrides", {}).items()
        },
        salt_scope=str(d.get("salt_scope", "tenant")),
        corpus_id=str(d.get("corpus_id", "")),
        reversible=bool(d.get("reversible", False)),
        pseudonym_len=int(d.get("pseudonym_len", 8)),
        policy_version=str(d.get("policy_version", "0")),
    )


@dataclass
class Replacement:
    entity_type: str
    strategy: str
    orig_start: int
    orig_end: int
    new_start: int
    new_end: int
    replacement: str
    original: str | None = None  # ALWAYS None in training mode (irreversibility)


@dataclass
class LeakFinding:
    entity_type: str
    start: int
    end: int
    confidence: float


@dataclass
class Receipt:
    file_id: str
    job_id: str
    mode: str
    policy_version: str
    canonicalizer_version: str
    status: str
    replacements: list[Replacement] = field(default_factory=list)
    leaks: list[LeakFinding] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TransformResult:
    masked_text: str
    receipt: Receipt

    @property
    def deliverable(self) -> bool:
        return self.receipt.status == Status.VERIFIED.value
