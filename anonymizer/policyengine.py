"""Regulation-pack policy engine (Phase 1 — see docs/07_POLICY_ENGINE_DESIGN.md
in the platform repo).

Consumes detection findings and the regulation packs selected for a job, and
decides an action per entity: which spans to mask, how, and at what
confidence bar. Rules are versioned YAML data, so regulatory changes never
touch the detection model or the masking mechanics.

Phase-1 boundary: decisions are *compiled into the existing JobSpec levers*
(``type_thresholds``, ``strategy_overrides``, ``policy_version``) — the
transformation engine is unchanged, and a job selecting the mechanically
converted default packs behaves bit-identically to one selecting none
(pinned by tests/test_policyengine.py).

Pack schema (pydantic-strict, unknown keys rejected):

    regulation: HIPAA_safe_harbor
    version: "2026.07"
    default_action: suppress        # must be suppress — unknown types fail closed
    below_threshold: review         # keep | review | mask_anyway
    rules:
      - entity: SSN
        min_confidence: 0.80
        action: hash_irreversible
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .core.types import Strategy, Target

#: Action severity lattice — composition across regulations takes the MOST
#: severe action (and the LOWEST threshold). Native strategy names are legal
#: actions for expert packs (e.g. the mechanical conversions of
#: masking_policy.yaml); the abstract actions are the portable vocabulary.
ACTION_SEVERITY = {
    "keep": 0,
    "generalize": 1,
    "date_shift": 1,
    "placeholder_indexed": 2,
    "hmac_tokenize": 2,
    "hmac_pseudonym": 2,
    "fpe": 2,
    "hash_irreversible": 3,
    "suppress": 4,
}

_BELOW_THRESHOLD_SEVERITY = {"keep": 0, "review": 1, "mask_anyway": 2}

Action = Literal[
    "keep", "generalize", "date_shift", "placeholder_indexed", "hmac_tokenize",
    "hmac_pseudonym", "fpe", "hash_irreversible", "suppress",
]

#: Native actions that produce stable, cross-document identifiers — packs
#: using them can only serve the ``rag`` target (the portable
#: ``hmac_tokenize`` action is fine everywhere: it maps per target).
LINKABLE_ACTIONS = frozenset({"fpe", "hmac_pseudonym"})


def action_to_strategy(action: str, target: Target) -> Strategy:
    """Map a policy action onto the executing strategy for a target.

    ``hmac_tokenize`` is guarantee-aware: per-document placeholders under the
    irreversible ``training`` target, stable HMAC pseudonyms under ``rag``.
    ``hash_irreversible`` executes as suppression in Phase 1 (the
    ``[REDACTED-SSN-a8f3]`` render template is Phase 2).
    Linkable strategies requested for ``training`` raise — the same invariant
    the policy loader and the engine already enforce, applied a third time.
    """
    training = target == Target.TRAINING
    if action == "hmac_tokenize":
        return Strategy.PLACEHOLDER_INDEXED if training else Strategy.HMAC_PSEUDONYM
    if action == "hash_irreversible":
        return Strategy.SUPPRESS
    strategy = Strategy(action)
    if training and strategy in (Strategy.HMAC_PSEUDONYM, Strategy.FPE):
        raise ValueError(
            f"action {action!r} is linkable — forbidden under the training target"
        )
    return strategy


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity: str
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    action: Action
    params: dict = Field(default_factory=dict)   # accepted; executed Phase 2
    render: str | None = None                    # accepted; executed Phase 2
    condition: str | None = None                 # accepted; executed Phase 2

    @field_validator("entity")
    @classmethod
    def _canonical_upper(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("entity must be non-empty")
        return v.strip().upper()


class RegulationPack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    regulation: str
    version: str
    description: str = ""
    #: Catalog metadata — the pack is the single source of truth for how it is
    #: filed in a selection UI. Optional so a hand-written pack stays valid.
    jurisdiction: str = ""      # EU, UK, US, India, Brazil, ... or Global
    category: Literal["default", "baseline", "privacy", "sector", ""] = ""
    default_action: Literal["suppress"] = "suppress"  # fail closed, non-negotiable
    below_threshold: Literal["keep", "review", "mask_anyway"] = "keep"
    rules: list[Rule]
    #: sha256 of the pack file's bytes, stamped by the loader for provenance.
    sha256: str = ""

    @field_validator("rules")
    @classmethod
    def _no_duplicate_entities(cls, v: list[Rule]) -> list[Rule]:
        seen: set[str] = set()
        for r in v:
            if r.entity in seen:
                raise ValueError(f"duplicate rule for entity {r.entity}")
            seen.add(r.entity)
        return v

    def rule_for(self, entity: str) -> Rule | None:
        entity = entity.upper()
        for r in self.rules:
            if r.entity == entity:
                return r
        return None


def load_pack(path: str | Path) -> RegulationPack:
    """Load + validate one pack; a bad pack raises, never half-applies."""
    raw = Path(path).read_bytes()
    data = yaml.safe_load(raw) or {}
    pack = RegulationPack.model_validate(data)
    pack.sha256 = hashlib.sha256(raw).hexdigest()
    return pack


def compatible_targets(pack: RegulationPack) -> set[str]:
    """Which job targets this pack can compile for. Callers (UIs, job
    launchers) should check this up front so an incompatible pack/mode pair
    is rejected at selection time, not as a failed job."""
    if any(r.action in LINKABLE_ACTIONS for r in pack.rules):
        return {Target.RAG.value}
    return {Target.TRAINING.value, Target.RAG.value}


def load_packs(packs_dir: str | Path, names: list[str]) -> list[RegulationPack]:
    """Load the named packs from ``packs_dir`` (``<name>.yaml``)."""
    packs = []
    for name in names:
        path = Path(packs_dir) / f"{name}.yaml"
        if not path.is_file():
            available = sorted(p.stem for p in Path(packs_dir).glob("*.yaml"))
            raise FileNotFoundError(
                f"regulation pack {name!r} not found in {packs_dir} "
                f"(available: {available})"
            )
        packs.append(load_pack(path))
    return packs


# --------------------------------------------------------------- resolution


@dataclass(frozen=True)
class ComposedRule:
    entity: str
    action: str
    min_confidence: float
    below_threshold: str
    rule_id: str  # e.g. "HIPAA_safe_harbor/2026.07#SSN" (";"-joined when composed)


def compose(packs: list[RegulationPack], entity: str) -> ComposedRule | None:
    """Strictest-wins composition across every pack that has a rule for
    ``entity``: most severe action, lowest threshold, most aggressive
    below-threshold outcome. None when no pack mentions the entity
    (caller falls through to default_action)."""
    matches = [
        (p, r) for p in packs if (r := p.rule_for(entity)) is not None
    ]
    if not matches:
        return None
    action = max((r.action for _, r in matches), key=lambda a: ACTION_SEVERITY[a])
    threshold = min(r.min_confidence for _, r in matches)
    below = max(
        (p.below_threshold for p, _ in matches),
        key=lambda b: _BELOW_THRESHOLD_SEVERITY[b],
    )
    rule_id = ";".join(f"{p.regulation}/{p.version}#{r.entity}" for p, r in matches)
    return ComposedRule(
        entity=entity.upper(), action=action, min_confidence=threshold,
        below_threshold=below, rule_id=rule_id,
    )


@dataclass(frozen=True)
class PolicyDecision:
    entity: str
    start: int
    end: int
    confidence: float
    action: str
    strategy: str
    threshold: float
    outcome: str  # apply | keep | review
    rule: str

    def to_dict(self) -> dict:
        return {
            "entity": self.entity, "start": self.start, "end": self.end,
            "confidence": self.confidence, "action": self.action,
            "strategy": self.strategy, "threshold": self.threshold,
            "outcome": self.outcome, "rule": self.rule,
        }


def resolve(
    findings: list[dict], packs: list[RegulationPack], target: Target | str
) -> list[PolicyDecision]:
    """Decide per finding. ``findings`` are anonymizer-job-shaped dicts
    (``entity_type``/``start``/``end``/``confidence``). Findings with no
    matching rule get the default action (suppress) at threshold 0 — fail
    closed. Below-threshold findings surface as ``keep`` or ``review``
    outcomes (``mask_anyway`` applies regardless of confidence)."""
    target = Target(target) if not isinstance(target, Target) else target
    decisions: list[PolicyDecision] = []
    for f in findings:
        entity = str(f["entity_type"]).upper()
        confidence = float(f.get("confidence", 1.0))
        rule = compose(packs, entity)
        if rule is None:
            decisions.append(PolicyDecision(
                entity=entity, start=int(f["start"]), end=int(f["end"]),
                confidence=confidence, action="suppress",
                strategy=Strategy.SUPPRESS.value, threshold=0.0,
                outcome="apply",
                rule=";".join(f"{p.regulation}/{p.version}#default" for p in packs),
            ))
            continue
        if confidence >= rule.min_confidence or rule.below_threshold == "mask_anyway":
            outcome = "apply"
        else:
            outcome = rule.below_threshold  # keep | review
        decisions.append(PolicyDecision(
            entity=entity, start=int(f["start"]), end=int(f["end"]),
            confidence=confidence, action=rule.action,
            strategy=action_to_strategy(rule.action, target).value,
            threshold=rule.min_confidence, outcome=outcome, rule=rule.rule_id,
        ))
    return decisions


# -------------------------------------------------------------- compilation


def compile_job_policy(
    packs: list[RegulationPack],
    target: Target | str,
    base_entities: set[str] | None = None,
) -> dict:
    """Fold the selected packs into existing JobSpec levers — the Phase-1
    execution path, requiring zero engine changes:

    - ``type_thresholds``: composed per-entity min_confidence (0.0 for
      mask_anyway packs, so the engine masks regardless);
    - ``strategy_overrides``: composed action mapped per target;
    - ``policy_version``: pack provenance string — lands in every receipt
      (and in the idempotency key, so changing packs re-runs documents);
    - ``policy_provenance``: names/versions/content hashes for audit.

    Merge the returned dict into the job message dict.

    ``base_entities`` — the entity types the executor's base masking policy
    defines for this target. Any of them NOT covered by a pack rule is
    compiled to suppress-at-any-confidence, so the packs' fail-closed
    ``default_action`` reaches entities the base policy would otherwise
    handle its own way (execution must match ``resolve()``'s decisions).
    Truly unknown entity types fail closed in the engine regardless.
    """
    if not packs:
        raise ValueError("compile_job_policy needs at least one regulation pack")
    target = Target(target) if not isinstance(target, Target) else target
    entities = {r.entity for p in packs for r in p.rules}
    type_thresholds: dict[str, float] = {}
    strategy_overrides: dict[str, str] = {}
    for entity in sorted(entities):
        rule = compose(packs, entity)
        assert rule is not None
        type_thresholds[entity] = (
            0.0 if rule.below_threshold == "mask_anyway" else rule.min_confidence
        )
        strategy_overrides[entity] = action_to_strategy(rule.action, target).value
    for entity in sorted(base_entities or set()):
        entity = entity.upper()
        if entity not in entities:  # uncovered by every pack: default_action
            type_thresholds[entity] = 0.0
            strategy_overrides[entity] = Strategy.SUPPRESS.value
    return {
        "type_thresholds": type_thresholds,
        "strategy_overrides": strategy_overrides,
        "policy_version": ";".join(f"{p.regulation}/{p.version}" for p in packs),
        "policy_provenance": {
            "regulations": [
                {"name": p.regulation, "version": p.version, "sha256": p.sha256}
                for p in packs
            ]
        },
    }
