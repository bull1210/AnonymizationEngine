"""Pydantic v2 validated policy loader (masking_policy.yaml).

Strict at the boundary: unknown strategies, unknown targets, or a linkable
strategy under `training` are startup errors. The validated document is
converted to the core PolicyTable used by the engine.
"""
from __future__ import annotations

from typing import Literal, Union

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .core.policyload import build_policy_table
from .core.types import PolicyTable

_STRATEGIES = Literal[
    "placeholder_indexed", "generalize", "date_shift",
    "hmac_pseudonym", "fpe", "suppress", "keep",
]
_LINKABLE = {"hmac_pseudonym", "fpe"}


class EntryModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    strategy: _STRATEGIES
    indexed: bool = True
    token: str | None = None
    params: dict = Field(default_factory=dict)


class PolicyFileModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = "0"
    default_strategy: Literal["suppress"] = "suppress"  # fail closed, non-negotiable
    policies: dict[Literal["training", "rag"], dict[str, Union[str, EntryModel]]]

    @model_validator(mode="after")
    def _no_linkable_in_training(self) -> "PolicyFileModel":
        for etype, spec in self.policies.get("training", {}).items():
            strategy = spec if isinstance(spec, str) else spec.strategy
            if strategy in _LINKABLE:
                raise ValueError(
                    f"training.{etype}: '{strategy}' is forbidden in training mode "
                    "(irreversibility invariant)"
                )
        return self


def load_policy(path: str) -> PolicyTable:
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    validated = PolicyFileModel.model_validate(raw)  # strict pydantic pass
    return build_policy_table(validated.model_dump())  # -> core table (same invariants)
