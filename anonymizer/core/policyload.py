"""Policy YAML -> PolicyTable.

anonymizer.policy (pydantic v2) is the primary, strictly-typed loader. This
module holds the shared shape/semantic checks plus a dict-based builder so the
stdlib core can construct tables directly (tests, constrained environments).
Both paths enforce the same invariants and fail closed.
"""
from __future__ import annotations

from .types import PolicyEntry, PolicyTable, PolicyViolation, Strategy, Target

_VALID_TARGETS = {t.value for t in Target}


def build_policy_table(doc: dict) -> PolicyTable:
    """Build and validate a PolicyTable from a parsed YAML/JSON dict."""
    if not isinstance(doc, dict) or "policies" not in doc:
        raise PolicyViolation("policy file must contain a 'policies' mapping")
    version = str(doc.get("version", "0"))
    default = Strategy(str(doc.get("default_strategy", "suppress")))
    if default not in (Strategy.SUPPRESS,):
        raise PolicyViolation("default_strategy must be 'suppress' (fail closed)")

    entries: dict[tuple[str, str], PolicyEntry] = {}
    for target, mapping in doc["policies"].items():
        if target not in _VALID_TARGETS:
            raise PolicyViolation(f"unknown downstream_target '{target}'")
        if not isinstance(mapping, dict):
            raise PolicyViolation(f"policies.{target} must be a mapping")
        for etype, spec in mapping.items():
            if isinstance(spec, str):
                spec = {"strategy": spec}
            try:
                strategy = Strategy(str(spec["strategy"]))
            except (KeyError, ValueError) as exc:
                raise PolicyViolation(f"invalid strategy for {target}.{etype}: {exc}") from exc
            entries[(target, str(etype).upper())] = PolicyEntry(
                strategy=strategy,
                indexed=bool(spec.get("indexed", True)),
                token=spec.get("token"),
                params=dict(spec.get("params", {})),
            )

    table = PolicyTable(version=version, entries=entries, default_strategy=default)
    table.validate_mode_invariants()
    return table


def load_policy_yaml(path: str) -> PolicyTable:
    import yaml  # deferred: PyYAML

    with open(path, encoding="utf-8") as fh:
        return build_policy_table(yaml.safe_load(fh))
