"""Policy engine (Phase 1): pack validation, lattice composition, per-finding
resolution, and the bit-identical guarantee of the converted default packs."""
from __future__ import annotations

from pathlib import Path

import pytest

from anonymizer.core.engine import Engine
from anonymizer.core.policyload import load_policy_yaml
from anonymizer.core.types import Finding, Target, jobspec_from_dict
from anonymizer.policyengine import (
    RegulationPack,
    action_to_strategy,
    compatible_targets,
    compile_job_policy,
    compose,
    load_pack,
    load_packs,
    resolve,
)

CONFIG = Path(__file__).resolve().parent.parent / "config"
REGS = CONFIG / "regulations"


def _pack(**overrides) -> RegulationPack:
    base = {
        "regulation": "test_reg", "version": "1", "rules": [
            {"entity": "SSN", "min_confidence": 0.8, "action": "hash_irreversible"},
            {"entity": "PERSON", "min_confidence": 0.85, "action": "hmac_tokenize"},
        ],
    }
    base.update(overrides)
    return RegulationPack.model_validate(base)


class TestPackLoading:
    def test_shipped_packs_load_with_provenance_hash(self) -> None:
        for name in ("training_default", "rag_default", "hipaa_safe_harbor"):
            pack = load_pack(REGS / f"{name}.yaml")
            assert len(pack.sha256) == 64
            assert pack.default_action == "suppress"

    def test_unknown_key_rejected(self) -> None:
        with pytest.raises(Exception):
            RegulationPack.model_validate(
                {"regulation": "x", "version": "1", "rules": [], "surprise": 1}
            )

    def test_default_action_must_be_suppress(self) -> None:
        with pytest.raises(Exception):
            _pack(default_action="keep")

    def test_duplicate_entity_rejected(self) -> None:
        with pytest.raises(Exception):
            _pack(rules=[
                {"entity": "SSN", "action": "suppress"},
                {"entity": "ssn", "action": "keep"},
            ])

    def test_unknown_action_rejected(self) -> None:
        with pytest.raises(Exception):
            _pack(rules=[{"entity": "SSN", "action": "obliterate"}])

    def test_missing_pack_lists_available(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="available"):
            load_packs(REGS, ["nonexistent_reg"])


class TestActionMapping:
    def test_hmac_tokenize_is_guarantee_aware(self) -> None:
        assert action_to_strategy("hmac_tokenize", Target.TRAINING).value == "placeholder_indexed"
        assert action_to_strategy("hmac_tokenize", Target.RAG).value == "hmac_pseudonym"

    def test_hash_irreversible_executes_as_suppress(self) -> None:
        assert action_to_strategy("hash_irreversible", Target.TRAINING).value == "suppress"

    def test_linkable_native_actions_forbidden_in_training(self) -> None:
        for action in ("fpe", "hmac_pseudonym"):
            with pytest.raises(ValueError, match="linkable"):
                action_to_strategy(action, Target.TRAINING)

    def test_compatible_targets(self) -> None:
        """Job launchers use this to reject pack/mode mismatches up front."""
        assert compatible_targets(load_pack(REGS / "rag_default.yaml")) == {"rag"}
        assert compatible_targets(
            load_pack(REGS / "training_default.yaml")) == {"rag", "training"}
        # hmac_tokenize is guarantee-aware, so HIPAA serves both targets
        assert compatible_targets(
            load_pack(REGS / "hipaa_safe_harbor.yaml")) == {"rag", "training"}


class TestComposition:
    def test_strictest_action_wins(self) -> None:
        a = _pack(regulation="a", rules=[{"entity": "ZIP", "action": "keep"}])
        b = _pack(regulation="b", rules=[{"entity": "ZIP", "action": "suppress"}])
        rule = compose([a, b], "ZIP")
        assert rule.action == "suppress"

    def test_lowest_threshold_wins(self) -> None:
        a = _pack(regulation="a", rules=[
            {"entity": "SSN", "min_confidence": 0.9, "action": "suppress"}])
        b = _pack(regulation="b", rules=[
            {"entity": "SSN", "min_confidence": 0.6, "action": "suppress"}])
        assert compose([a, b], "SSN").min_confidence == 0.6

    def test_most_aggressive_below_threshold_wins(self) -> None:
        a = _pack(regulation="a", below_threshold="keep",
                  rules=[{"entity": "SSN", "action": "suppress"}])
        b = _pack(regulation="b", below_threshold="review",
                  rules=[{"entity": "SSN", "action": "suppress"}])
        assert compose([a, b], "SSN").below_threshold == "review"

    def test_unmentioned_entity_composes_to_none(self) -> None:
        assert compose([_pack()], "ZEBRA") is None

    def test_rule_id_names_every_contributing_pack(self) -> None:
        a = _pack(regulation="hipaa", version="2026.07",
                  rules=[{"entity": "SSN", "action": "suppress"}])
        b = _pack(regulation="gdpr", version="3",
                  rules=[{"entity": "SSN", "action": "keep"}])
        assert compose([a, b], "SSN").rule_id == "hipaa/2026.07#SSN;gdpr/3#SSN"


class TestResolve:
    def _findings(self) -> list[dict]:
        return [
            {"entity_type": "SSN", "start": 0, "end": 11, "confidence": 0.94},
            {"entity_type": "PERSON", "start": 20, "end": 25, "confidence": 0.82},
            {"entity_type": "ZEBRA", "start": 30, "end": 35, "confidence": 0.99},
        ]

    def test_outcomes_apply_review_and_fail_closed_default(self) -> None:
        pack = _pack(below_threshold="review")
        decisions = resolve(self._findings(), [pack], Target.TRAINING)
        by_entity = {d.entity: d for d in decisions}
        assert by_entity["SSN"].outcome == "apply"          # 0.94 >= 0.80
        assert by_entity["PERSON"].outcome == "review"      # 0.82 < 0.85
        assert by_entity["ZEBRA"].outcome == "apply"        # no rule -> suppress
        assert by_entity["ZEBRA"].action == "suppress"
        assert by_entity["SSN"].rule == "test_reg/1#SSN"

    def test_mask_anyway_applies_below_threshold(self) -> None:
        pack = _pack(below_threshold="mask_anyway")
        decisions = resolve(self._findings(), [pack], Target.TRAINING)
        assert all(d.outcome == "apply" for d in decisions)

    def test_strategy_reflects_target(self) -> None:
        pack = _pack()
        training = {d.entity: d for d in resolve(self._findings(), [pack], "training")}
        rag = {d.entity: d for d in resolve(self._findings(), [pack], "rag")}
        assert training["PERSON"].strategy == "placeholder_indexed"
        assert rag["PERSON"].strategy == "hmac_pseudonym"


class TestCompile:
    def test_compiles_thresholds_overrides_and_provenance(self) -> None:
        pack = load_pack(REGS / "hipaa_safe_harbor.yaml")
        compiled = compile_job_policy([pack], Target.TRAINING)
        assert compiled["type_thresholds"]["SSN"] == 0.80
        assert compiled["strategy_overrides"]["SSN"] == "suppress"
        assert compiled["strategy_overrides"]["PERSON"] == "placeholder_indexed"
        assert compiled["policy_version"] == "HIPAA_safe_harbor/2026.07"
        prov = compiled["policy_provenance"]["regulations"][0]
        assert prov["name"] == "HIPAA_safe_harbor" and len(prov["sha256"]) == 64

    def test_mask_anyway_compiles_to_zero_threshold(self) -> None:
        pack = _pack(below_threshold="mask_anyway")
        compiled = compile_job_policy([pack], Target.TRAINING)
        assert compiled["type_thresholds"]["SSN"] == 0.0

    def test_uncovered_base_entities_compile_to_fail_closed_suppression(self) -> None:
        """Entities the base masking policy handles but no pack mentions must
        execute the packs' default_action (suppress) — execution must match
        resolve()'s decisions, not silently fall back to base behavior."""
        pack = _pack()  # covers SSN + PERSON only
        compiled = compile_job_policy(
            [pack], Target.TRAINING, base_entities={"MEDICATION", "EMAIL"})
        assert compiled["strategy_overrides"]["MEDICATION"] == "suppress"
        assert compiled["strategy_overrides"]["EMAIL"] == "suppress"
        assert compiled["type_thresholds"]["MEDICATION"] == 0.0
        # covered entities keep their pack rule
        assert compiled["strategy_overrides"]["SSN"] == "suppress"
        assert compiled["type_thresholds"]["SSN"] == 0.8

    def test_hipaa_pack_keeps_clinical_content(self) -> None:
        pack = load_pack(REGS / "hipaa_safe_harbor.yaml")
        compiled = compile_job_policy([pack], Target.TRAINING)
        for clinical in ("MEDICATION", "DIAGNOSIS", "PROCEDURE"):
            assert compiled["strategy_overrides"][clinical] == "keep"

    def test_jobspec_accepts_compiled_dict(self) -> None:
        pack = load_pack(REGS / "rag_default.yaml")
        job = {"job_id": "j1", "downstream_target": "rag",
               **compile_job_policy([pack], Target.RAG)}
        spec = jobspec_from_dict(job)
        assert spec.threshold_for("SSN") == 0.5
        assert spec.strategy_overrides["PERSON"].value == "hmac_pseudonym"
        assert spec.policy_version == "rag_default/1.0"


class TestBitIdenticalDefaults:
    """The converted default packs must not change behavior at all."""

    TEXT = ("Alice Smith emailed alice@corp.example about SSN 856-45-6789, "
            "ZIP 56001, and her Metformin refill. Visit https://intra/x today.")

    def _findings(self) -> list[Finding]:
        def span(s: str) -> tuple[int, int]:
            i = self.TEXT.index(s)
            return i, i + len(s)
        return [
            Finding("PERSON", *span("Alice Smith"), confidence=0.90),
            Finding("EMAIL", *span("alice@corp.example"), confidence=0.90),
            Finding("SSN", *span("856-45-6789"), confidence=0.90),
            Finding("ZIP", *span("56001"), confidence=0.90),
            Finding("MEDICATION", *span("Metformin"), confidence=0.90),
            Finding("URL", *span("https://intra/x"), confidence=0.90),
            Finding("ORG", *span("corp"), confidence=0.40),  # below 0.5: kept
        ]

    @pytest.mark.parametrize("target,pack_name", [
        ("training", "training_default"), ("rag", "rag_default"),
    ])
    def test_masked_output_identical_with_and_without_pack(
        self, target: str, pack_name: str
    ) -> None:
        policy = load_policy_yaml(str(CONFIG / "masking_policy.yaml"))
        engine = Engine(policy, salt_provider=lambda job: b"\x07" * 32)
        base_job = {"job_id": "bit", "downstream_target": target}
        pack_job = {**base_job,
                    **compile_job_policy(load_packs(REGS, [pack_name]), target)}

        without = engine.transform(
            self.TEXT, self._findings(), jobspec_from_dict(base_job), "f1")
        with_pack = engine.transform(
            self.TEXT, self._findings(), jobspec_from_dict(pack_job), "f1")

        assert with_pack.masked_text == without.masked_text
        assert (
            [(r.entity_type, r.strategy) for r in with_pack.receipt.replacements]
            == [(r.entity_type, r.strategy) for r in without.receipt.replacements]
        )

    @pytest.mark.parametrize("target,pack_name", [
        ("training", "training_default"), ("rag", "rag_default"),
    ])
    def test_every_converted_rule_matches_base_policy_strategy(
        self, target: str, pack_name: str
    ) -> None:
        """Structural identity for ALL entities (incl. DATE, whose per-doc
        random shift makes exact-text comparison meaningless by design)."""
        policy = load_policy_yaml(str(CONFIG / "masking_policy.yaml"))
        compiled = compile_job_policy(load_packs(REGS, [pack_name]), target)
        for entity, strategy in compiled["strategy_overrides"].items():
            assert policy.lookup(target, entity).strategy.value == strategy, entity
            assert compiled["type_thresholds"][entity] == 0.5, entity
        # and the pack covers every entity the base policy defines for the target
        base_entities = {e for (t, e) in policy.entries if t == target}
        assert base_entities == set(compiled["strategy_overrides"])
