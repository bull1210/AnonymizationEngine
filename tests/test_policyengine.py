"""Policy engine (Phase 1): pack validation, lattice composition, per-finding
resolution, and the bit-identical guarantee of the converted default packs."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from anonymizer.core.engine import Engine
from anonymizer.core.policyload import load_policy_yaml
from anonymizer.core.types import Finding, Target, jobspec_from_dict
from anonymizer.policyengine import (
    PolicyDecision,
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


#: Every pack shipped in config/regulations — extend when adding packs.
SHIPPED_PACKS = (
    "training_default", "rag_default", "hipaa_safe_harbor",
    "gdpr_pseudonymization", "pii_protection", "india_dpdp",
    "pci_dss", "ccpa_deidentification",
    # global privacy laws
    "uk_dpa_2018", "lgpd_brazil", "pipl_china", "appi_japan",
    "pipeda_canada", "popia_south_africa", "privacy_act_australia",
    "pdpa_singapore",
    # US sectoral
    "glba", "hipaa_expert_determination",
)

#: The policy vocabulary: entity names the masking policy actually knows how
#: to execute. A pack rule naming anything outside this set is a typo that
#: fails SILENTLY — the entity never matches a finding, and the finding falls
#: through to default_action (suppress). It over-masks, so nothing breaks
#: loudly; it just quietly stops doing what the pack author wrote.
KNOWN_ENTITIES = frozenset(
    entity
    for mapping in (
        yaml.safe_load((CONFIG / "masking_policy.yaml").read_text(encoding="utf-8"))
        ["policies"].values()
    )
    for entity in mapping
)


class TestPackLoading:
    def test_shipped_pack_list_is_complete(self) -> None:
        assert {p.stem for p in REGS.glob("*.yaml")} == set(SHIPPED_PACKS)

    def test_shipped_packs_load_with_provenance_hash(self) -> None:
        for name in SHIPPED_PACKS:
            pack = load_pack(REGS / f"{name}.yaml")
            assert len(pack.sha256) == 64
            assert pack.default_action == "suppress"

    def test_shipped_packs_compile_for_their_targets(self) -> None:
        """Every pack must compile cleanly for every target it claims —
        a pack that loads but explodes at job launch is a broken ship."""
        for name in SHIPPED_PACKS:
            pack = load_pack(REGS / f"{name}.yaml")
            for target in compatible_targets(pack):
                compiled = compile_job_policy([pack], target)
                assert compiled["strategy_overrides"], name

    def test_enterprise_packs_are_dual_target(self) -> None:
        """All packs except rag_default use guarantee-aware actions only, so
        they serve both training and rag jobs."""
        for name in SHIPPED_PACKS:
            pack = load_pack(REGS / f"{name}.yaml")
            expected = {"rag"} if name == "rag_default" else {"rag", "training"}
            assert compatible_targets(pack) == expected, name

    def test_shipped_pack_rules_use_known_entities(self) -> None:
        """A pack rule naming an entity the masking policy doesn't know is a
        silent no-op: it never matches, and the finding falls through to
        default_action (suppress). It over-masks, so no test fails and no leak
        happens — the pack just quietly doesn't do what its author wrote. With
        18 packs, a typo like MEDICAL_CONDITION (a detection name, not a policy
        name) is the likeliest way to ship a broken pack."""
        for name in SHIPPED_PACKS:
            pack = load_pack(REGS / f"{name}.yaml")
            unknown = {r.entity for r in pack.rules} - KNOWN_ENTITIES
            assert not unknown, f"{name}: unknown entities {sorted(unknown)}"

    def test_shipped_packs_carry_catalog_metadata(self) -> None:
        """jurisdiction/category drive the grouping in the console's run
        dialog; a pack without them lands in an 'Other' bucket."""
        for name in SHIPPED_PACKS:
            pack = load_pack(REGS / f"{name}.yaml")
            assert pack.jurisdiction, name
            assert pack.category, name

    def test_multi_regulation_composition_is_strictest(self) -> None:
        """GDPR (tokenize EMAIL) + PII baseline (hash EMAIL) => hash wins;
        thresholds compose to the lowest."""
        packs = load_packs(REGS, ["gdpr_pseudonymization", "pii_protection"])
        rule = compose(packs, "EMAIL")
        assert rule.action == "hash_irreversible"
        assert rule.min_confidence == 0.0          # pii pack has no threshold
        assert rule.below_threshold == "mask_anyway"

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


def _decide(packs: list[RegulationPack], entity: str, confidence: float,
            target: str) -> PolicyDecision:
    """resolve() one synthetic finding of `entity` at `confidence`."""
    finding = {"entity_type": entity, "start": 0, "end": 5, "confidence": confidence}
    return resolve([finding], packs, target)[0]


class TestJurisdictionPackStances:
    """The four packs whose legal stance genuinely diverges from the GDPR
    family. The rest (UK DPA, LGPD, PDPA-SG, PIPEDA, POPIA, Australia) are
    covered by the catalog-wide tests above; asserting their near-identical
    rule tables again would just restate the YAML."""

    def test_appi_never_produces_a_linkable_identifier(self) -> None:
        """APPI Art. 36: anonymously-processed information must not be
        restorable. An HMAC pseudonym is unrestorable without the salt but
        LINKABLE across the corpus, which keeps it regulated as merely
        pseudonymized. So the pack must resolve identifiers to irreversible
        strategies under BOTH targets — including rag, where hmac_tokenize
        would otherwise become a stable pseudonym."""
        pack = load_pack(REGS / "appi_japan.yaml")
        linkable = {"hmac_pseudonym", "fpe"}
        for target in ("training", "rag"):
            for entity in ("PERSON", "EMAIL", "PHONE", "ADDRESS", "LOCATION", "IP"):
                decision = _decide([pack], entity, 0.99, target)
                assert decision.strategy not in linkable, f"{target}/{entity}"

    def test_pipl_suppresses_sensitive_information_at_any_confidence(self) -> None:
        """PIPL Art. 28-29: financial accounts and whereabouts are sensitive
        personal information requiring separate consent, which an AI corpus
        does not have. A stable pseudonym for someone's movements is still a
        movement trail — these must be suppressed, not tokenized, and at a
        confidence bar of zero (below_threshold: mask_anyway)."""
        pack = load_pack(REGS / "pipl_china.yaml")
        for entity in ("ACCOUNT_NUMBER", "CREDIT_CARD", "LOCATION", "ADDRESS"):
            decision = _decide([pack], entity, 0.10, "rag")
            assert decision.action == "suppress", entity
            assert decision.strategy == "suppress", entity
            assert decision.outcome == "apply", entity   # mask_anyway

    def test_expert_determination_keeps_dates_where_safe_harbor_generalizes(
        self,
    ) -> None:
        """The one place a shipped pack is deliberately LOOSER than another:
        §164.514(b)(1) lets a statistician's risk assessment retain full dates
        that Safe Harbor reduces to the year."""
        expert = load_pack(REGS / "hipaa_expert_determination.yaml")
        safe_harbor = load_pack(REGS / "hipaa_safe_harbor.yaml")
        assert compose([expert], "DATE").action == "keep"
        assert compose([safe_harbor], "DATE").action == "generalize"

    def test_both_hipaa_routes_together_compose_to_safe_harbor(self) -> None:
        """Strictest-wins means selecting both HIPAA packs is safe: the looser
        expert-determination `keep` cannot weaken Safe Harbor. Users must still
        pick one route — but a mis-click cannot leak a date."""
        packs = load_packs(REGS, ["hipaa_safe_harbor", "hipaa_expert_determination"])
        assert compose(packs, "DATE").action == "generalize"

    def test_glba_masks_account_data_on_weak_evidence(self) -> None:
        """Safeguards Rule: a 'probably an account number' left in clear text
        is an unencrypted customer record. below_threshold: mask_anyway means
        even a 0.1-confidence finding is removed."""
        pack = load_pack(REGS / "glba.yaml")
        decision = _decide([pack], "ACCOUNT_NUMBER", 0.10, "training")
        assert decision.strategy == "suppress"
        assert decision.outcome == "apply"
