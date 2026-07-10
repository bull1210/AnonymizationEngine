"""Evaluation harness: synthetic labeled corpus -> mask -> measure.

Reports:
  * residual-leak rate (both modes)  — primary quality KPI
  * verification quarantine rate
  * RAG cross-document consistency (same entity => same pseudonym)
  * RAG false-merge rate (distinct entities sharing a pseudonym)

Stdlib-only: runs in any environment, including air-gapped acceptance tests.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass, field

from .core.canonicalize import canonicalize
from .core.checkdigits import luhn_fix, verhoeff_fix
from .core.engine import Engine
from .core.detection import RegexDetector
from .core.policyload import build_policy_table
from .core.pseudonym import MemoryCollisionRegistry
from .core.types import Finding, JobSpec, Status, Strategy, Target

_FIRST = ["Priya", "Arjun", "Meera", "Rahul", "Anita", "Vikram", "Divya", "Karthik",
          "Sneha", "Rohan", "Lakshmi", "Aditya", "Nisha", "Suresh", "Kavya", "Manoj"]
_LAST = ["Sharma", "Iyer", "Patel", "Reddy", "Nair", "Gupta", "Menon", "Singh",
         "Krishnan", "Das", "Bose", "Rao", "Joshi", "Mehta", "Pillai", "Verma"]
_ORGS = ["Apex Solutions", "Bluefin Analytics", "Cygnus Health", "Deccan Motors",
         "Everest Textiles", "Falcon Systems", "Ganga Pharma", "Horizon Steel"]
_MEDS = ["Metformin", "Atorvastatin", "Lisinopril", "Omeprazole", "Amlodipine"]

DEFAULT_POLICY = {
    "version": "eval-1",
    "policies": {
        "training": {
            "PERSON": {"strategy": "placeholder_indexed", "token": "NAME"},
            "ORG": {"strategy": "placeholder_indexed", "token": "ORG"},
            "EMAIL": {"strategy": "placeholder_indexed", "token": "EMAIL", "indexed": False},
            "PHONE": {"strategy": "placeholder_indexed", "token": "PHONE", "indexed": False},
            "CREDIT_CARD": "suppress",
            "AADHAAR": "suppress",
            "DATE": {"strategy": "date_shift"},
            "ZIP": {"strategy": "generalize"},
            "AGE": {"strategy": "generalize"},
            "MEDICATION": {"strategy": "placeholder_indexed", "indexed": False},
        },
        "rag": {
            "PERSON": "hmac_pseudonym",
            "ORG": "hmac_pseudonym",
            "EMAIL": "hmac_pseudonym",
            "PHONE": "hmac_pseudonym",   # fpe in production; hmac keeps harness stdlib-only
            "CREDIT_CARD": "hmac_pseudonym",
            "AADHAAR": "hmac_pseudonym",
            "DATE": "keep",
            "ZIP": "keep",
            "AGE": "keep",
            "MEDICATION": "keep",
        },
    },
}


@dataclass
class SynthDoc:
    file_id: str
    text: str
    findings: list[Finding]
    truth: list[tuple[str, str, str]] = field(default_factory=list)
    # (entity_type, surface, canonical_identity)


def _person_alias(rng: random.Random, first: str, last: str) -> str:
    return rng.choice([f"{first} {last}", f"Dr. {first} {last}", f"{last}, {first}",
                       f"{first.upper()} {last.upper()}"])


def build_corpus(n_docs: int = 40, seed: int = 42) -> list[SynthDoc]:
    rng = random.Random(seed)
    people = [(f, last) for f in _FIRST for last in _LAST]
    rng.shuffle(people)
    people = people[:30]  # entity pool shared across docs (tests cross-doc linking)

    docs: list[SynthDoc] = []
    for i in range(n_docs):
        parts: list[str] = []
        findings: list[Finding] = []
        truth: list[tuple[str, str, str]] = []
        pos = 0

        def emit(s: str) -> None:
            nonlocal pos
            parts.append(s)
            pos += len(s)

        def entity(etype: str, surface: str, identity: str, conf: float = 0.95) -> None:
            nonlocal pos
            findings.append(Finding(etype, pos, pos + len(surface), conf))
            truth.append((etype, surface, identity))
            emit(surface)

        p1, p2 = rng.sample(people, 2)
        org = rng.choice(_ORGS)
        card = luhn_fix("".join(str(rng.randint(0, 9)) for _ in range(16)))
        aadhaar = verhoeff_fix("".join(str(rng.randint(0, 9)) for _ in range(12)))
        phone = "9" + "".join(str(rng.randint(0, 9)) for _ in range(9))
        email = f"{p1[0].lower()}.{p1[1].lower()}@example.com"
        date1 = f"{rng.randint(2020, 2024)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}"

        emit("Case note: ")
        entity("PERSON", _person_alias(rng, *p1), f"{p1[0]} {p1[1]}".lower())
        emit(" of ")
        entity("ORG", org + rng.choice(["", " Pvt Ltd", " Inc."]), org.lower())
        emit(" met ")
        entity("PERSON", _person_alias(rng, *p2), f"{p2[0]} {p2[1]}".lower())
        emit(" on ")
        entity("DATE", date1, date1)
        emit(". Contact: ")
        entity("EMAIL", email, email)
        emit(" / ")
        entity("PHONE", phone, phone)
        emit(". Card ")
        entity("CREDIT_CARD", " ".join(card[j : j + 4] for j in range(0, 16, 4)), card)
        emit(", Aadhaar ")
        entity("AADHAAR", aadhaar, aadhaar)
        emit(". Prescribed ")
        entity("MEDICATION", rng.choice(_MEDS), "med")
        emit(". ZIP ")
        entity("ZIP", f"{rng.randint(560001, 600100)}", "zip")
        emit(", age ")
        entity("AGE", str(rng.randint(25, 95)), "age")
        emit(".")

        docs.append(SynthDoc(f"doc-{i:04d}", "".join(parts), findings, truth))
    return docs


def run_eval(n_docs: int = 40, seed: int = 42) -> dict:
    policy = build_policy_table(DEFAULT_POLICY)
    corpus = build_corpus(n_docs, seed)
    detector = RegexDetector()
    salt = b"\x11" * 32
    report: dict = {"docs": n_docs}

    for target in (Target.TRAINING, Target.RAG):
        registry = MemoryCollisionRegistry()
        engine = Engine(
            policy,
            salt_provider=(lambda job: salt) if target == Target.RAG else None,
            detector=detector,
            collision_registry=registry if target == Target.RAG else None,
        )
        job = JobSpec(job_id=f"eval-{target.value}", target=target)

        leaked = total = quarantined = 0
        token_by_identity: dict[tuple[str, str], set[str]] = {}
        identity_by_token: dict[str, set[str]] = {}

        for doc in corpus:
            result = engine.transform(doc.text, doc.findings, job, doc.file_id)
            if result.receipt.status == Status.LEAK_DETECTED.value:
                quarantined += 1
            rep_by_span = {
                (r.orig_start, r.orig_end): r for r in result.receipt.replacements
            }
            for finding, (etype, surface, identity) in zip(doc.findings, doc.truth):
                if policy.lookup(target, etype).strategy == Strategy.KEEP:
                    continue
                total += 1
                if len(surface) > 3 and surface in result.masked_text:
                    leaked += 1
                if target == Target.RAG:
                    rep = rep_by_span.get((finding.start, finding.end))
                    if rep is not None and rep.strategy == "hmac_pseudonym":
                        canonical = canonicalize(etype, surface)
                        token_by_identity.setdefault((etype, canonical), set()).add(
                            rep.replacement
                        )
                        identity_by_token.setdefault(rep.replacement, set()).add(canonical)

        section = {
            "masked_spans": total,
            "residual_leaks": leaked,
            "residual_leak_rate": round(leaked / total, 6) if total else 0.0,
            "quarantined_docs": quarantined,
        }
        if target == Target.RAG:
            consistent = sum(1 for toks in token_by_identity.values() if len(toks) == 1)
            merged = sum(1 for ids in identity_by_token.values() if len(ids) > 1)
            section.update(
                {
                    "entities_tracked": len(token_by_identity),
                    "consistency_rate": round(consistent / len(token_by_identity), 6)
                    if token_by_identity
                    else 1.0,
                    "false_merges": merged,
                    "false_merge_rate": round(merged / len(identity_by_token), 6)
                    if identity_by_token
                    else 0.0,
                }
            )
        report[target.value] = section
    return report


def format_report(report: dict) -> str:
    lines = [f"Evaluation report — {report['docs']} synthetic documents", "-" * 52]
    for mode in ("training", "rag"):
        s = report[mode]
        lines.append(f"[{mode}]")
        lines.append(f"  masked spans:        {s['masked_spans']}")
        lines.append(f"  residual leaks:      {s['residual_leaks']}"
                     f"  (rate {s['residual_leak_rate']:.4%})")
        lines.append(f"  quarantined docs:    {s['quarantined_docs']}")
        if mode == "rag":
            lines.append(f"  entities tracked:    {s['entities_tracked']}")
            lines.append(f"  consistency rate:    {s['consistency_rate']:.4%}")
            lines.append(f"  false merges:        {s['false_merges']}"
                         f"  (rate {s['false_merge_rate']:.4%})")
    return "\n".join(lines)


if __name__ == "__main__":
    print(format_report(run_eval()))
    print()
    print(json.dumps(run_eval(), indent=2))
