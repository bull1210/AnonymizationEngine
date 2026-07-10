"""Pydantic v2 boundary models — external contracts (Kafka messages, API
bodies) validated here, then converted to core dataclasses via .to_core()."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

from .core import types as core


class FindingModel(BaseModel):
    entity_type: str
    start: int = Field(ge=0)
    end: int = Field(gt=0)
    confidence: float = Field(ge=0.0, le=1.0)
    tier: str = "T1"
    validated: bool = False

    @field_validator("end")
    @classmethod
    def _end_after_start(cls, v: int, info) -> int:
        if "start" in info.data and v <= info.data["start"]:
            raise ValueError("end must be > start")
        return v

    def to_core(self) -> core.Finding:
        return core.Finding(
            entity_type=self.entity_type.upper(),
            start=self.start,
            end=self.end,
            confidence=self.confidence,
            tier=self.tier,
            validated=self.validated,
        )


class ScanResultModel(BaseModel):
    file_id: str
    findings: list[FindingModel] = Field(default_factory=list)


class JobConfigModel(BaseModel):
    job_id: str
    downstream_target: Literal["training", "rag"]
    tenant_id: str = "default"
    confidence_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    type_thresholds: dict[str, float] = Field(default_factory=dict)
    strategy_overrides: dict[str, str] = Field(default_factory=dict)
    salt_scope: Literal["tenant", "corpus", "run"] = "tenant"
    corpus_id: str = ""
    reversible: bool = False
    pseudonym_len: int = Field(default=8, ge=6, le=32)
    policy_version: str = "0"

    def to_core(self) -> core.JobSpec:
        return core.jobspec_from_dict(self.model_dump())


class DryRunRequest(BaseModel):
    file_id: str = "adhoc"
    text: str
    findings: list[FindingModel]
    job: JobConfigModel


class RevealRequest(BaseModel):
    pseudonym: str
    reason: str = Field(min_length=10)
