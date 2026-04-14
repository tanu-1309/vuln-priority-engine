"""Loads and validates the YAML risk-scoring policy (`policy.yaml`).

Keeping "what counts as critical" in a config file (rather than hardcoded
constants) is the whole point of requirement #5 in the project scope:
a security team should be able to retune prioritization without a code
change or redeploy.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, field_validator

DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "policy.yaml"


class Bucket(BaseModel):
    name: str
    min_score: float
    sla_days: int


class Weights(BaseModel):
    cvss: float
    epss: float
    kev: float
    asset_criticality: float


class Policy(BaseModel):
    weights: Weights
    asset_criticality_scores: dict[str, float]
    force_critical_on_kev: bool = True
    buckets: list[Bucket]

    @field_validator("buckets")
    @classmethod
    def _buckets_sorted_desc(cls, buckets: list[Bucket]) -> list[Bucket]:
        if not buckets:
            raise ValueError("policy.yaml must define at least one bucket")
        # Store sorted descending by min_score so evaluation ("first
        # bucket whose threshold is met") is a simple linear scan.
        return sorted(buckets, key=lambda b: b.min_score, reverse=True)

    def bucket_for_score(self, score: float) -> Bucket:
        for bucket in self.buckets:
            if score >= bucket.min_score:
                return bucket
        # Should be unreachable if a bucket with min_score<=0 exists, but
        # guard against a misconfigured policy file.
        return self.buckets[-1]

    def top_bucket(self) -> Bucket:
        return self.buckets[0]

    def asset_score(self, criticality: str) -> float:
        return self.asset_criticality_scores.get(criticality, 50.0)


def load_policy(path: Optional[Path | str] = None) -> Policy:
    policy_path = Path(path) if path else DEFAULT_POLICY_PATH
    if not policy_path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")
    raw = yaml.safe_load(policy_path.read_text())
    return Policy.model_validate(raw)
