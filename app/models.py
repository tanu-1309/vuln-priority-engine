"""Normalized CVE data model shared by every scanner adapter.

Every adapter (Trivy JSON, generic CVE CSV, ...) parses its own vendor
format into a list of `NormalizedFinding` objects. Everything downstream
(enrichment, scoring, API, storage) only ever deals with this one shape,
so adding a new scanner format never touches enrichment/scoring code.
"""

from __future__ import annotations

from datetime import date, datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    """Scanner-reported severity label, normalized to a common vocabulary."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_raw(cls, raw: Optional[str]) -> "Severity":
        if not raw:
            return cls.UNKNOWN
        normalized = raw.strip().upper()
        if normalized in {"CRIT", "CRITICAL"}:
            return cls.CRITICAL
        if normalized in {"HIGH"}:
            return cls.HIGH
        if normalized in {"MED", "MEDIUM", "MODERATE"}:
            return cls.MEDIUM
        if normalized in {"LOW", "MINOR", "INFO", "INFORMATIONAL", "NEGLIGIBLE"}:
            return cls.LOW
        return cls.UNKNOWN


class AssetCriticality(str, Enum):
    """Business-defined criticality tier for the asset a CVE was found on."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @classmethod
    def from_raw(cls, raw: Optional[str]) -> "AssetCriticality":
        if not raw:
            return cls.MEDIUM
        normalized = raw.strip().lower()
        for member in cls:
            if member.value == normalized:
                return member
        return cls.MEDIUM


class NormalizedFinding(BaseModel):
    """One CVE observed on one asset, in a scanner-agnostic shape.

    `finding_id` is a stable, deterministic key (asset_id + cve_id +
    package) used to de-duplicate the same finding reported by multiple
    scanners and to upsert into storage idempotently.
    """

    cve_id: str
    asset_id: str
    source: str = Field(description="Adapter/scanner that produced this finding, e.g. 'trivy', 'csv'")
    package: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    title: Optional[str] = None
    severity: Severity = Severity.UNKNOWN
    cvss_score: Optional[float] = None
    discovered_at: Optional[date] = None

    @field_validator("cve_id")
    @classmethod
    def _upper_cve(cls, v: str) -> str:
        return v.strip().upper()

    @field_validator("cvss_score")
    @classmethod
    def _clamp_cvss(cls, v: Optional[float]) -> Optional[float]:
        if v is None:
            return None
        return max(0.0, min(10.0, float(v)))

    @property
    def finding_id(self) -> str:
        pkg = self.package or "-"
        return f"{self.asset_id}::{self.cve_id}::{pkg}"


class EnrichedFinding(NormalizedFinding):
    """A NormalizedFinding merged with external threat-intel + asset context."""

    epss_score: float = Field(default=0.0, ge=0.0, le=1.0, description="EPSS exploit probability, 0-1")
    epss_percentile: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    kev_listed: bool = Field(default=False, description="Present in the CISA Known Exploited Vulnerabilities catalog")
    kev_date_added: Optional[date] = None
    asset_criticality: AssetCriticality = AssetCriticality.MEDIUM


class ScoredFinding(EnrichedFinding):
    """An EnrichedFinding after the risk-scoring formula has been applied."""

    risk_score: float = Field(ge=0.0, le=100.0)
    priority_bucket: str
    sla_days: int
    score_breakdown: dict = Field(default_factory=dict)

    @property
    def due_date(self) -> Optional[date]:
        base = self.discovered_at or date.today()
        from datetime import timedelta

        return base + timedelta(days=self.sla_days)
