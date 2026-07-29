"""Persistence layer: SQLAlchemy models + engine/session setup.

Uses SQLite by default (`sqlite:///./vuln_priority.db`, or `:memory:`
for tests) so the whole project runs with zero external services. The
engine URL is driven by `DATABASE_URL`, and since everything goes
through SQLAlchemy Core/ORM (not raw SQLite-specific SQL), pointing
`DATABASE_URL` at a Postgres DSN (e.g.
`postgresql+psycopg2://user:pass@host/db`) works without touching any
application code - hence "Postgres-ready".
"""

from __future__ import annotations

import json
import os
from datetime import date
from typing import Iterator, Optional

from sqlalchemy import Boolean, Date, Float, Integer, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from .models import ScoredFinding


class Base(DeclarativeBase):
    pass


class ScoredFindingRecord(Base):
    """Persisted, ranked view of one CVE-on-asset finding."""

    __tablename__ = "scored_findings"

    finding_id: Mapped[str] = mapped_column(String, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String, index=True)
    asset_id: Mapped[str] = mapped_column(String, index=True)
    source: Mapped[str] = mapped_column(String)
    package: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    installed_version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    fixed_version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    title: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    severity: Mapped[str] = mapped_column(String)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    discovered_at: Mapped[Optional[date]] = mapped_column(Date, nullable=True)

    epss_score: Mapped[float] = mapped_column(Float, default=0.0)
    epss_percentile: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    kev_listed: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_date_added: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    asset_criticality: Mapped[str] = mapped_column(String)

    risk_score: Mapped[float] = mapped_column(Float, index=True)
    priority_bucket: Mapped[str] = mapped_column(String, index=True)
    sla_days: Mapped[int] = mapped_column(Integer)
    score_breakdown_json: Mapped[str] = mapped_column(String)

    def to_scored_finding(self) -> ScoredFinding:
        return ScoredFinding(
            cve_id=self.cve_id,
            asset_id=self.asset_id,
            source=self.source,
            package=self.package,
            installed_version=self.installed_version,
            fixed_version=self.fixed_version,
            title=self.title,
            severity=self.severity,
            cvss_score=self.cvss_score,
            discovered_at=self.discovered_at,
            epss_score=self.epss_score,
            epss_percentile=self.epss_percentile,
            kev_listed=self.kev_listed,
            kev_date_added=self.kev_date_added,
            asset_criticality=self.asset_criticality,
            risk_score=self.risk_score,
            priority_bucket=self.priority_bucket,
            sla_days=self.sla_days,
            score_breakdown=json.loads(self.score_breakdown_json),
        )

    @classmethod
    def from_scored_finding(cls, finding: ScoredFinding) -> "ScoredFindingRecord":
        return cls(
            finding_id=finding.finding_id,
            cve_id=finding.cve_id,
            asset_id=finding.asset_id,
            source=finding.source,
            package=finding.package,
            installed_version=finding.installed_version,
            fixed_version=finding.fixed_version,
            title=finding.title,
            severity=finding.severity.value,
            cvss_score=finding.cvss_score,
            discovered_at=finding.discovered_at,
            epss_score=finding.epss_score,
            epss_percentile=finding.epss_percentile,
            kev_listed=finding.kev_listed,
            kev_date_added=finding.kev_date_added,
            asset_criticality=finding.asset_criticality.value,
            risk_score=finding.risk_score,
            priority_bucket=finding.priority_bucket,
            sla_days=finding.sla_days,
            score_breakdown_json=json.dumps(finding.score_breakdown),
        )


def get_database_url() -> str:
    return os.environ.get("DATABASE_URL", "sqlite:///./vuln_priority.db")


def build_engine(database_url: Optional[str] = None):
    url = database_url or get_database_url()
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args)


_engine = build_engine()
_SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)


def init_db(engine=None) -> None:
    Base.metadata.create_all(bind=engine or _engine)


def get_session_factory(engine=None) -> sessionmaker:
    if engine is None:
        return _SessionLocal
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_session() -> Iterator[Session]:
    """FastAPI dependency: yields a request-scoped session."""
    session = _SessionLocal()
    try:
        yield session
    finally:
        session.close()


def upsert_scored_findings(session: Session, findings: list[ScoredFinding]) -> int:
    """Insert or update scored findings, keyed by `finding_id`. Returns count written."""
    count = 0
    for finding in findings:
        record = session.get(ScoredFindingRecord, finding.finding_id)
        new_record = ScoredFindingRecord.from_scored_finding(finding)
        if record is None:
            session.add(new_record)
        else:
            for column in ScoredFindingRecord.__table__.columns.keys():
                if column == "finding_id":
                    continue
                setattr(record, column, getattr(new_record, column))
        count += 1
    session.commit()
    return count
