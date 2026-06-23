"""FastAPI service exposing the vuln-priority-engine pipeline.

Endpoints
---------
GET  /health              liveness probe
GET  /policy               the currently loaded risk-scoring policy
POST /ingest/sample        load the bundled Trivy + CSV sample fixtures (demo/quick-start)
POST /ingest/trivy         upload & ingest a Trivy JSON report
POST /ingest/csv           upload & ingest a generic CVE CSV export
GET  /vulns                the ranked remediation queue (persisted findings)
POST /score                score a single ad-hoc finding, no persistence

The full pipeline for every ingest endpoint is:
    adapter.parse(...) -> enrichment.enrich_findings(...) -> scoring.score_findings(...) -> db.upsert(...)
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from functools import lru_cache
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import enrichment
from .adapters import parse_cve_csv, parse_trivy_report
from .db import ScoredFindingRecord, get_session, init_db
from .enrichment import DATA_DIR
from .models import NormalizedFinding, ScoredFinding
from .policy import Policy, load_policy
from .scoring import score_findings

SAMPLE_TRIVY_PATH = DATA_DIR / "sample_trivy_report.json"
SAMPLE_CSV_PATH = DATA_DIR / "sample_cves.csv"


@lru_cache(maxsize=1)
def get_policy() -> Policy:
    return load_policy()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="vuln-priority-engine",
    description=(
        "Risk-based vulnerability prioritization: merges CVSS + EPSS + CISA KEV "
        "+ asset criticality into a ranked, SLA-bucketed remediation queue."
    ),
    version="0.1.0",
    lifespan=lifespan,
)


def _pipeline(findings: list[NormalizedFinding], policy: Policy) -> list[ScoredFinding]:
    enriched = enrichment.enrich_findings(findings)
    return score_findings(enriched, policy)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/policy")
def get_policy_view(policy: Policy = Depends(get_policy)) -> dict:
    return policy.model_dump()


@app.post("/ingest/sample")
def ingest_sample(session: Session = Depends(get_session), policy: Policy = Depends(get_policy)) -> dict:
    """Load the bundled Trivy + CSV sample fixtures. Handy for a quick demo
    with zero uploads: `curl -X POST http://localhost:8000/ingest/sample`.
    """
    trivy_findings = parse_trivy_report(SAMPLE_TRIVY_PATH)
    csv_findings = parse_cve_csv(SAMPLE_CSV_PATH)
    scored = _pipeline(trivy_findings + csv_findings, policy)
    from .db import upsert_scored_findings

    written = upsert_scored_findings(session, scored)
    return {"ingested": written, "source": "sample"}


@app.post("/ingest/trivy")
async def ingest_trivy(
    file: UploadFile,
    session: Session = Depends(get_session),
    policy: Policy = Depends(get_policy),
) -> dict:
    raw = await file.read()
    try:
        import json

        report = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid Trivy JSON: {exc}") from exc

    findings = parse_trivy_report(report)
    scored = _pipeline(findings, policy)
    from .db import upsert_scored_findings

    written = upsert_scored_findings(session, scored)
    return {"ingested": written, "source": "trivy", "filename": file.filename}


@app.post("/ingest/csv")
async def ingest_csv(
    file: UploadFile,
    session: Session = Depends(get_session),
    policy: Policy = Depends(get_policy),
) -> dict:
    raw = await file.read()
    text = raw.decode("utf-8")
    try:
        findings = parse_cve_csv(text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scored = _pipeline(findings, policy)
    from .db import upsert_scored_findings

    written = upsert_scored_findings(session, scored)
    return {"ingested": written, "source": "csv", "filename": file.filename}


@app.get("/vulns", response_model=list[ScoredFinding])
def list_vulns(
    bucket: Optional[str] = Query(default=None, description="Filter by priority bucket, e.g. 'critical'"),
    asset_id: Optional[str] = Query(default=None, description="Filter by asset id"),
    min_score: Optional[float] = Query(default=None, ge=0, le=100, description="Minimum risk_score"),
    limit: int = Query(default=100, ge=1, le=1000),
    session: Session = Depends(get_session),
) -> list[ScoredFinding]:
    """The ranked remediation queue: highest risk_score first."""
    stmt = select(ScoredFindingRecord)
    if bucket:
        stmt = stmt.where(ScoredFindingRecord.priority_bucket == bucket)
    if asset_id:
        stmt = stmt.where(ScoredFindingRecord.asset_id == asset_id)
    if min_score is not None:
        stmt = stmt.where(ScoredFindingRecord.risk_score >= min_score)
    stmt = stmt.order_by(ScoredFindingRecord.risk_score.desc()).limit(limit)

    records = session.execute(stmt).scalars().all()
    return [r.to_scored_finding() for r in records]


@app.post("/score", response_model=ScoredFinding)
def score_one(finding: NormalizedFinding, policy: Policy = Depends(get_policy)) -> ScoredFinding:
    """Score a single ad-hoc finding against bundled threat intel. Not persisted -
    useful for "what would this CVE score if it were on this asset" queries.
    """
    scored = _pipeline([finding], policy)
    return scored[0]
