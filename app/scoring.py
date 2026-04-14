"""The risk-scoring engine: turns an EnrichedFinding into a ScoredFinding.

This is the heart of the "problem" this project solves: CVSS alone is a
poor prioritization signal (it measures theoretical severity, not
real-world exploitation likelihood), so a huge backlog of "High" CVEs
sits unpatched while a handful of actually-dangerous ones do too,
buried in the noise. This module combines four signals into one
0-100 `risk_score` and maps that score to an actionable SLA bucket.

Formula (see policy.yaml for the tunable weights/thresholds):

    normalized_cvss   = (cvss_score or 0) / 10 * 100      # 0-100
    epss_component    = epss_score * 100                  # 0-100
    kev_component     = 100 if kev_listed else 0           # 0 or 100
    asset_component   = policy asset_criticality_scores[tier]  # 0-100

    risk_score = w_cvss   * normalized_cvss
               + w_epss   * epss_component
               + w_kev    * kev_component
               + w_asset  * asset_component

The result is clamped to [0, 100] and mapped to the first bucket (from
`policy.buckets`, evaluated highest-`min_score`-first) whose threshold
the score meets. If `policy.force_critical_on_kev` is true, any KEV-listed
CVE is force-escalated to the top (most urgent) bucket regardless of its
computed score - an actively-exploited CVE is a fire drill even on a
low-criticality asset, because attackers scanning for it don't care
about your asset inventory.
"""

from __future__ import annotations

from .models import EnrichedFinding, ScoredFinding
from .policy import Policy


def score_finding(finding: EnrichedFinding, policy: Policy) -> ScoredFinding:
    normalized_cvss = ((finding.cvss_score or 0.0) / 10.0) * 100.0
    epss_component = finding.epss_score * 100.0
    kev_component = 100.0 if finding.kev_listed else 0.0
    asset_component = policy.asset_score(finding.asset_criticality.value)

    weighted_cvss = policy.weights.cvss * normalized_cvss
    weighted_epss = policy.weights.epss * epss_component
    weighted_kev = policy.weights.kev * kev_component
    weighted_asset = policy.weights.asset_criticality * asset_component

    raw_score = weighted_cvss + weighted_epss + weighted_kev + weighted_asset
    risk_score = max(0.0, min(100.0, raw_score))

    bucket = policy.bucket_for_score(risk_score)
    kev_escalated = False
    if policy.force_critical_on_kev and finding.kev_listed:
        top = policy.top_bucket()
        if bucket.name != top.name:
            kev_escalated = True
        bucket = top

    breakdown = {
        "normalized_cvss": round(normalized_cvss, 2),
        "epss_component": round(epss_component, 2),
        "kev_component": kev_component,
        "asset_component": asset_component,
        "weighted_cvss": round(weighted_cvss, 2),
        "weighted_epss": round(weighted_epss, 2),
        "weighted_kev": round(weighted_kev, 2),
        "weighted_asset": round(weighted_asset, 2),
        "kev_escalated": kev_escalated,
    }

    return ScoredFinding(
        **finding.model_dump(),
        risk_score=round(risk_score, 2),
        priority_bucket=bucket.name,
        sla_days=bucket.sla_days,
        score_breakdown=breakdown,
    )


def score_findings(findings: list[EnrichedFinding], policy: Policy) -> list[ScoredFinding]:
    """Score every finding and return them ranked highest-risk-first.

    Ties break by EPSS (probability of near-term exploitation) then by
    CVSS, so among equally-risky findings the "more likely to be
    exploited soon" one is queued first.
    """
    scored = [score_finding(f, policy) for f in findings]
    scored.sort(key=lambda f: (f.risk_score, f.epss_score, f.cvss_score or 0.0), reverse=True)
    return scored
