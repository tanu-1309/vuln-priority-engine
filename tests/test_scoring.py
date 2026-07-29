import pytest

from app.models import AssetCriticality, EnrichedFinding, Severity
from app.scoring import score_finding, score_findings


def _enriched(
    cve_id="CVE-TEST-0001",
    asset_id="test-asset",
    cvss_score=None,
    epss_score=0.0,
    kev_listed=False,
    asset_criticality=AssetCriticality.MEDIUM,
):
    return EnrichedFinding(
        cve_id=cve_id,
        asset_id=asset_id,
        source="test",
        severity=Severity.HIGH,
        cvss_score=cvss_score,
        epss_score=epss_score,
        kev_listed=kev_listed,
        asset_criticality=asset_criticality,
    )


class TestScoreFinding:
    def test_known_high_risk_combination_matches_hand_computed_score(self, policy):
        # cvss=9.8, epss=0.94371, kev=True, asset=high(75)
        # normalized_cvss=98, epss_component=94.371, kev_component=100, asset_component=75
        # weighted = .35*98 + .35*94.371 + .20*100 + .10*75 = 94.82985
        finding = _enriched(
            cvss_score=9.8,
            epss_score=0.94371,
            kev_listed=True,
            asset_criticality=AssetCriticality.HIGH,
        )
        scored = score_finding(finding, policy)
        assert scored.risk_score == pytest.approx(94.83, abs=0.01)
        assert scored.priority_bucket == "critical"
        assert scored.sla_days == 7

    def test_low_severity_no_intel_lands_in_low_bucket(self, policy):
        finding = _enriched(cvss_score=2.1, epss_score=0.0, kev_listed=False, asset_criticality=AssetCriticality.HIGH)
        scored = score_finding(finding, policy)
        # normalized_cvss=21 -> weighted .35*21=7.35 ; asset .10*75=7.5 -> 14.85
        assert scored.risk_score == pytest.approx(14.85, abs=0.01)
        assert scored.priority_bucket == "low"
        assert scored.sla_days == 180

    def test_missing_cvss_score_treated_as_zero_not_error(self, policy):
        finding = _enriched(cvss_score=None, epss_score=0.0, kev_listed=False, asset_criticality=AssetCriticality.CRITICAL)
        scored = score_finding(finding, policy)
        # normalized_cvss=0; asset .10*100=10
        assert scored.risk_score == pytest.approx(10.0, abs=0.01)
        assert scored.score_breakdown["normalized_cvss"] == 0.0

    def test_kev_forces_critical_bucket_even_with_low_computed_score(self, policy):
        finding = _enriched(
            cvss_score=0.0,
            epss_score=0.0,
            kev_listed=True,
            asset_criticality=AssetCriticality.LOW,
        )
        scored = score_finding(finding, policy)
        # weighted = 0 + 0 + .20*100 + .10*25 = 22.5 -> would naturally be "low"
        assert scored.risk_score == pytest.approx(22.5, abs=0.01)
        assert scored.priority_bucket == "critical"
        assert scored.sla_days == 7
        assert scored.score_breakdown["kev_escalated"] is True

    def test_kev_escalated_flag_false_when_already_critical(self, policy):
        finding = _enriched(cvss_score=10.0, epss_score=1.0, kev_listed=True, asset_criticality=AssetCriticality.CRITICAL)
        scored = score_finding(finding, policy)
        assert scored.priority_bucket == "critical"
        assert scored.score_breakdown["kev_escalated"] is False

    def test_risk_score_is_clamped_to_100(self, policy):
        finding = _enriched(cvss_score=10.0, epss_score=1.0, kev_listed=True, asset_criticality=AssetCriticality.CRITICAL)
        scored = score_finding(finding, policy)
        assert scored.risk_score <= 100.0

    def test_risk_score_is_never_negative(self, policy):
        finding = _enriched(cvss_score=0.0, epss_score=0.0, kev_listed=False, asset_criticality=AssetCriticality.LOW)
        scored = score_finding(finding, policy)
        assert scored.risk_score >= 0.0

    def test_score_breakdown_contains_all_components(self, policy):
        finding = _enriched(cvss_score=5.0, epss_score=0.5, kev_listed=False, asset_criticality=AssetCriticality.MEDIUM)
        scored = score_finding(finding, policy)
        for key in (
            "normalized_cvss",
            "epss_component",
            "kev_component",
            "asset_component",
            "weighted_cvss",
            "weighted_epss",
            "weighted_kev",
            "weighted_asset",
            "kev_escalated",
        ):
            assert key in scored.score_breakdown


class TestScoreFindings:
    def test_results_ranked_highest_risk_first(self, policy):
        low = _enriched(cve_id="CVE-LOW", cvss_score=1.0, epss_score=0.0, asset_criticality=AssetCriticality.LOW)
        high = _enriched(cve_id="CVE-HIGH", cvss_score=9.9, epss_score=0.9, kev_listed=True, asset_criticality=AssetCriticality.CRITICAL)
        mid = _enriched(cve_id="CVE-MID", cvss_score=5.0, epss_score=0.3, asset_criticality=AssetCriticality.MEDIUM)

        ranked = score_findings([low, high, mid], policy)

        assert [f.cve_id for f in ranked] == ["CVE-HIGH", "CVE-MID", "CVE-LOW"]

    def test_ties_break_by_epss_then_cvss(self, policy):
        # Two findings engineered to land on the exact same risk_score,
        # differing only in epss_score (and, to compensate, cvss_score).
        a = _enriched(cve_id="CVE-A", cvss_score=10.0, epss_score=0.0, asset_criticality=AssetCriticality.MEDIUM)
        b = _enriched(cve_id="CVE-B", cvss_score=0.0, epss_score=1.0, asset_criticality=AssetCriticality.MEDIUM)
        # a: .35*100=35 + asset .10*50=5 => 40
        # b: .35*100=35 + asset .10*50=5 => 40
        ranked = score_findings([a, b], policy)
        assert ranked[0].risk_score == ranked[1].risk_score
        # b has higher epss (1.0 vs 0.0) so it should be ranked first on tie-break.
        assert ranked[0].cve_id == "CVE-B"

    def test_empty_input_returns_empty_list(self, policy):
        assert score_findings([], policy) == []
