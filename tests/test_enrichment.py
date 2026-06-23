from datetime import date

from app.enrichment import (
    enrich_finding,
    enrich_findings,
    load_asset_criticality,
    load_epss_scores,
    load_kev_catalog,
)
from app.models import AssetCriticality, NormalizedFinding, Severity
from tests.conftest import (
    SAMPLE_ASSET_CRITICALITY_PATH,
    SAMPLE_CSV_PATH,
    SAMPLE_EPSS_PATH,
    SAMPLE_KEV_PATH,
    SAMPLE_TRIVY_PATH,
)
from app.adapters import parse_cve_csv, parse_trivy_report


class TestLoaders:
    def test_load_epss_scores_skips_comment_line(self):
        scores = load_epss_scores(SAMPLE_EPSS_PATH)
        assert "CVE-2023-4863" in scores
        assert scores["CVE-2023-4863"].score == 0.94371
        assert scores["CVE-2023-4863"].percentile == 0.99983

    def test_load_epss_scores_keys_are_uppercased(self):
        scores = load_epss_scores(SAMPLE_EPSS_PATH)
        assert all(k == k.upper() for k in scores)

    def test_load_kev_catalog_flags_known_exploited_cves(self):
        kev = load_kev_catalog(SAMPLE_KEV_PATH)
        assert "CVE-2021-44228" in kev
        assert kev["CVE-2021-44228"].date_added == date(2021, 12, 10)

    def test_load_kev_catalog_excludes_non_listed_cves(self):
        kev = load_kev_catalog(SAMPLE_KEV_PATH)
        assert "CVE-2023-0286" not in kev

    def test_load_asset_criticality_returns_map_and_default(self):
        asset_map, default_tier = load_asset_criticality(SAMPLE_ASSET_CRITICALITY_PATH)
        assert asset_map["db-prod-01"] == AssetCriticality.CRITICAL
        assert asset_map["internal-tool-07"] == AssetCriticality.LOW
        assert default_tier == AssetCriticality.MEDIUM


class TestEnrichFinding:
    def _finding(self, cve_id="CVE-2023-4863", asset_id="webapp-backend:2.3.1", cvss=9.8):
        return NormalizedFinding(
            cve_id=cve_id,
            asset_id=asset_id,
            source="trivy",
            severity=Severity.CRITICAL,
            cvss_score=cvss,
        )

    def test_merges_epss_kev_and_asset_criticality(self):
        epss_map = load_epss_scores(SAMPLE_EPSS_PATH)
        kev_map = load_kev_catalog(SAMPLE_KEV_PATH)
        asset_map, default_tier = load_asset_criticality(SAMPLE_ASSET_CRITICALITY_PATH)

        enriched = enrich_finding(self._finding(), epss_map, kev_map, asset_map, default_tier)

        assert enriched.epss_score == 0.94371
        assert enriched.kev_listed is True
        assert enriched.asset_criticality == AssetCriticality.HIGH  # webapp-backend:2.3.1 -> high

    def test_missing_epss_entry_defaults_to_zero(self):
        epss_map = load_epss_scores(SAMPLE_EPSS_PATH)
        kev_map = load_kev_catalog(SAMPLE_KEV_PATH)
        asset_map, default_tier = load_asset_criticality(SAMPLE_ASSET_CRITICALITY_PATH)

        finding = self._finding(cve_id="CVE-2019-9999", asset_id="unknown-asset")
        enriched = enrich_finding(finding, epss_map, kev_map, asset_map, default_tier)

        assert enriched.epss_score == 0.0
        assert enriched.epss_percentile is None
        assert enriched.kev_listed is False

    def test_unknown_asset_falls_back_to_default_criticality(self):
        epss_map = load_epss_scores(SAMPLE_EPSS_PATH)
        kev_map = load_kev_catalog(SAMPLE_KEV_PATH)
        asset_map, default_tier = load_asset_criticality(SAMPLE_ASSET_CRITICALITY_PATH)

        finding = self._finding(asset_id="some-totally-unlisted-host")
        enriched = enrich_finding(finding, epss_map, kev_map, asset_map, default_tier)

        assert enriched.asset_criticality == default_tier == AssetCriticality.MEDIUM

    def test_enrich_findings_batch_matches_manual_merge(self):
        trivy_findings = parse_trivy_report(SAMPLE_TRIVY_PATH)
        enriched = enrich_findings(trivy_findings)
        assert len(enriched) == len(trivy_findings)
        by_cve = {e.cve_id: e for e in enriched}
        assert by_cve["CVE-2021-44228"].kev_listed is True
        assert by_cve["CVE-2019-9999"].kev_listed is False
        assert by_cve["CVE-2019-9999"].epss_score == 0.0

    def test_enrich_findings_on_csv_sample(self):
        csv_findings = parse_cve_csv(SAMPLE_CSV_PATH)
        enriched = enrich_findings(csv_findings)
        by_cve_asset = {(e.cve_id, e.asset_id): e for e in enriched}
        bluekeep = by_cve_asset[("CVE-2019-0708", "db-prod-01")]
        assert bluekeep.kev_listed is True
        assert bluekeep.asset_criticality == AssetCriticality.CRITICAL
