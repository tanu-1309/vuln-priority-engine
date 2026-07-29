from datetime import date

import pytest

from app.adapters.csv_adapter import parse_cve_csv
from app.adapters.trivy_adapter import parse_trivy_report
from app.models import Severity
from tests.conftest import SAMPLE_CSV_PATH, SAMPLE_TRIVY_PATH


class TestTrivyAdapter:
    def test_parses_all_vulnerabilities_from_sample_report(self):
        findings = parse_trivy_report(SAMPLE_TRIVY_PATH)
        assert len(findings) == 5

    def test_skips_results_with_no_vulnerabilities_key(self):
        # The sample report has a second "Results" entry (Class: secret)
        # with no "Vulnerabilities" key at all - it must not blow up or
        # produce a phantom finding.
        findings = parse_trivy_report(SAMPLE_TRIVY_PATH)
        assert all(f.cve_id for f in findings)

    def test_extracts_expected_fields_for_known_finding(self):
        findings = parse_trivy_report(SAMPLE_TRIVY_PATH)
        libwebp = next(f for f in findings if f.cve_id == "CVE-2023-4863")
        assert libwebp.asset_id == "webapp-backend:2.3.1"
        assert libwebp.package == "libwebp"
        assert libwebp.installed_version == "1.3.1-r0"
        assert libwebp.fixed_version == "1.3.2-r0"
        assert libwebp.severity == Severity.CRITICAL
        assert libwebp.source == "trivy"
        assert libwebp.discovered_at == date(2023, 9, 12)

    def test_prefers_nvd_cvss_score_over_other_vendors(self):
        findings = parse_trivy_report(SAMPLE_TRIVY_PATH)
        libwebp = next(f for f in findings if f.cve_id == "CVE-2023-4863")
        # Sample has nvd=9.8, redhat=8.8 -> nvd should win.
        assert libwebp.cvss_score == 9.8

    def test_falls_back_to_any_vendor_score_when_preferred_vendor_missing(self):
        report = {
            "ArtifactName": "test-image:1.0",
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-0001",
                            "Severity": "HIGH",
                            "CVSS": {"ghsa": {"V3Score": 8.1}},
                        }
                    ]
                }
            ],
        }
        findings = parse_trivy_report(report)
        assert findings[0].cvss_score == 8.1

    def test_handles_missing_cvss_block(self):
        report = {
            "ArtifactName": "test-image:1.0",
            "Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2024-0002", "Severity": "LOW"}]}],
        }
        findings = parse_trivy_report(report)
        assert findings[0].cvss_score is None

    def test_accepts_raw_json_string(self):
        raw = '{"ArtifactName": "img", "Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2024-0003"}]}]}'
        findings = parse_trivy_report(raw)
        assert len(findings) == 1
        assert findings[0].cve_id == "CVE-2024-0003"

    def test_finding_id_is_stable_and_unique_per_package(self):
        findings = parse_trivy_report(SAMPLE_TRIVY_PATH)
        ids = {f.finding_id for f in findings}
        assert len(ids) == len(findings)

    def test_unsupported_source_type_raises(self):
        with pytest.raises(TypeError):
            parse_trivy_report(12345)  # type: ignore[arg-type]


class TestCsvAdapter:
    def test_parses_valid_cve_rows_from_sample(self):
        findings = parse_cve_csv(SAMPLE_CSV_PATH)
        cve_ids = {f.cve_id for f in findings}
        # N/A and INVALID-ID rows must be skipped.
        assert "N/A" not in cve_ids
        assert "INVALID-ID" not in cve_ids
        assert "CVE-2019-0708" in cve_ids
        assert len(findings) == 5

    def test_extracts_expected_fields(self):
        findings = parse_cve_csv(SAMPLE_CSV_PATH)
        log4shell = next(f for f in findings if f.cve_id == "CVE-2021-44228")
        assert log4shell.asset_id == "web-prod-03"
        assert log4shell.severity == Severity.CRITICAL
        assert log4shell.cvss_score == 10.0
        assert log4shell.package == "log4j"
        assert log4shell.source == "csv"
        assert log4shell.discovered_at == date(2024, 2, 1)

    def test_missing_cvss_score_becomes_none_not_error(self):
        findings = parse_cve_csv(SAMPLE_CSV_PATH)
        no_score = next(f for f in findings if f.cve_id == "CVE-2024-5555")
        assert no_score.cvss_score is None

    def test_header_aliases_are_recognized(self):
        raw_csv = "host,cve,risk\nsome-host,CVE-2024-9999,HIGH\n"
        findings = parse_cve_csv(raw_csv)
        assert len(findings) == 1
        assert findings[0].asset_id == "some-host"
        assert findings[0].severity == Severity.HIGH

    def test_header_matching_is_case_insensitive(self):
        raw_csv = "Asset_ID,CVE_ID,Severity\nHost1,CVE-2024-1111,LOW\n"
        findings = parse_cve_csv(raw_csv)
        assert len(findings) == 1
        assert findings[0].asset_id == "Host1"

    def test_missing_required_columns_raises_value_error(self):
        raw_csv = "foo,bar\n1,2\n"
        with pytest.raises(ValueError):
            parse_cve_csv(raw_csv)

    def test_empty_csv_returns_empty_list(self):
        assert parse_cve_csv("") == []

    def test_alternate_date_formats_are_parsed(self):
        raw_csv = "asset_id,cve_id,discovered_at\nhost-a,CVE-2024-2222,03/15/2024\n"
        findings = parse_cve_csv(raw_csv)
        assert findings[0].discovered_at == date(2024, 3, 15)

    def test_unparseable_date_becomes_none(self):
        raw_csv = "asset_id,cve_id,discovered_at\nhost-a,CVE-2024-3333,not-a-date\n"
        findings = parse_cve_csv(raw_csv)
        assert findings[0].discovered_at is None
