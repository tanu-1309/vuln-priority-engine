from tests.conftest import SAMPLE_CSV_PATH, SAMPLE_TRIVY_PATH


class TestHealthAndPolicy:
    def test_health_endpoint(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_policy_endpoint_returns_weights_and_buckets(self, client):
        response = client.get("/policy")
        assert response.status_code == 200
        body = response.json()
        assert body["weights"]["cvss"] == 0.35
        assert any(b["name"] == "critical" for b in body["buckets"])


class TestIngestSample:
    def test_ingest_sample_reports_count(self, client):
        response = client.post("/ingest/sample")
        assert response.status_code == 200
        body = response.json()
        # 5 trivy findings + 5 valid csv findings = 10
        assert body["ingested"] == 10

    def test_vulns_empty_before_any_ingest(self, client):
        response = client.get("/vulns")
        assert response.status_code == 200
        assert response.json() == []

    def test_vulns_ranked_after_sample_ingest(self, client):
        client.post("/ingest/sample")
        response = client.get("/vulns")
        assert response.status_code == 200
        body = response.json()
        assert len(body) == 10
        scores = [item["risk_score"] for item in body]
        assert scores == sorted(scores, reverse=True)

    def test_kev_listed_cves_land_in_critical_bucket(self, client):
        client.post("/ingest/sample")
        response = client.get("/vulns", params={"bucket": "critical"})
        body = response.json()
        cve_ids = {item["cve_id"] for item in body}
        assert "CVE-2021-44228" in cve_ids  # Log4Shell, KEV-listed
        assert "CVE-2019-0708" in cve_ids  # BlueKeep, KEV-listed

    def test_vulns_filter_by_asset_id(self, client):
        client.post("/ingest/sample")
        response = client.get("/vulns", params={"asset_id": "db-prod-01"})
        body = response.json()
        assert body
        assert all(item["asset_id"] == "db-prod-01" for item in body)

    def test_vulns_filter_by_min_score(self, client):
        client.post("/ingest/sample")
        response = client.get("/vulns", params={"min_score": 80})
        body = response.json()
        assert all(item["risk_score"] >= 80 for item in body)

    def test_vulns_respects_limit(self, client):
        client.post("/ingest/sample")
        response = client.get("/vulns", params={"limit": 2})
        assert len(response.json()) == 2

    def test_re_ingesting_sample_upserts_not_duplicates(self, client):
        client.post("/ingest/sample")
        client.post("/ingest/sample")
        response = client.get("/vulns", params={"limit": 1000})
        assert len(response.json()) == 10


class TestIngestUploads:
    def test_ingest_trivy_file_upload(self, client):
        with open(SAMPLE_TRIVY_PATH, "rb") as f:
            response = client.post(
                "/ingest/trivy", files={"file": ("sample_trivy_report.json", f, "application/json")}
            )
        assert response.status_code == 200
        assert response.json()["ingested"] == 5

    def test_ingest_csv_file_upload(self, client):
        with open(SAMPLE_CSV_PATH, "rb") as f:
            response = client.post("/ingest/csv", files={"file": ("sample_cves.csv", f, "text/csv")})
        assert response.status_code == 200
        assert response.json()["ingested"] == 5

    def test_ingest_trivy_rejects_malformed_json(self, client):
        response = client.post(
            "/ingest/trivy", files={"file": ("bad.json", b"{not valid json", "application/json")}
        )
        assert response.status_code == 400

    def test_ingest_csv_rejects_missing_required_columns(self, client):
        response = client.post(
            "/ingest/csv", files={"file": ("bad.csv", b"foo,bar\n1,2\n", "text/csv")}
        )
        assert response.status_code == 400


class TestScoreEndpoint:
    def test_score_ad_hoc_finding(self, client):
        payload = {
            "cve_id": "CVE-2021-44228",
            "asset_id": "hypothetical-asset",
            "source": "manual",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
        }
        response = client.post("/score", json=payload)
        assert response.status_code == 200
        body = response.json()
        assert body["cve_id"] == "CVE-2021-44228"
        assert body["kev_listed"] is True
        assert body["priority_bucket"] == "critical"

    def test_score_endpoint_does_not_persist(self, client):
        payload = {"cve_id": "CVE-2099-0001", "asset_id": "scratch-asset", "source": "manual"}
        client.post("/score", json=payload)
        response = client.get("/vulns")
        assert response.json() == []

    def test_score_endpoint_rejects_missing_required_fields(self, client):
        response = client.post("/score", json={"asset_id": "x"})
        assert response.status_code == 422
