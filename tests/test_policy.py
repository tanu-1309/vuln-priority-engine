from pathlib import Path

import pytest

from app.policy import load_policy


class TestLoadPolicy:
    def test_loads_bundled_policy_yaml(self, policy):
        assert policy.weights.cvss == 0.35
        assert policy.weights.epss == 0.35
        assert policy.weights.kev == 0.20
        assert policy.weights.asset_criticality == 0.10

    def test_force_critical_on_kev_defaults_true_in_bundled_policy(self, policy):
        assert policy.force_critical_on_kev is True

    def test_buckets_sorted_descending_by_min_score(self, policy):
        thresholds = [b.min_score for b in policy.buckets]
        assert thresholds == sorted(thresholds, reverse=True)

    def test_missing_policy_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_policy(Path("/tmp/does-not-exist-vuln-priority-policy.yaml"))

    def test_asset_score_falls_back_for_unknown_tier(self, policy):
        assert policy.asset_score("nonexistent-tier") == 50.0


class TestBucketForScore:
    def test_exact_critical_threshold(self, policy):
        assert policy.bucket_for_score(80.0).name == "critical"

    def test_just_below_critical_threshold_is_high(self, policy):
        assert policy.bucket_for_score(79.99).name == "high"

    def test_exact_high_threshold(self, policy):
        assert policy.bucket_for_score(60.0).name == "high"

    def test_exact_medium_threshold(self, policy):
        assert policy.bucket_for_score(40.0).name == "medium"

    def test_just_below_medium_threshold_is_low(self, policy):
        assert policy.bucket_for_score(39.99).name == "low"

    def test_zero_score_is_low(self, policy):
        bucket = policy.bucket_for_score(0.0)
        assert bucket.name == "low"
        assert bucket.sla_days == 180

    def test_top_bucket_is_critical(self, policy):
        assert policy.top_bucket().name == "critical"
