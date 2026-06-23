"""Adapter for Aqua Trivy JSON scan reports (`trivy image -f json ...`).

Trivy's report shape (schema v2) looks like:

{
  "ArtifactName": "myapp:1.4.2",
  "Results": [
    {
      "Target": "myapp:1.4.2 (alpine 3.18.2)",
      "Class": "os-pkgs",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-1234",
          "PkgName": "openssl",
          "InstalledVersion": "3.0.8-r0",
          "FixedVersion": "3.0.9-r0",
          "Title": "openssl: some heap overflow",
          "Severity": "HIGH",
          "CVSS": {
            "nvd": {"V3Score": 7.5},
            "redhat": {"V3Score": 7.4}
          },
          "PublishedDate": "2023-05-01T00:00:00Z"
        }
      ]
    }
  ]
}

`Results` entries with no `Vulnerabilities` key (e.g. secret/misconfig
scans mixed into the same report) are skipped. Multiple `Results`
targets in one report are all folded into the same asset (`ArtifactName`)
since they describe the same scanned artifact.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Union

from ..models import NormalizedFinding, Severity

# Preference order for which vendor's CVSS v3 score to trust when a
# report includes several (Trivy commonly ships nvd/redhat/ghsa scores).
_CVSS_VENDOR_PREFERENCE = ("nvd", "redhat", "ghsa")


def _extract_cvss_score(cvss_block: dict[str, Any] | None) -> float | None:
    if not cvss_block:
        return None
    for vendor in _CVSS_VENDOR_PREFERENCE:
        vendor_scores = cvss_block.get(vendor)
        if vendor_scores and vendor_scores.get("V3Score") is not None:
            return float(vendor_scores["V3Score"])
    # Fall back to any vendor's V3Score, then any V2Score.
    for vendor_scores in cvss_block.values():
        if vendor_scores and vendor_scores.get("V3Score") is not None:
            return float(vendor_scores["V3Score"])
    for vendor_scores in cvss_block.values():
        if vendor_scores and vendor_scores.get("V2Score") is not None:
            return float(vendor_scores["V2Score"])
    return None


def _extract_discovered_at(vuln: dict[str, Any]):
    raw_date = vuln.get("PublishedDate")
    if not raw_date:
        return None
    try:
        return _parse_date(raw_date)
    except ValueError:
        return None


def _parse_date(raw: str):
    from datetime import datetime

    # Trivy emits RFC3339 timestamps, e.g. "2023-05-01T00:00:00Z".
    cleaned = raw.replace("Z", "+00:00")
    return datetime.fromisoformat(cleaned).date()


def parse_trivy_report(source: Union[str, Path, dict, list]) -> list[NormalizedFinding]:
    """Parse a Trivy JSON report into normalized findings.

    `source` may be a path to a JSON file, a raw JSON string, or an
    already-decoded dict/list (useful for tests).
    """
    report = _load_json(source)

    # Trivy can emit a single report object or (rarely, for multi-image
    # scans piped together) a list of report objects.
    reports = report if isinstance(report, list) else [report]

    findings: list[NormalizedFinding] = []
    for rpt in reports:
        asset_id = rpt.get("ArtifactName") or rpt.get("ArtifactType") or "unknown-artifact"
        for result in rpt.get("Results", []) or []:
            vulnerabilities = result.get("Vulnerabilities")
            if not vulnerabilities:
                continue
            for vuln in vulnerabilities:
                cve_id = vuln.get("VulnerabilityID")
                if not cve_id:
                    continue
                findings.append(
                    NormalizedFinding(
                        cve_id=cve_id,
                        asset_id=asset_id,
                        source="trivy",
                        package=vuln.get("PkgName"),
                        installed_version=vuln.get("InstalledVersion"),
                        fixed_version=vuln.get("FixedVersion"),
                        title=vuln.get("Title"),
                        severity=Severity.from_raw(vuln.get("Severity")),
                        cvss_score=_extract_cvss_score(vuln.get("CVSS")),
                        discovered_at=_extract_discovered_at(vuln),
                    )
                )
    return findings


def _load_json(source: Union[str, Path, dict, list]):
    if isinstance(source, (dict, list)):
        return source
    if isinstance(source, Path) or (isinstance(source, str) and Path(source).suffix == ".json" and Path(source).exists()):
        return json.loads(Path(source).read_text())
    if isinstance(source, str):
        # Not an existing file path -> treat as raw JSON text.
        return json.loads(source)
    raise TypeError(f"Unsupported source type for Trivy adapter: {type(source)!r}")
