"""Adapter for generic CVE CSV exports.

Many scanners (Nessus, Qualys, OpenVAS, in-house asset inventories) let
you export findings as CSV with slightly different header names. This
adapter accepts a fairly common column set and tolerates a handful of
synonyms so it isn't tied to one vendor's exact export format:

    asset_id | host | hostname | ip
    cve_id | cve | vulnerability_id
    severity | risk
    cvss_score | cvss | cvss_base_score
    package | component | affected_package
    installed_version | version
    fixed_version | remediation_version | patch_version
    title | name | description
    discovered_at | scan_date | detected_on | first_seen

Only `asset_id` and `cve_id` are strictly required per row; everything
else degrades gracefully to `None` (and severity to UNKNOWN) if absent.
Rows missing a required column, or whose `cve_id` doesn't look like a
real CVE identifier, are skipped rather than raising, since real-world
exports routinely contain a mix of CVE and non-CVE findings (e.g. "N/A",
custom plugin IDs).
"""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path
from typing import Union

from ..models import NormalizedFinding, Severity

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

_COLUMN_ALIASES: dict[str, tuple[str, ...]] = {
    "asset_id": ("asset_id", "host", "hostname", "ip", "asset"),
    "cve_id": ("cve_id", "cve", "vulnerability_id", "vuln_id"),
    "severity": ("severity", "risk"),
    "cvss_score": ("cvss_score", "cvss", "cvss_base_score", "cvss3_score"),
    "package": ("package", "component", "affected_package", "pkg_name"),
    "installed_version": ("installed_version", "version"),
    "fixed_version": ("fixed_version", "remediation_version", "patch_version"),
    "title": ("title", "name", "description"),
    "discovered_at": ("discovered_at", "scan_date", "detected_on", "first_seen"),
}


def _build_header_map(fieldnames: list[str]) -> dict[str, str]:
    """Map our canonical field name -> the actual header seen in the CSV."""
    lower_to_actual = {name.strip().lower(): name for name in fieldnames}
    header_map: dict[str, str] = {}
    for canonical, aliases in _COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in lower_to_actual:
                header_map[canonical] = lower_to_actual[alias]
                break
    return header_map


def _get(row: dict[str, str], header_map: dict[str, str], key: str) -> str | None:
    header = header_map.get(key)
    if header is None:
        return None
    value = row.get(header)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _parse_date(raw: str | None):
    if not raw:
        return None
    from datetime import date, datetime

    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%m/%d/%Y", "%d-%m-%Y"):
        try:
            return datetime.strptime(raw, fmt).date()
        except ValueError:
            continue
    try:
        return date.fromisoformat(raw)
    except ValueError:
        return None


def parse_cve_csv(source: Union[str, Path]) -> list[NormalizedFinding]:
    """Parse a generic CVE CSV export into normalized findings.

    `source` may be a path to a `.csv` file that exists on disk, or a raw
    CSV string (including its header row).
    """
    text = _load_text(source)
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return []

    header_map = _build_header_map(reader.fieldnames)
    if "asset_id" not in header_map or "cve_id" not in header_map:
        raise ValueError(
            "CVE CSV is missing a required column: need something that maps "
            "to 'asset_id' (e.g. host/hostname/ip) and 'cve_id' (e.g. cve)."
        )

    findings: list[NormalizedFinding] = []
    for row in reader:
        asset_id = _get(row, header_map, "asset_id")
        cve_id = _get(row, header_map, "cve_id")
        if not asset_id or not cve_id:
            continue
        if not _CVE_PATTERN.match(cve_id):
            # Skip non-CVE rows (custom plugin IDs, "N/A", etc.) rather than fail the whole file.
            continue

        raw_cvss = _get(row, header_map, "cvss_score")
        cvss_score = None
        if raw_cvss:
            try:
                cvss_score = float(raw_cvss)
            except ValueError:
                cvss_score = None

        findings.append(
            NormalizedFinding(
                cve_id=cve_id,
                asset_id=asset_id,
                source="csv",
                package=_get(row, header_map, "package"),
                installed_version=_get(row, header_map, "installed_version"),
                fixed_version=_get(row, header_map, "fixed_version"),
                title=_get(row, header_map, "title"),
                severity=Severity.from_raw(_get(row, header_map, "severity")),
                cvss_score=cvss_score,
                discovered_at=_parse_date(_get(row, header_map, "discovered_at")),
            )
        )
    return findings


def _load_text(source: Union[str, Path]) -> str:
    if isinstance(source, Path):
        return source.read_text()
    if isinstance(source, str) and source.endswith(".csv") and Path(source).exists():
        return Path(source).read_text()
    if isinstance(source, str):
        return source
    raise TypeError(f"Unsupported source type for CSV adapter: {type(source)!r}")
