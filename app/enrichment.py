"""Enrichment layer: merges normalized CVE findings with threat intel.

Three external signals get merged onto every `NormalizedFinding`:

1. **EPSS** (Exploit Prediction Scoring System) - FIRST.org's daily
   probability (0-1) that a CVE will be exploited in the wild in the
   next 30 days. CVSS tells you how *bad* a flaw is; EPSS tells you how
   *likely* it is to actually be used against you.
2. **CISA KEV** (Known Exploited Vulnerabilities catalog) - a binary
   flag: this CVE has confirmed, real-world exploitation, right now.
3. **Asset criticality** - a business judgment call: how much would it
   hurt if *this* asset got popped (customer DB vs. an internal
   dev-only tool).

By default all three are read from bundled, offline sample fixtures in
`data/` so the whole pipeline runs with zero network access and zero
secrets (required for CI and for anyone cloning the repo to try it).

Live data option
----------------
In a real deployment you'd refresh `data/epss_scores.csv` and
`data/kev_catalog.json` on a schedule from the authoritative, free,
no-auth-required feeds:

    EPSS (all CVEs, CSV):  https://epss.cyentia.com/epss_scores-current.csv.gz
    CISA KEV (JSON):       https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

`fetch_live_epss_scores()` / `fetch_live_kev_catalog()` below show how,
using only the stdlib (no extra dependency, no API key). They are never
called by the default pipeline or by the test suite - tests and the API
always run fully offline against the bundled fixtures.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import date, datetime
from pathlib import Path
from typing import NamedTuple, Optional

import yaml

from .models import AssetCriticality, EnrichedFinding, NormalizedFinding

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DEFAULT_EPSS_PATH = DATA_DIR / "epss_scores.csv"
DEFAULT_KEV_PATH = DATA_DIR / "kev_catalog.json"
DEFAULT_ASSET_CRITICALITY_PATH = DATA_DIR / "asset_criticality.yaml"


class EpssEntry(NamedTuple):
    score: float
    percentile: Optional[float]


class KevEntry(NamedTuple):
    date_added: Optional[date]


# ---------------------------------------------------------------------------
# Loaders (bundled, offline fixtures)
# ---------------------------------------------------------------------------


def load_epss_scores(path: Path | str = DEFAULT_EPSS_PATH) -> dict[str, EpssEntry]:
    """Load an EPSS CSV export (FIRST.org format: optional '#' comment line,
    then a `cve,epss,percentile` header) into `{cve_id: EpssEntry}`.
    """
    path = Path(path)
    text = path.read_text()
    return _parse_epss_text(text)


def _parse_epss_text(text: str) -> dict[str, EpssEntry]:
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    scores: dict[str, EpssEntry] = {}
    for row in reader:
        cve_id = (row.get("cve") or "").strip().upper()
        if not cve_id:
            continue
        try:
            score = float(row["epss"])
        except (KeyError, ValueError):
            continue
        percentile_raw = row.get("percentile")
        percentile = float(percentile_raw) if percentile_raw else None
        scores[cve_id] = EpssEntry(score=score, percentile=percentile)
    return scores


def load_kev_catalog(path: Path | str = DEFAULT_KEV_PATH) -> dict[str, KevEntry]:
    """Load a CISA KEV catalog JSON export into `{cve_id: KevEntry}`."""
    path = Path(path)
    raw = json.loads(path.read_text())
    entries: dict[str, KevEntry] = {}
    for vuln in raw.get("vulnerabilities", []):
        cve_id = (vuln.get("cveID") or "").strip().upper()
        if not cve_id:
            continue
        date_added = None
        raw_date = vuln.get("dateAdded")
        if raw_date:
            try:
                date_added = datetime.strptime(raw_date, "%Y-%m-%d").date()
            except ValueError:
                date_added = None
        entries[cve_id] = KevEntry(date_added=date_added)
    return entries


def load_asset_criticality(
    path: Path | str = DEFAULT_ASSET_CRITICALITY_PATH,
) -> tuple[dict[str, AssetCriticality], AssetCriticality]:
    """Load the asset -> criticality-tier map. Returns (map, default_tier)."""
    path = Path(path)
    raw = yaml.safe_load(path.read_text()) or {}
    default_tier = AssetCriticality.from_raw(raw.get("default"))
    asset_map = {
        asset_id: AssetCriticality.from_raw(tier) for asset_id, tier in (raw.get("assets") or {}).items()
    }
    return asset_map, default_tier


# ---------------------------------------------------------------------------
# Core merge
# ---------------------------------------------------------------------------


def enrich_finding(
    finding: NormalizedFinding,
    epss_map: dict[str, EpssEntry],
    kev_map: dict[str, KevEntry],
    asset_map: dict[str, AssetCriticality],
    default_asset_criticality: AssetCriticality = AssetCriticality.MEDIUM,
) -> EnrichedFinding:
    """Merge one normalized finding with EPSS + KEV + asset-criticality data.

    Missing intel degrades gracefully rather than raising: a CVE with no
    EPSS entry gets `epss_score=0.0` (conservative - we simply don't
    have evidence it's being exploited), and an asset with no explicit
    criticality entry falls back to `default_asset_criticality`.
    """
    epss_entry = epss_map.get(finding.cve_id)
    kev_entry = kev_map.get(finding.cve_id)
    criticality = asset_map.get(finding.asset_id, default_asset_criticality)

    return EnrichedFinding(
        **finding.model_dump(),
        epss_score=epss_entry.score if epss_entry else 0.0,
        epss_percentile=epss_entry.percentile if epss_entry else None,
        kev_listed=kev_entry is not None,
        kev_date_added=kev_entry.date_added if kev_entry else None,
        asset_criticality=criticality,
    )


def enrich_findings(
    findings: list[NormalizedFinding],
    epss_path: Path | str = DEFAULT_EPSS_PATH,
    kev_path: Path | str = DEFAULT_KEV_PATH,
    asset_criticality_path: Path | str = DEFAULT_ASSET_CRITICALITY_PATH,
) -> list[EnrichedFinding]:
    """Batch version of `enrich_finding`: loads each intel source once."""
    epss_map = load_epss_scores(epss_path)
    kev_map = load_kev_catalog(kev_path)
    asset_map, default_tier = load_asset_criticality(asset_criticality_path)
    return [
        enrich_finding(f, epss_map, kev_map, asset_map, default_asset_criticality=default_tier)
        for f in findings
    ]


# ---------------------------------------------------------------------------
# Optional: live data fetchers (stdlib-only, NOT used by default/tests)
# ---------------------------------------------------------------------------


def fetch_live_epss_scores(dest_path: Path | str = DEFAULT_EPSS_PATH) -> Path:
    """Download the full current EPSS scores CSV from FIRST.org and save it
    to `dest_path`, overwriting the bundled sample. Requires network access.

    Not called anywhere in the default pipeline or test suite - opt in
    explicitly (e.g. from a scheduled refresh job) when you want live data.
    """
    import gzip
    import urllib.request

    url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310
        compressed = response.read()
    text = gzip.decompress(compressed).decode("utf-8")
    Path(dest_path).write_text(text)
    return Path(dest_path)


def fetch_live_kev_catalog(dest_path: Path | str = DEFAULT_KEV_PATH) -> Path:
    """Download the full current CISA KEV catalog JSON and save it to
    `dest_path`, overwriting the bundled sample. Requires network access.

    Not called anywhere in the default pipeline or test suite - opt in
    explicitly when you want live data.
    """
    import urllib.request

    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310
        raw = response.read()
    Path(dest_path).write_bytes(raw)
    return Path(dest_path)
