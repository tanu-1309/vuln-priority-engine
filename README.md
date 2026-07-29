# vuln-priority-engine

**CVSS tells you how bad a flaw is. EPSS + CISA KEV tell you whether anyone is actually shooting at it -- this turns your scanner's flat CVE dump into a ranked, SLA-bucketed remediation queue.**

![vuln-priority-engine](assets/hero.png)

## The problem

Security scanners (Trivy, Nessus, Qualys, ...) hand engineering teams thousands of CVEs a week, usually sorted by CVSS severity alone. That's a bad prioritization signal in practice: CVSS measures theoretical worst-case impact, not the probability a flaw actually gets exploited. The result is entirely predictable -- teams burn weeks patching "High" CVEs that nobody has ever weaponized, while a handful of CVEs with active, real-world exploitation sit in the backlog for months because they happened to score "Medium."

`vuln-priority-engine` closes that gap. It ingests raw scanner output, enriches every CVE with **EPSS** (exploit probability), **CISA KEV** (confirmed active exploitation), and **asset criticality** (how much this specific host/image actually matters), and produces one ranked queue with a concrete SLA per finding.

## Architecture

```mermaid
flowchart LR
    A[Scanner adapters<br/>Trivy JSON, Nmap/CSV] --> B[CVE normalization]
    B --> C[Enrichment<br/>EPSS + CISA KEV + asset criticality]
    C --> D[Configurable risk-scoring engine]
    D --> E[Prioritized remediation queue<br/>with SLA tracking]
```

## Quick start

Requires Python 3.11+. Everything runs fully offline against bundled sample data -- no API keys, no external services.

```bash
git clone <this-repo>
cd vuln-priority-engine
pip install -r requirements.txt

# Run the test suite (68 tests)
python -m pytest -v

# Start the API
uvicorn app.main:app --reload

# In another shell: load the bundled sample fixtures (Trivy report + CVE CSV)
curl -X POST http://localhost:8000/ingest/sample

# See the ranked remediation queue
curl http://localhost:8000/vulns | python -m json.tool

# Only the fire drills
curl "http://localhost:8000/vulns?bucket=critical"

# Score one hypothetical finding without persisting anything
curl -X POST http://localhost:8000/score \
  -H 'Content-Type: application/json' \
  -d '{"cve_id": "CVE-2021-44228", "asset_id": "my-prod-host", "source": "manual", "cvss_score": 10.0}'
```

Or with Docker:

```bash
docker build -t vuln-priority-engine .
docker run -p 8000:8000 vuln-priority-engine
```

Interactive API docs (Swagger UI) are auto-generated at `http://localhost:8000/docs`.

## How it works

### 1. Scanner adapters -> normalized CVE model

Two real-world scanner output formats are parsed into one common `NormalizedFinding` shape (`app/models.py`):

- **`app/adapters/trivy_adapter.py`** -- parses Aqua Trivy's JSON report schema (`trivy image -f json ...`), including its multi-vendor `CVSS` block (nvd/redhat/ghsa) and mixed `Results` entries (os-pkgs, secrets, etc.).
- **`app/adapters/csv_adapter.py`** -- parses generic CVE CSV exports (the kind Nessus/Qualys/OpenVAS/homegrown inventories produce), tolerating common header synonyms (`host`/`hostname`/`ip` -> `asset_id`, `cve`/`vulnerability_id` -> `cve_id`, etc.) and skipping non-CVE or malformed rows instead of failing the whole file.

Adding a third format only means writing one more adapter that returns `list[NormalizedFinding]` -- nothing downstream changes.

### 2. Enrichment (`app/enrichment.py`)

Every normalized finding is merged with three signals, loaded from bundled, offline fixtures in `data/`:

| Signal | Source file | What it captures |
|---|---|---|
| CVSS | already on the finding | theoretical severity of the flaw |
| EPSS | `data/epss_scores.csv` | FIRST.org's probability (0-1) of exploitation in the next 30 days |
| CISA KEV | `data/kev_catalog.json` | binary flag: this CVE has *confirmed* real-world exploitation |
| Asset criticality | `data/asset_criticality.yaml` | business judgment: how much this asset matters |

Missing intel degrades gracefully -- a CVE absent from the EPSS/KEV fixtures just gets `epss_score=0.0` / `kev_listed=False` rather than raising, and an asset with no explicit criticality entry falls back to a configurable default tier.

**Live data option:** `enrichment.fetch_live_epss_scores()` and `enrichment.fetch_live_kev_catalog()` show how to refresh those fixtures from the real, free, no-auth-required feeds (`epss.cyentia.com` and CISA's KEV JSON feed) using only the stdlib. They are never called by the default pipeline or the test suite, so the project stays 100% offline unless you opt in.

### 3. Risk-scoring engine (`app/scoring.py` + `policy.yaml`)

Every signal is normalized to 0-100 and combined as a configurable weighted sum:

```
normalized_cvss = (cvss_score or 0) / 10 * 100
epss_component  = epss_score * 100
kev_component   = 100 if kev_listed else 0
asset_component = policy.asset_criticality_scores[tier]     # critical=100, high=75, medium=50, low=25

risk_score = w_cvss * normalized_cvss
           + w_epss * epss_component
           + w_kev  * kev_component
           + w_asset * asset_component
```

Default weights (`policy.yaml`): `cvss=0.35, epss=0.35, kev=0.20, asset_criticality=0.10`. The resulting 0-100 `risk_score` is mapped to a priority bucket / SLA:

| Bucket | Threshold | SLA |
|---|---|---|
| critical | risk_score >= 80 | 7 days |
| high | risk_score >= 60 | 30 days |
| medium | risk_score >= 40 | 90 days |
| low | risk_score >= 0 | 180 days |

**KEV override:** if `force_critical_on_kev: true` (the default), any CVE listed in CISA KEV is force-escalated to the `critical` bucket regardless of its computed score -- an actively-exploited CVE is a fire drill even on a low-criticality asset, because attackers scanning the internet for it don't care about your asset inventory. This is exactly the "reframe the flat CVE list" behavior the project sets out to fix: `policy.yaml` is the one place that defines what "critical" means, and it's meant to be retuned per organization without touching code.

### 4. Storage & API (`app/db.py`, `app/main.py`)

Findings are upserted (by a deterministic `asset_id::cve_id::package` key) into SQLite via SQLAlchemy. Because everything goes through the ORM rather than raw SQLite SQL, pointing the `DATABASE_URL` environment variable at a Postgres DSN (e.g. `postgresql+psycopg2://user:pass@host/db`) works without any code changes.

- `POST /ingest/sample` -- load the bundled Trivy + CSV fixtures (fastest way to see it work)
- `POST /ingest/trivy` -- upload a Trivy JSON report
- `POST /ingest/csv` -- upload a generic CVE CSV
- `GET /vulns` -- the ranked remediation queue, filterable by `bucket`, `asset_id`, `min_score`, `limit`
- `POST /score` -- score one ad-hoc finding without persisting it
- `GET /policy` -- inspect the currently loaded scoring policy

## Testing

68 tests across adapters, enrichment, policy, scoring math (including edge cases: missing CVSS, missing EPSS/KEV entries, KEV-forced escalation, bucket-boundary exactness, tie-breaking), and the full FastAPI request/response cycle.

```bash
python -m pytest -v
```

## Project layout

```
app/
  adapters/          Trivy JSON + generic CVE CSV parsers -> NormalizedFinding
  models.py           Shared pydantic data model (Normalized/Enriched/Scored finding)
  enrichment.py        EPSS + CISA KEV + asset-criticality merge (+ optional live fetchers)
  policy.py            Loads & validates policy.yaml
  scoring.py            The weighted risk-scoring formula + bucket/SLA assignment
  db.py                 SQLAlchemy models + SQLite/Postgres-ready persistence
  main.py               FastAPI app wiring it all together
data/                  Bundled offline sample fixtures (Trivy report, CVE CSV, EPSS, KEV, asset tiers)
policy.yaml            The tunable "what counts as critical" config
tests/                 68 pytest tests
```

## Scope & honest limits

This is a solo-scale prototype, not an enterprise vulnerability-management platform: no auth/RBAC, no live feed scheduler (fetchers are provided but opt-in), no dedupe across scan runs beyond the deterministic finding key, and only two ingest formats. It's deliberately sized to demonstrate the real, hard part of the problem -- a defensible, configurable, tested risk-scoring pipeline -- rather than build out every integration a production SOC would eventually want.

## About the Maintainer

This project is currently maintained by Tanu Sree Reddy Gavinnolla, a Cyber Security Professional pursuing a Master's in Applied Computing. With a background in vulnerability assessment, security documentation, and cyber risk reporting, Tanu brings hands-on experience in securing systems and streamlining remediation processes. Key skills include Python, PowerShell Scripting, and a strong understanding of the MITRE ATT&CK Framework.

Connect:
- Email: gavinno@uwindsor.ca
- LinkedIn: linkedin.com/in/TanusreeReddy

## License

MIT -- see [LICENSE](LICENSE).