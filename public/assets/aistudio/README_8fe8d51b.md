# PROTEUS — Enterprise Brand Abuse & Lookalike Domain Intelligence Engine

FastAPI backend + vanilla HTML/CSS/JS frontend. The default scan uses
offline fixtures. **Live Enrich** collects public registration, DNS,
reputation, certificate log, and IP registration data.

## Run

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

## Live enrichment

Enable **Live Enrich** in the dashboard or send `"online_enrich": true` to
`POST /api/scan`. Configure `VIRUSTOTAL_API_KEY` or `URLHAUS_AUTH_KEY` in the
server environment to enable reputation lookups. VirusTotal takes priority
when both keys are set.

Each finding in the scan response and JSON export includes an `enrichment`
record. Lookups can report `found`, `no_records`, `lookup_failed`,
`source_unavailable`, or `not_collected`. The scan attempts live lookups for up
to eight eligible candidates, ordered by their initial technique weight, and
up to four addresses per candidate. Candidates and addresses outside those
budgets carry a reason for skipped collection. DNS and certificate searches
use the exact hostname. Domain RDAP uses the registrable domain.
