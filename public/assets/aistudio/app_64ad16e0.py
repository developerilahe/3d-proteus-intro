from dataclasses import asdict
from pathlib import Path
from datetime import datetime, timezone, timedelta
from uuid import UUID
from typing import Any
from enum import Enum

from fastapi import FastAPI, Response, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from core.enrichment.cache import EnrichmentCache
from core.normalize import to_ascii
from core.permutations import generate
from core.resolver import DynamicResolver
from core.scoring import analyze_candidate
from core.triage import sort_findings, tier_counts
from core.intel import (
    get_brand_dna,
    get_precrime_risk,
    get_drift_status,
    get_historical_timeline,
    get_osint_intel,
    build_geo_data,
    build_campaign_clusters,
    calculate_aggregate_impact,
    build_osint_matrix,
)
from core.exporters import (
    export_csv,
    export_json,
    generate_takedown_report,
    generate_misp_event,
)
from core.schemas import (
    ScanRequest,
    ScanResponse,
    ScanProgress,
    ScanResults,
    FindingSchema,
    ScanStatus,
    Tier,
    Status,
    SignalSchema,
    CandidateSchema,
    DnsFactsSchema,
    GeoPointSchema,
    ClusterSchema,
    ImpactSchema,
    TakedownChannel,
    ExportRequest,
    new_scan_id,
)

app = FastAPI(title="PROTEUS - Threat Intel")

BASE_DIR = Path(__file__).parent
STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
FIXTURE = BASE_DIR / "data" / "fixtures" / "dns_fixture.json"
ENRICHMENT_CACHE = EnrichmentCache()
STATIC_DIR.mkdir(exist_ok=True)


class ScanJobState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class ScanJob(BaseModel):
    scan_id: UUID
    request: ScanRequest
    state: ScanJobState = ScanJobState.PENDING
    progress_pct: int = 0
    current_step: str = "initializing"
    domains_total: int = 0
    domains_processed: int = 0
    findings_so_far: int = 0
    results: ScanResults | None = None
    error: str | None = None
    started_at: datetime | None = None
    updated_at: datetime | None = None
    completed_at: datetime | None = None


scan_jobs: dict[UUID, ScanJob] = {}

# WARNING: In-memory job store for MVP only.
# Do NOT run with multiple workers (uvicorn --workers > 1) or behind a load balancer.
# Scan state is lost on server restart. For production, replace with Celery + Redis.


def _to_candidate_schema(c) -> CandidateSchema:
    return CandidateSchema(
        domain=c.domain,
        ascii_form=c.ascii_form,
        registrable=c.registrable,
        family=c.family,
        rule=c.rule,
        technique=c.technique,
        importance=c.importance,
        weight=c.weight,
        provenance=c.provenance_dict,
    )


def _to_dns_facts_schema(facts) -> DnsFactsSchema | None:
    if facts is None:
        return None
    return DnsFactsSchema(
        a_records=list(facts.a_records),
        aaaa_records=list(facts.aaaa_records),
        mx_records=list(facts.mx_records),
        ns_records=list(facts.ns_records),
        spf=facts.spf,
        dmarc=facts.dmarc,
        created_days_ago=facts.created_days_ago,
        registrar=facts.registrar,
        asn=facts.asn,
        asn_org=facts.asn_org,
        country=facts.country,
        region=facts.region,
        netblock=facts.netblock,
        infra_role=facts.infra_role,
        rdns=facts.rdns,
        abuse_contact=facts.abuse_contact,
        past_ips=[{"ip": ip, "seen": ts} for ip, ts in facts.past_ips],
        tls_issuer=facts.tls_issuer,
        tls_subject=facts.tls_subject,
        tls_sans=list(facts.tls_sans),
        tls_not_before=facts.tls_not_before,
        tls_not_after=facts.tls_not_after,
        tls_fingerprint=facts.tls_fingerprint,
        source=facts.source,
        is_live=facts.is_live,
        is_mail_enabled=facts.is_mail_enabled,
    )


def _to_signal_schema(s) -> SignalSchema:
    return SignalSchema(key=s.key, label=s.label, points=s.points, evidence=s.evidence)


def _to_finding_schema(f: FindingSchema, brand: str, scan_pass: int, online_enrich: bool) -> FindingSchema:
    dna = get_brand_dna(brand, f, scan_pass)
    precrime = get_precrime_risk(f)
    drift, drift_data = get_drift_status(f, scan_pass)
    osint = get_osint_intel(brand, f, online_enrich)
    timeline = get_historical_timeline(f)
    osint_matrix = build_osint_matrix(brand, f)

    is_live = bool(f.facts and f.facts.is_live)
    if drift:
        status = Status.DRIFT_DETECTED
    elif precrime:
        status = Status.PRECRIME
    elif is_live:
        status = Status.LIVE_INFRA
    else:
        status = Status.UNRESOLVED

    return FindingSchema(
        brand=brand,
        candidate=_to_candidate_schema(f.candidate),
        facts=_to_dns_facts_schema(f.facts),
        signals=[_to_signal_schema(s) for s in f.signals],
        tier=f.tier,
        score=f.score,
        similarity_pct=f.similarity_pct,
        mutation_type=f.mutation_type,
        status=status,
        osint=osint,
        osint_matrix=osint_matrix,
        timeline=timeline,
        dna=dna,
        precrime=precrime,
        drift=drift,
        drift_data=drift_data,
    )


async def run_scan_job(scan_id: UUID):
    job = scan_jobs[scan_id]
    req = job.request
    job.state = ScanJobState.RUNNING
    job.started_at = datetime.now(timezone.utc)
    job.updated_at = job.started_at
    job.current_step = "generating candidates"

    resolver = DynamicResolver(FIXTURE, online=req.online_enrich)
    candidates = generate(req.brand, max_candidates=2000)
    allowlist = {to_ascii(name) for name in req.allowlist}
    allowlist.add(to_ascii(req.brand))

    job.domains_total = len(candidates)
    job.updated_at = datetime.now(timezone.utc)

    findings = []
    for i, c in enumerate(candidates):
        if c.registrable.lower() in allowlist:
            continue
        job.current_step = f"analyzing {c.registrable}"
        job.domains_processed = i + 1
        job.progress_pct = int((i + 1) / len(candidates) * 100)
        job.updated_at = datetime.now(timezone.utc)

        facts = resolver.lookup(c.registrable)
        finding = analyze_candidate(req.brand, c, facts, allowlist=allowlist)
        if finding:
            findings.append(finding)
            job.findings_so_far = len(findings)

    job.current_step = "enriching findings"
    job.updated_at = datetime.now(timezone.utc)

    ordered = sort_findings(findings)
    geo = build_geo_data(ordered)
    clusters = build_campaign_clusters(ordered)
    impact = calculate_aggregate_impact(ordered)

    finding_schemas = [
        _to_finding_schema(f, req.brand, req.scan_pass.value, req.online_enrich)
        for f in ordered
    ]

    job.results = ScanResults(
        scan_id=scan_id,
        brand=req.brand,
        scan_pass=req.scan_pass,
        online_enrich=req.online_enrich,
        inspect_websites=req.inspect_websites,
        generated=len(candidates),
        tiers=tier_counts(ordered),
        impact=impact,
        findings=finding_schemas,
        geo=geo,
        clusters=clusters,
        completed_at=datetime.now(timezone.utc),
    )

    job.state = ScanJobState.COMPLETE
    job.progress_pct = 100
    job.current_step = "complete"
    job.completed_at = datetime.now(timezone.utc)
    job.updated_at = job.completed_at


@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = new_scan_id()
    job = ScanJob(scan_id=scan_id, request=req)
    scan_jobs[scan_id] = job
    background_tasks.add_task(run_scan_job, scan_id)
    return ScanResponse(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        message="Scan started. Poll /api/scan/{scan_id}/status for progress.",
    )


@app.get("/api/scan/{scan_id}/status", response_model=ScanProgress)
async def get_scan_status(scan_id: UUID):
    job = scan_jobs.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanProgress(
        scan_id=job.scan_id,
        status=ScanStatus(job.state.value),
        progress_pct=job.progress_pct,
        current_step=job.current_step,
        domains_total=job.domains_total,
        domains_processed=job.domains_processed,
        findings_so_far=job.findings_so_far,
        started_at=job.started_at or datetime.now(timezone.utc),
        updated_at=job.updated_at or datetime.now(timezone.utc),
        error=job.error,
    )


@app.get("/api/scan/{scan_id}/results", response_model=ScanResults)
async def get_scan_results(scan_id: UUID):
    job = scan_jobs.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    if job.state != ScanJobState.COMPLETE:
        raise HTTPException(status_code=409, detail=f"Scan not complete (state: {job.state.value})")
    if not job.results:
        raise HTTPException(status_code=500, detail="Scan complete but no results")
    return job.results


@app.get("/api/export/csv")
def get_csv(scan_id: UUID):
    job = scan_jobs.get(scan_id)
    if not job or not job.results:
        return Response("No scan data available", status_code=404)
    raw_findings = [
        type('obj', (object,), {
            'candidate': type('obj', (object,), {
                'domain': f.candidate.domain,
                'ascii_form': f.candidate.ascii_form,
                'registrable': f.candidate.registrable,
                'family': f.candidate.family,
                'rule': f.candidate.rule,
                'technique': f.candidate.technique,
                'importance': f.candidate.importance,
                'weight': f.candidate.weight,
                'provenance': f.candidate.provenance,
            })(),
            'facts': type('obj', (object,), {
                'a_records': f.facts.a_records if f.facts else (),
                'aaaa_records': f.facts.aaaa_records if f.facts else (),
                'mx_records': f.facts.mx_records if f.facts else (),
                'ns_records': f.facts.ns_records if f.facts else (),
                'spf': f.facts.spf if f.facts else None,
                'dmarc': f.facts.dmarc if f.facts else None,
                'created_days_ago': f.facts.created_days_ago if f.facts else None,
                'registrar': f.facts.registrar if f.facts else None,
            })() if f.facts else None,
            'signals': [
                type('obj', (object,), {'key': s.key, 'label': s.label, 'points': s.points, 'evidence': s.evidence})()
                for s in f.signals
            ],
            'tier': f.tier,
            'score': f.score,
            'similarity_pct': f.similarity_pct,
            'mutation_type': f.mutation_type,
        })()
        for f in job.results.findings
    ]
    return Response(
        export_csv(raw_findings),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=proteus_triage_{scan_id}.csv"},
    )


@app.get("/api/export/json")
def get_json(scan_id: UUID):
    job = scan_jobs.get(scan_id)
    if not job or not job.results:
        return Response("No scan data available", status_code=404)
    return Response(
        export_json(job.results.findings, job.results.brand),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=proteus_triage_{scan_id}.json"},
    )


@app.get("/api/export/misp/{domain}")
def get_misp(scan_id: UUID, domain: str):
    job = scan_jobs.get(scan_id)
    if not job or not job.results:
        return Response("No scan data available", status_code=404)
    for f in job.results.findings:
        # Match by either Unicode domain or ASCII form (Punycode)
        if f.candidate.domain == domain or f.candidate.ascii_form == domain:
            # Use the finding's candidate object directly (handles encoding)
            candidate_obj = type('obj', (object,), {
                'domain': f.candidate.domain,
                'ascii_form': f.candidate.ascii_form,
                'technique': f.candidate.technique,
            })()
            facts_obj = None
            if f.facts:
                facts_obj = type('obj', (object,), {
                    'a_records': f.facts.a_records,
                    'asn': f.facts.asn,
                    'tls_fingerprint': f.facts.tls_fingerprint,
                })()
            finding_obj = type('obj', (object,), {
                'candidate': candidate_obj,
                'facts': facts_obj,
                'tier': f.tier,
                'score': f.score,
            })()
            try:
                misp = generate_misp_event(finding_obj)
            except Exception as e:
                import traceback
                traceback.print_exc()
                raise HTTPException(status_code=500, detail=str(e))
            import json as _json
            # Use ASCII-safe filename (use ascii_form or sanitized domain)
            safe_domain = f.candidate.ascii_form.replace(".", "_")
            return Response(
                _json.dumps(misp, indent=2),
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=proteus_misp_{safe_domain}.json"},
            )
    raise HTTPException(status_code=404, detail="Domain not found in current scan")


@app.get("/api/takedown/{domain}")
def get_takedown(scan_id: UUID, domain: str, channel: str = "Domain Registrar"):
    job = scan_jobs.get(scan_id)
    if not job or not job.results:
        raise HTTPException(status_code=404, detail="Scan not found")
    for f in job.results.findings:
        if f.candidate.domain == domain:
            if not f.facts or not f.facts.is_live:
                return {"error": "No active hosting observed. Takedown not applicable."}
            finding_obj = type('obj', (object,), {
                'candidate': f.candidate,
                'facts': f.facts,
                'tier': f.tier,
                'score': f.score,
                'similarity_pct': f.similarity_pct,
                'mutation_type': f.mutation_type,
                'signals': f.signals,
            })()
            return {
                "report": generate_takedown_report(finding_obj, channel),
                "misp": generate_misp_event(finding_obj),
            }
    raise HTTPException(status_code=404, detail="Domain not found in current scan")
    return {"error": "Domain not found in current scan"}


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def read_index():
    return FileResponse(STATIC_DIR / "index.html")
