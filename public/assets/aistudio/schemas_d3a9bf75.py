"""Pydantic schemas for PROTEUS API contracts.

SINGLE SOURCE OF TRUTH: All API request/response models are defined here.
Other modules MUST import from this file rather than defining their own models.
This ensures consistency across the API, frontend, and integration layers.

Ownership: Integration & Dashboard team maintains this file.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ScanPass(int, Enum):
    BASELINE = 1
    DRIFT_CHECK = 2


class TakedownChannel(str, Enum):
    DOMAIN_REGISTRAR = "Domain Registrar"
    HOSTING_PROVIDER = "Hosting Provider"
    GOOGLE_SAFE_BROWSING = "Google Safe Browsing"
    MICROSOFT_DEFENDER = "Microsoft Defender SmartScreen"
    APWG = "APWG"
    NATIONAL_CERT = "National CERT / CSIRT"


class Tier(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    WATCH = "WATCH"
    LOW = "LOW"


class Status(str, Enum):
    LIVE_INFRA = "LIVE INFRA"
    PRECRIME = "PRECRIME"
    DRIFT_DETECTED = "DRIFT DETECTED"
    UNRESOLVED = "UNRESOLVED"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class SignalSchema(BaseModel):
    key: str
    label: str
    points: int
    evidence: str = ""


class CandidateSchema(BaseModel):
    domain: str
    ascii_form: str
    registrable: str
    family: str
    rule: str
    technique: str
    importance: str
    weight: int
    provenance: dict[str, str] = {}


class DnsFactsSchema(BaseModel):
    a_records: list[str] = []
    aaaa_records: list[str] = []
    mx_records: list[str] = []
    ns_records: list[str] = []
    spf: str | None = None
    dmarc: str | None = None
    created_days_ago: int | None = None
    registrar: str | None = None
    asn: str | None = None
    asn_org: str | None = None
    country: str | None = None
    region: str | None = None
    netblock: str | None = None
    infra_role: str | None = None
    rdns: str | None = None
    abuse_contact: str | None = None
    past_ips: list[dict[str, str]] = []
    tls_issuer: str | None = None
    tls_subject: str | None = None
    tls_sans: list[str] = []
    tls_not_before: str | None = None
    tls_not_after: str | None = None
    tls_fingerprint: str | None = None
    source: str = "OFFLINE FIXTURE"

    @property
    def is_live(self) -> bool:
        return bool(self.a_records or self.aaaa_records or self.mx_records)

    @property
    def is_mail_enabled(self) -> bool:
        return bool(self.mx_records)


class FindingSchema(BaseModel):
    brand: str
    candidate: CandidateSchema
    facts: DnsFactsSchema | None = None
    signals: list[SignalSchema] = []
    tier: Tier
    score: int
    similarity_pct: int
    mutation_type: str
    status: Status
    osint: dict[str, Any] = {}
    osint_matrix: dict[str, Any] = {}
    timeline: list[dict[str, Any]] = []
    dna: dict[str, Any] | None = None
    precrime: int | None = None
    drift: bool = False
    drift_data: dict[str, Any] | None = None


class ScanRequest(BaseModel):
    brand: str
    scan_pass: ScanPass = ScanPass.BASELINE
    online_enrich: bool = False
    inspect_websites: bool = False
    allowlist: list[str] = Field(default_factory=list)


class ScanResponse(BaseModel):
    scan_id: UUID
    status: ScanStatus
    message: str


class ScanProgress(BaseModel):
    scan_id: UUID
    status: ScanStatus
    progress_pct: int
    current_step: str
    domains_total: int
    domains_processed: int
    findings_so_far: int
    started_at: datetime
    updated_at: datetime
    error: str | None = None


class ScanResults(BaseModel):
    scan_id: UUID
    brand: str
    scan_pass: ScanPass
    online_enrich: bool
    inspect_websites: bool
    generated: int
    tiers: dict[str, int]
    impact: dict[str, Any]
    findings: list[FindingSchema]
    geo: list[GeoPointSchema]
    clusters: list[ClusterSchema]
    completed_at: datetime


class FormFieldSchema(BaseModel):
    name: str | None = None
    type: str | None = None
    autocomplete: str | None = None
    placeholder: str | None = None
    required: bool = False


class FormEvidenceSchema(BaseModel):
    form_index: int
    action: str | None = None
    method: str | None = None
    fields: list[FormFieldSchema] = []
    external_destination: bool = False
    destination_domain: str | None = None
    form_type: str | None = None  # login, payment, otp, verification, unknown


class RedirectHopSchema(BaseModel):
    from_url: str
    to_url: str
    status_code: int | None = None
    redirect_type: str  # http, client_side, meta_refresh, js_location


class ScreenshotRefSchema(BaseModel):
    kind: str  # viewport, fullpage
    path: str
    sha256: str
    timestamp: datetime
    width: int
    height: int


class InspectionResultSchema(BaseModel):
    domain: str
    url: str
    final_url: str
    title: str | None = None
    visible_text: str = ""
    metadata: dict[str, str] = {}
    brand_mentions: list[str] = []
    forms: list[FormEvidenceSchema] = []
    redirects: list[RedirectHopSchema] = []
    screenshots: dict[str, ScreenshotRefSchema] = {}
    errors: list[str] = []
    timestamp: datetime
    inspection_duration_ms: int


class GeoPointSchema(BaseModel):
    code: str
    name: str
    coords: list[float]
    count: int
    threats: int
    asns: list[str]
    domains: list[str]


class ClusterSchema(BaseModel):
    ip: str
    asn: str
    org: str
    country: str
    role: str
    members: list[dict[str, Any]]
    threats: int
    confidence: int
    caveat: str


class ImpactSchema(BaseModel):
    harm_category: str
    triage_hours: float
    exposure_low: str
    exposure_high: str
    defensive_cost: str
    note: str


class ExportRequest(BaseModel):
    scan_id: UUID
    format: str  # csv, json, misp


class TakedownRequest(BaseModel):
    scan_id: UUID
    domain: str
    channel: TakedownChannel = TakedownChannel.DOMAIN_REGISTRAR


class TakedownResponse(BaseModel):
    report: str
    misp: dict[str, Any] | None = None
    error: str | None = None


def new_scan_id() -> UUID:
    return uuid4()