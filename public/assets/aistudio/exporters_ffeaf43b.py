"""Deterministic JSON/CSV exporters plus takedown and MISP generators."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Iterable, Mapping

from .models import Finding
from .triage import sort_findings

CSV_COLUMNS = [
    "domain", "ascii_form", "registrable", "family", "technique",
    "importance", "weight", "rule", "tier", "score", "similarity_pct",
    "mutation_type", "a_record", "mx", "spf", "dmarc", "age_days",
    "registrar", "reasons",
]


def _reasons(f: Finding) -> str:
    return " | ".join(f"{s.key}:{s.points}" for s in f.signals)


def _row(f: Finding) -> dict[str, str]:
    facts = f.facts
    return {
        "domain": f.candidate.domain,
        "ascii_form": f.candidate.ascii_form,
        "registrable": f.candidate.registrable,
        "family": f.candidate.family,
        "technique": f.candidate.technique,
        "importance": f.candidate.importance,
        "weight": str(f.candidate.weight),
        "rule": f.candidate.rule,
        "tier": f.tier,
        "score": str(f.score),
        "similarity_pct": str(f.similarity_pct),
        "mutation_type": f.mutation_type,
        "a_record": "1" if facts and facts.a_records else "0",
        "mx": "1" if facts and facts.mx_records else "0",
        "spf": "1" if facts and facts.spf else "0",
        "dmarc": "1" if facts and facts.dmarc else "0",
        "age_days": str(facts.created_days_ago) if facts and facts.created_days_ago is not None else "",
        "registrar": (facts.registrar if facts and facts.registrar else ""),
        "reasons": _reasons(f),
    }


def export_csv(findings: Iterable[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    for f in sort_findings(findings):
        writer.writerow(_row(f))
    return buf.getvalue()


def export_json(
    findings: Iterable[Finding], brand: str | None = None, *,
    enrichments: Mapping[str, dict] | None = None,
) -> str:
    ordered = sort_findings(findings)
    records = [_finding_to_dict(f) for f in ordered]
    if enrichments is not None:
        for record in records:
            if record["domain"] in enrichments:
                record["enrichment"] = enrichments[record["domain"]]
    payload = {
        "brand": brand,
        "count": len(ordered),
        "findings": records,
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)


def _finding_to_dict(f: Finding) -> dict:
    return {
        "domain": f.candidate.domain,
        "ascii_form": f.candidate.ascii_form,
        "registrable": f.candidate.registrable,
        "family": f.candidate.family,
        "rule": f.candidate.rule,
        "technique": f.candidate.technique,
        "importance": f.candidate.importance,
        "weight": f.candidate.weight,
        "provenance": dict(f.candidate.provenance),
        "tier": f.tier,
        "score": f.score,
        "similarity_pct": f.similarity_pct,
        "mutation_type": f.mutation_type,
        "facts": _facts_dict(f.facts),
        "signals": [
            {"key": s.key, "label": s.label, "points": s.points, "evidence": s.evidence}
            for s in f.signals
        ],
    }


def _facts_dict(facts) -> dict | None:
    if facts is None:
        return None
    return {
        "a_records": list(facts.a_records),
        "aaaa_records": list(facts.aaaa_records),
        "mx_records": list(facts.mx_records),
        "ns_records": list(facts.ns_records),
        "spf": facts.spf,
        "dmarc": facts.dmarc,
        "created_days_ago": facts.created_days_ago,
        "registrar": facts.registrar,
        "asn": facts.asn,
        "asn_org": facts.asn_org,
        "country": facts.country,
        "region": facts.region,
        "netblock": facts.netblock,
        "infra_role": facts.infra_role,
        "rdns": facts.rdns,
        "abuse_contact": facts.abuse_contact,
        "past_ips": [list(p) for p in facts.past_ips],
        "tls": {
            "issuer": facts.tls_issuer,
            "subject_cn": facts.tls_subject,
            "san_list": list(facts.tls_sans),
            "not_before": facts.tls_not_before,
            "not_after": facts.tls_not_after,
            "sha256_prefix": facts.tls_fingerprint,
        },
        "source": facts.source,
    }


def _recipient(channel: str, f: Finding) -> str:
    facts = f.facts
    return {
        "Domain Registrar": f"Registrar abuse desk — {facts.registrar if facts else 'unknown'}",
        "Hosting Provider": f"Hosting abuse desk — {facts.asn_org if facts else 'unknown'} ({facts.abuse_contact if facts else 'N/A'})",
        "Google Safe Browsing": "Google Safe Browsing — https://safebrowsing.google.com/",
        "Microsoft Defender SmartScreen": "Microsoft — https://www.microsoft.com/wdsi/support/report-unsafe-site",
        "APWG": "APWG eCrime Exchange — https://apwg.org/reportphishing/",
        "National CERT / CSIRT": "National CERT/CSIRT abuse intake",
    }.get(channel, channel)


def generate_takedown_report(f: Finding, channel: str = "Domain Registrar") -> str:
    facts = f.facts
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    evidence = "\n".join(
        f"  - {s.label} (+{s.points})" + (f" — {s.evidence}" if s.evidence else "")
        for s in f.signals
    )
    return f"""PROTEUS TAKEDOWN REQUEST
========================================
Generated (UTC): {now}
Channel: {channel}
Recipient: {_recipient(channel, f)}

TARGET
  Domain:            {f.candidate.domain}
  ASCII / Punycode:  {f.candidate.ascii_form}
  Registrable:       {f.candidate.registrable}
  Technique:         {f.candidate.technique} ({f.candidate.importance}, weight {f.candidate.weight}/100)
  Mutation type:     {f.mutation_type}
  Name similarity:   {f.similarity_pct}%
  Risk tier:         {f.tier} (score {f.score}/100)

HOSTING & REGISTRATION
  Registrar:         {facts.registrar if facts else 'N/A'}
  Domain age:        {f'{facts.created_days_ago} days' if facts and facts.created_days_ago is not None else 'N/A'}
  A records:         {', '.join(facts.a_records) if facts and facts.a_records else 'N/A'}
  MX records:        {', '.join(facts.mx_records) if facts and facts.mx_records else 'N/A'}
  NS records:        {', '.join(facts.ns_records) if facts and facts.ns_records else 'N/A'}
  ASN:               {facts.asn if facts else 'N/A'} ({facts.asn_org if facts else 'N/A'})
  Netblock:          {facts.netblock if facts else 'N/A'}
  Country:           {facts.country if facts else 'N/A'}
  Infra role:        {facts.infra_role if facts else 'N/A'}
  rDNS:              {facts.rdns if facts else 'N/A'}
  Abuse contact:     {facts.abuse_contact if facts else 'N/A'}

TLS
  Issuer:            {facts.tls_issuer if facts else 'N/A'}
  Subject CN:        {facts.tls_subject if facts else 'N/A'}
  SANs:              {', '.join(facts.tls_sans) if facts and facts.tls_sans else 'N/A'}
  Valid from:        {facts.tls_not_before if facts else 'N/A'}
  Valid to:          {facts.tls_not_after if facts else 'N/A'}
  SHA-256 prefix:    {facts.tls_fingerprint if facts else 'N/A'}

EVIDENCE (explainable signals)
{evidence}

REQUESTED ACTION
  1. Suspend or sinkhole the domain pending abuse review.
  2. Preserve registration, DNS, and TLS records for the retention period.
  3. Confirm receipt and provide a case reference.

LEGAL / SAFETY NOTE
  This report is generated from defensive brand-protection analysis.
  All telemetry is fixture-derived unless explicitly tagged LIVE PUBLIC.
  No unauthorized access, scanning, or payload interaction was performed.

Signature: PROTEUS / Lookalike Sentinel — automated brand protection
"""


def generate_misp_event(f: Finding) -> dict:
    facts = f.facts
    attributes = [
        {"type": "domain", "category": "Network activity", "to_ids": True, "value": f.candidate.domain},
        {"type": "domain", "category": "Network activity", "to_ids": True, "value": f.candidate.ascii_form},
    ]
    if facts:
        for ip in facts.a_records:
            attributes.append({"type": "ip-dst", "category": "Network activity", "to_ids": True, "value": ip})
        if facts.asn:
            attributes.append({"type": "AS", "category": "Network activity", "to_ids": False, "value": facts.asn})
        if facts.tls_fingerprint and facts.tls_fingerprint != "N/A":
            attributes.append({
                "type": "x509-fingerprint-sha256",
                "category": "Network activity",
                "to_ids": False,
                "value": facts.tls_fingerprint.replace(":", ""),
            })
    return {
        "Event": {
            "info": f"PROTEUS lookalike: {f.candidate.domain} — {f.candidate.technique} ({f.tier} {f.score})",
            "distribution": "0",
            "threat_level_id": "1" if f.tier == "CRITICAL" else "2",
            "analysis": "1",
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "published": False,
            "Attribute": attributes,
            "Tag": [
                {"name": "brand-abuse"},
                {"name": "lookalike-domain"},
                {"name": f"technique:{f.candidate.technique}"},
                {"name": f"tier:{f.tier.lower()}"},
                {"name": "tlp:amber"},
            ],
        }
    }
