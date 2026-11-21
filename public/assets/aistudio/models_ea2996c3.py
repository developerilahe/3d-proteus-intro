"""Immutable data contracts for the detection engine."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Protocol


TIER_ORDER: Mapping[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "WATCH": 2,
    "LOW": 3,
}


@dataclass(frozen=True)
class Candidate:
    domain: str
    ascii_form: str
    registrable: str
    family: str
    rule: str
    technique: str = "unknown"
    importance: str = "Medium"
    weight: int = 50
    provenance: tuple[tuple[str, str], ...] = ()

    @property
    def provenance_dict(self) -> dict[str, str]:
        return dict(self.provenance)


@dataclass(frozen=True)
class Signal:
    key: str
    label: str
    points: int
    evidence: str = ""


@dataclass(frozen=True)
class DnsFacts:
    a_records: tuple[str, ...] = ()
    aaaa_records: tuple[str, ...] = ()
    mx_records: tuple[str, ...] = ()
    ns_records: tuple[str, ...] = ()
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
    past_ips: tuple[tuple[str, str], ...] = ()

    tls_issuer: str | None = None
    tls_subject: str | None = None
    tls_sans: tuple[str, ...] = ()
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

    @classmethod
    def from_dict(cls, data: dict) -> "DnsFacts":
        tls = data.get("tls") or {}
        return cls(
            a_records=tuple(data.get("a_records") or ()),
            aaaa_records=tuple(data.get("aaaa_records") or ()),
            mx_records=tuple(data.get("mx_records") or ()),
            ns_records=tuple(data.get("ns_records") or ()),
            spf=data.get("spf"),
            dmarc=data.get("dmarc"),
            created_days_ago=data.get("created_days_ago"),
            registrar=data.get("registrar"),
            asn=data.get("asn"),
            asn_org=data.get("asn_org"),
            country=data.get("country"),
            region=data.get("region"),
            netblock=data.get("netblock"),
            infra_role=data.get("infra_role"),
            rdns=data.get("rdns"),
            abuse_contact=data.get("abuse_contact"),
            past_ips=tuple(tuple(p) for p in (data.get("past_ips") or ())),
            tls_issuer=data.get("tls_issuer") or tls.get("issuer"),
            tls_subject=data.get("tls_subject") or tls.get("subject_cn"),
            tls_sans=tuple(data.get("tls_sans") or tls.get("san_list") or ()),
            tls_not_before=data.get("tls_not_before") or tls.get("not_before"),
            tls_not_after=data.get("tls_not_after") or tls.get("not_after"),
            tls_fingerprint=data.get("tls_fingerprint") or tls.get("sha256_prefix"),
            source=data.get("source", "OFFLINE FIXTURE"),
        )


@dataclass(frozen=True)
class Finding:
    brand: str
    candidate: Candidate
    facts: DnsFacts | None
    signals: tuple[Signal, ...]
    tier: str = "LOW"
    similarity_pct: int = 0
    mutation_type: str = "other"
    score: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        total = sum(s.points for s in self.signals)
        if total < 0 or total > 100:
            raise ValueError(
                f"score {total} outside [0,100] for {self.candidate.registrable}"
            )
        object.__setattr__(self, "score", total)


class Resolver(Protocol):
    def lookup(self, registrable: str) -> DnsFacts | None: ...