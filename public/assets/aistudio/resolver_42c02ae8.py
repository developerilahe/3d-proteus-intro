"""Offline fixtures and opt-in public domain enrichment."""
from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .enrichment.cache import EnrichmentCache
from .enrichment.certificates import lookup_certificates
from .enrichment.dns import lookup_dns
from .enrichment.infrastructure import lookup_ip
from .enrichment.models import DomainEnrichment, IpInfrastructure, LookupResult, LookupStatus
from .enrichment.names import ascii_hostname
from .enrichment.rdap import lookup_rdap
from .enrichment.reputation import lookup_reputation
from .models import DnsFacts, Resolver
from .normalize import from_ascii, registrable_domain, to_ascii


COUNTRY_INFO: dict[str, tuple[str, float, float]] = {
    "US": ("United States", 39.8, -98.6),
    "NL": ("Netherlands", 52.1, 5.3),
    "RO": ("Romania", 45.9, 24.97),
    "RU": ("Russia", 61.5, 105.3),
    "CN": ("China", 35.9, 104.2),
    "DE": ("Germany", 51.2, 10.4),
    "GB": ("United Kingdom", 55.4, -3.4),
    "FR": ("France", 46.2, 2.2),
    "SG": ("Singapore", 1.35, 103.8),
    "BR": ("Brazil", -14.2, -51.9),
    "IN": ("India", 20.6, 78.9),
    "TR": ("Turkey", 38.96, 35.24),
    "UA": ("Ukraine", 48.4, 31.2),
    "PA": ("Panama", 8.5, -80.8),
    "SC": ("Seychelles", -4.7, 55.5),
    "HK": ("Hong Kong", 22.3, 114.2),
    "BG": ("Bulgaria", 42.7, 25.5),
    "LT": ("Lithuania", 55.2, 23.9),
    "SE": ("Sweden", 60.1, 18.6),
}

_ORG_POOL: tuple[str, ...] = (
    "HostSlick B.V.", "M247 Europe SRL", "Cloudflare, Inc.", "DigitalOcean, LLC",
    "OVH SAS", "Hetzner Online GmbH", "Amazon.com, Inc.", "Namecheap, Inc.",
    "Contabo GmbH", "Frantech Solutions", "Stark Industries Networks",
)

_ROLE_POOL: tuple[str, ...] = (
    "Shared Hosting", "Bulletproof/High-Risk Hosting", "CDN",
    "VPS Provider", "Cloud Hosting", "Parked/Proxy",
)

_COUNTRY_CODES: tuple[str, ...] = tuple(COUNTRY_INFO.keys())

_ISSUERS: tuple[str, ...] = (
    "Let's Encrypt", "DigiCert", "Sectigo", "ZeroSSL", "Google Trust Services",
)


def _h(value: str, mod: int) -> int:
    return int(hashlib.sha256(value.encode("utf-8")).hexdigest(), 16) % mod


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _netblock(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.0.0/16"
    return "N/A"


def _fingerprint(seed: str) -> str:
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32].upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


class FixtureResolver:
    def __init__(self, fixture_path: str | Path):
        self.path = Path(fixture_path)
        self._data: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        with self.path.open(encoding="utf-8") as f:
            raw = json.load(f)
        if isinstance(raw, dict) and isinstance(raw.get("domains"), dict):
            raw = raw["domains"]
        self._data = {k.lower(): v for k, v in raw.items()}

    @staticmethod
    def _keys(registrable: str) -> list[str]:
        keys = [registrable.lower()]
        try:
            a = to_ascii(registrable).lower()
            if a not in keys:
                keys.append(a)
        except Exception:
            pass
        try:
            d = from_ascii(registrable).lower()
            if d not in keys:
                keys.append(d)
        except Exception:
            pass
        return keys

    def lookup(self, registrable: str) -> DnsFacts | None:
        for key in self._keys(registrable):
            if key in self._data:
                return _enrich(key, self._data[key])
        return None


class DynamicResolver:
    """Resolve a scan's selected candidates through public data sources."""

    LIVE_CAP = 8
    IP_CAP = 4

    def __init__(
        self, fixture_path: str | Path, online: bool = False, *, cache: EnrichmentCache | None = None
    ):
        self.online = bool(online)
        self._fixture = None if self.online else FixtureResolver(fixture_path)
        self._cache = cache if cache is not None else EnrichmentCache()
        self._live_attempts = 0

    def lookup(self, registrable: str) -> DnsFacts | None:
        facts, _ = self.resolve(registrable, registrable)
        return facts

    def resolve(self, domain: str, registrable: str) -> tuple[DnsFacts | None, DomainEnrichment]:
        enrichment = self.lookup_enrichment(domain, registrable)
        if self._fixture is not None:
            return self._fixture.lookup(registrable), enrichment
        return _live_facts(enrichment), enrichment

    def lookup_enrichment(self, domain: str, registrable: str | None = None) -> DomainEnrichment:
        registrable = registrable or registrable_domain(domain)
        if not self.online:
            return DomainEnrichment(
                to_ascii(domain), to_ascii(registrable), collection_note="Live enrichment disabled"
            )
        try:
            hostname = ascii_hostname(domain)
            base = ascii_hostname(registrable)
        except ValueError:
            return DomainEnrichment(
                to_ascii(domain), to_ascii(registrable), collection_note="Invalid hostname"
            )
        if self._live_attempts >= self.LIVE_CAP:
            return DomainEnrichment(hostname, base, collection_note="Scan lookup budget reached")

        self._live_attempts += 1
        with ThreadPoolExecutor(max_workers=4) as pool:
            dns_future = pool.submit(lookup_dns, hostname, timeout=2, cache=self._cache)
            rdap_future = pool.submit(lookup_rdap, base, cache=self._cache)
            reputation_future = pool.submit(lookup_reputation, hostname, cache=self._cache)
            certificate_future = pool.submit(lookup_certificates, hostname, cache=self._cache)
            dns = dns_future.result()
            addresses = dict.fromkeys((*(dns.a.data or ()), *(dns.aaaa.data or ())))
            skipped = LookupResult(LookupStatus.NOT_COLLECTED, detail="IP lookup budget reached")
            infrastructure = tuple(
                lookup_ip(ip, timeout=3, cache=self._cache)
                if index < self.IP_CAP else IpInfrastructure(ip, registration=skipped, ptr=skipped)
                for index, ip in enumerate(addresses)
            )
            return DomainEnrichment(
                hostname, base, rdap=rdap_future.result(), dns=dns,
                reputation=reputation_future.result(), certificates=certificate_future.result(),
                infrastructure=infrastructure,
            )


class NoopResolver:
    def lookup(self, registrable: str) -> DnsFacts | None:
        return None


def _live_facts(enrichment: DomainEnrichment) -> DnsFacts | None:
    dns = enrichment.dns
    registration = enrichment.rdap.data
    age = None
    if registration and registration.registration_date:
        try:
            registered = datetime.fromisoformat(registration.registration_date.replace("Z", "+00:00"))
            if registered.tzinfo is not None:
                age = (_now() - registered).days
                if age < 0:
                    age = None
        except ValueError:
            pass
    # A null MX is a published DNS answer indicating that the host accepts no mail.
    mx = tuple(record for record in (dns.mx.data or ()) if record.split() != ["0", "."])
    facts = DnsFacts(
        a_records=dns.a.data or (),
        aaaa_records=dns.aaaa.data or (),
        mx_records=mx,
        ns_records=dns.ns.data or (),
        spf=next(iter(dns.spf.data or ()), None),
        dmarc=next(iter(dns.dmarc.data or ()), None),
        created_days_ago=age,
        registrar=registration.registrar if registration else None,
        source="LIVE PUBLIC",
    )
    if registration or facts.is_live or facts.ns_records or facts.spf or facts.dmarc:
        return facts
    return None


def _enrich(registrable: str, data: dict) -> DnsFacts:
    now = _now()
    seed = registrable.lower()
    h = _h(seed, 1_000_003)

    a_records = list(data.get("a_records") or [])
    aaaa_records = list(data.get("aaaa_records") or [])
    mx_records = list(data.get("mx_records") or [])
    ns_records = list(data.get("ns_records") or [])

    ip = a_records[0] if a_records else None
    if ip is None and (mx_records or aaaa_records):
        ip = f"185.{h % 250}.{(h // 250) % 250}.{(h // 62_500) % 250}"
        a_records = [ip]

    created = data.get("created_days_ago")
    if created is None and (ip or mx_records):
        created = 30 + (h % 900)

    asn = data.get("asn") or f"AS{1000 + (h % 39000)}"
    org = data.get("asn_org") or _ORG_POOL[h % len(_ORG_POOL)]
    country = data.get("country")
    if country not in COUNTRY_INFO:
        country = _COUNTRY_CODES[h % len(_COUNTRY_CODES)]
    role = data.get("infra_role") or _ROLE_POOL[h % len(_ROLE_POOL)]
    rdns = data.get("rdns")
    if not rdns and ip:
        slug = "".join(ch for ch in org.lower() if ch.isalnum())[:14]
        rdns = f"host-{h % 9999}.{slug}.net"
    abuse = data.get("abuse_contact")
    if not abuse:
        slug = "".join(ch for ch in org.lower() if ch.isalnum())[:14]
        abuse = f"abuse@{slug}.example"

    not_before = None
    not_after = None
    cert_age_days = None
    if ip or mx_records:
        age = min(created or 90, 90)
        nb = now - timedelta(days=age)
        na = nb + timedelta(days=90)
        not_before = nb.isoformat()
        not_after = na.isoformat()
        cert_age_days = age

    past_ips: list[tuple[str, str]] = list(data.get("past_ips") or [])
    if not past_ips and created and h % 3 == 0:
        for i in range(1 + (h % 2)):
            old_ip = f"45.{h % 200}.{(h // 3 + i) % 250}.{(h // 7 + i) % 250}"
            seen = (now - timedelta(days=(created * (i + 1)) // 4)).isoformat()
            past_ips.append((old_ip, seen))

    return DnsFacts(
        a_records=tuple(a_records),
        aaaa_records=tuple(aaaa_records),
        mx_records=tuple(mx_records),
        ns_records=tuple(ns_records),
        spf=data.get("spf"),
        dmarc=data.get("dmarc"),
        created_days_ago=created,
        registrar=data.get("registrar") or "N/A",
        asn=asn,
        asn_org=org,
        country=country,
        region=data.get("region") or country,
        netblock=data.get("netblock") or (_netblock(ip) if ip else "N/A"),
        infra_role=role,
        rdns=rdns or "N/A",
        abuse_contact=abuse,
        past_ips=tuple(past_ips),
        tls_issuer=data.get("tls_issuer") or _ISSUERS[h % len(_ISSUERS)],
        tls_subject=data.get("tls_subject") or registrable,
        tls_sans=tuple(data.get("tls_sans") or (registrable, f"www.{registrable}")),
        tls_not_before=not_before or "N/A",
        tls_not_after=not_after or "N/A",
        tls_fingerprint=data.get("tls_fingerprint") or _fingerprint(seed),
        source="OFFLINE FIXTURE",
    )


def assert_offline_safe(resolver: Resolver) -> None:
    if isinstance(resolver, (FixtureResolver, NoopResolver)):
        return
    if isinstance(resolver, DynamicResolver) and not resolver.online:
        return
    raise RuntimeError(
        f"Resolver {type(resolver).__name__} is not offline-safe. "
        "Live resolvers must be explicitly opted in and locally cached."
    )
