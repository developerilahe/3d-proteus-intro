"""Deterministic offline enrichment + OSINT discovery matrix."""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from .lures import lures_in
from .models import Finding
from .resolver import COUNTRY_INFO


def _h(value: str, mod: int) -> int:
    return int(hashlib.sha256(value.encode("utf-8")).hexdigest(), 16) % mod


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat()


def get_brand_dna(brand: str, finding: Finding, scan_pass: int) -> dict | None:
    facts = finding.facts
    if not facts or not facts.is_live:
        return None
    h = _h(finding.candidate.domain + "dna", 1000)
    lures = lures_in(finding.candidate.registrable)
    phrases = ["Sign in to your account", "Verify your identity", "Unusual activity detected"]
    if lures:
        phrases = [f"Continue to {lure.title()}" for lure in lures[:2]] + phrases[:1]
    return {
        "similarity_pct": finding.similarity_pct,
        "logo_match": h % 5 != 0,
        "login_form": bool(lures) or h % 3 == 0,
        "visual_match": h % 4 == 0,
        "matched_phrases": phrases,
        "scan_pass": scan_pass,
    }


def get_precrime_risk(finding: Finding) -> int | None:
    facts = finding.facts
    if facts is not None and facts.is_live:
        return None
    if finding.tier not in ("WATCH", "LOW"):
        return None
    if finding.similarity_pct < 85:
        return None
    h = _h(finding.candidate.domain + "precrime", 100)
    if h % 9 != 0:
        return None
    return 40 + (h % 36)


def get_drift_status(finding: Finding, scan_pass: int) -> tuple[bool, dict | None]:
    facts = finding.facts
    if not facts or not facts.is_live:
        return False, None
    h = _h(finding.candidate.domain + "drift", 1000)
    drift = (h % 11 == 0) or (scan_pass >= 2 and h % 4 == 0)
    if not drift:
        return False, None
    old_ip = facts.past_ips[0][0] if facts.past_ips else f"45.{h % 200}.{(h // 3) % 250}.{(h // 7) % 250}"
    old_mx = "no MX" if h % 2 else "10 mail." + finding.candidate.registrable
    new_mx = ", ".join(facts.mx_records[:1]) if facts.mx_records else "no MX"
    before = f"A {old_ip} · MX {old_mx} · TLS issuer {facts.tls_issuer or 'N/A'}"
    after = (
        f"A {', '.join(facts.a_records[:1]) or 'none'} · MX {new_mx} · "
        f"TLS issuer {facts.tls_issuer or 'N/A'}"
    )
    return True, {
        "before": before,
        "after": after,
        "first_seen": (_now() - timedelta(days=14 + h % 40)).date().isoformat(),
        "observed_at": _now().date().isoformat(),
    }


def get_historical_timeline(finding: Finding) -> list[dict]:
    facts = finding.facts
    now = _now()
    h = _h(finding.candidate.domain + "timeline", 1000)
    events: list[dict] = []

    if facts and facts.created_days_ago is not None:
        events.append({
            "time": (now - timedelta(days=facts.created_days_ago)).isoformat(),
            "kind": "registration",
            "event": f"Domain registered via {facts.registrar or 'unknown registrar'}",
        })
    else:
        events.append({
            "time": (now - timedelta(days=30 + h % 200)).isoformat(),
            "kind": "registration",
            "event": "Registration record unavailable (unresolved candidate)",
        })

    if facts and facts.is_live:
        events.append({
            "time": (now - timedelta(days=7 + h % 25)).isoformat(),
            "kind": "dns",
            "event": f"A record observed at {', '.join(facts.a_records[:1]) or 'unknown'}",
        })
        if facts.tls_not_before and facts.tls_not_before != "N/A":
            events.append({
                "time": facts.tls_not_before,
                "kind": "tls",
                "event": f"TLS issued by {facts.tls_issuer or 'unknown'}",
            })
        if facts.mx_records:
            events.append({
                "time": (now - timedelta(days=3 + h % 15)).isoformat(),
                "kind": "mail",
                "event": f"MX configured: {facts.mx_records[0]}",
            })
    else:
        events.append({
            "time": (now - timedelta(days=2 + h % 10)).isoformat(),
            "kind": "analysis",
            "event": "Lexical analysis flagged candidate; no active hosting observed",
        })

    events.append({
        "time": _iso(now),
        "kind": "scan",
        "event": "Last checked — live" if (facts and facts.is_live) else "Last checked — unresolved",
    })
    return sorted(events, key=lambda e: e["time"])


def _news_items(brand: str, finding: Finding) -> list[dict]:
    now = _now()
    domain = finding.candidate.registrable
    search = f"https://news.google.com/search?q={quote(brand + ' phishing')}"
    items = [
        {
            "source": "PROTEUS Advisory Modeling",
            "type": "modeled",
            "sentiment": "elevated",
            "kind": "offline",
            "title": f"Modeled credential-harvesting pattern consistent with {domain}",
            "summary": (
                f"Offline model groups {domain} with known impersonation classes. "
                f"Not a verified incident; monitor and corroborate."
            ),
            "date": _iso(now - timedelta(days=1 + _h(domain + "n1", 6))),
            "link": search,
        },
        {
            "source": "PROTEUS Brand Watch",
            "type": "advisory",
            "sentiment": "neutral",
            "kind": "offline",
            "title": f"{brand} lookalike registration cluster observed (fixture)",
            "summary": (
                "Deterministic offline fixture summarizes lookalike trends. "
                "Treat as monitoring prompt, not a confirmed campaign."
            ),
            "date": _iso(now - timedelta(days=4 + _h(domain + "n2", 9))),
            "link": search,
        },
    ]
    if finding.facts and finding.facts.is_live and finding.score >= 60:
        items.insert(0, {
            "source": "PROTEUS PreCrime",
            "type": "precrime",
            "sentiment": "elevated",
            "kind": "offline",
            "title": f"Live infrastructure on {domain} raises pre-weaponization risk",
            "summary": (
                "Domain resolves and shows mail/HTTP posture consistent with staged "
                "phishing. Phishing status: Not confirmed."
            ),
            "date": _iso(now - timedelta(days=_h(domain + "n3", 3))),
            "link": search,
        })
    return items


def _osint_links(brand: str, finding: Finding) -> dict[str, list[dict]]:
    domain = finding.candidate.registrable
    q = quote(domain)
    ip = finding.facts.a_records[0] if finding.facts and finding.facts.a_records else None
    asn = finding.facts.asn if finding.facts else None
    infra: list[dict] = []
    if ip:
        infra.append({"source": "Shodan", "url": f"https://www.shodan.io/host/{quote(ip)}",
                      "desc": "Observed services on hosting IP"})
        infra.append({"source": "ipinfo.io", "url": f"https://ipinfo.io/{quote(ip)}",
                      "desc": "ASN, geo, and rDNS"})
    if asn:
        infra.append({"source": "Hurricane Electric BGP", "url": f"https://bgp.he.net/{quote(asn)}",
                      "desc": "ASN routing and peers"})
    infra.append({"source": "Censys", "url": f"https://search.censys.io/search?resource=hosts&q={q}",
                  "desc": "Certificate and host observations"})

    return {
        "registration": [
            {"source": "RDAP", "url": f"https://rdap.org/domain/{q}", "desc": "Public registry registration record"},
            {"source": "ICANN Lookup", "url": f"https://lookup.icann.org/en/lookup?q={q}", "desc": "Registrar and registry"},
            {"source": "Whois.com", "url": f"https://www.whois.com/whois/{q}", "desc": "Public WHOIS"},
        ],
        "dns_history": [
            {"source": "DNSDumpster", "url": f"https://dnsdumpster.com/static/map/{q}.png", "desc": "DNS map visualization"},
            {"source": "SecurityTrails", "url": f"https://securitytrails.com/domain/{q}/dns", "desc": "Historical DNS records"},
            {"source": "ViewDNS", "url": f"https://viewdns.info/iphistory/?domain={q}", "desc": "IP history"},
            {"source": "Mnemonic PassiveDNS", "url": f"https://passivedns.mnemonic.no/search?query={q}", "desc": "Passive DNS"},
            {"source": "MXToolbox", "url": f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{q}", "desc": "MX and mail checks"},
        ],
        "reputation": [
            {"source": "VirusTotal", "url": f"https://www.virustotal.com/gui/domain/{q}", "desc": "Multi-engine reputation"},
            {"source": "URLScan.io", "url": f"https://urlscan.io/domain/{q}", "desc": "Public scan history"},
            {"source": "URLhaus", "url": f"https://urlhaus.abuse.ch/browse.php?search={q}", "desc": "Malware URLs"},
            {"source": "PhishTank", "url": f"https://phishtank.org/search.php?q={q}", "desc": "Community phishing"},
            {"source": "OpenPhish", "url": "https://openphish.com/phishing_feeds.html", "desc": "Open phishing feed"},
            {"source": "AlienVault OTX", "url": f"https://otx.alienvault.com/indicator/domain/{q}", "desc": "Community pulses"},
            {"source": "Google Safe Browsing", "url": f"https://transparencyreport.google.com/safe-browsing/search?url={q}", "desc": "Safe Browsing transparency"},
        ],
        "infrastructure": infra + [
            {"source": "Robtex", "url": f"https://www.robtex.com/dns-lookup/{q}", "desc": "DNS/IP relationships"},
            {"source": "Netlas", "url": f"https://app.netlas.io/responses/?q=domain%3A%22{q}%22", "desc": "Host/certificate search"},
            {"source": "crt.sh", "url": f"https://crt.sh/?q={q}", "desc": "Certificate transparency"},
        ],
        "brand_protection": [
            {"source": "APWG", "url": "https://apwg.org/reportphishing/", "desc": "Report a suspected phishing URL"},
            {"source": "MISP Project", "url": "https://www.misp-project.org/", "desc": "Threat-sharing platform"},
            {"source": "Google News Search", "url": f"https://news.google.com/search?q={quote(brand + ' brand abuse')}", "desc": "Public news search"},
        ],
    }


def get_osint_intel(brand: str, finding: Finding, online: bool) -> dict:
    return {
        "intel": [] if online else _news_items(brand, finding),
        "links": _osint_links(brand, finding),
        "live_enrich_requested": bool(online),
        "source": finding.facts.source if finding.facts else "NO DATA",
    }


def build_osint_matrix(brand: str, finding: Finding) -> dict:
    """Return source-by-source coverage + PROTEUS conclusions."""
    facts = finding.facts
    domain = finding.candidate.registrable
    q = quote(domain)
    ip = facts.a_records[0] if facts and facts.a_records else None
    asn = facts.asn if facts else None

    registered = bool(facts and facts.registrar and facts.registrar != "N/A")
    resolves = bool(facts and facts.is_live)
    recent = bool(facts and facts.created_days_ago is not None and facts.created_days_ago < 90)
    https = bool(facts and facts.tls_issuer and facts.tls_issuer != "N/A")
    has_login = bool(finding.candidate.technique in (
        "combosquatting", "suffix_addition", "prefix_addition", "brand_service", "brand_typo_keyword",
    ))
    has_logo = bool(finding.score >= 60 and resolves)
    shared_infra = bool(asn and asn != "N/A" and facts.infra_role in (
        "Shared Hosting", "CDN", "VPS Provider", "Bulletproof/High-Risk Hosting",
    ))
    phishing_evidence = "None observed (offline fixture)"
    malware_evidence = "None observed (offline fixture)"
    redirects = "Not observed (offline fixture)"

    sections: list[dict] = [
        {
            "category": "Registration & Ownership",
            "relevance": "Medium",
            "sources": [
                {"name": "ICANN Lookup", "tag": "OFFLINE FIXTURE",
                 "link": f"https://lookup.icann.org/en/lookup?q={q}",
                 "conclusion": "Registered" if registered else "No registration observed"},
                {"name": "RDAP.org", "tag": "OFFLINE FIXTURE",
                 "link": f"https://rdap.org/domain/{q}",
                 "conclusion": f"Registrar: {facts.registrar if facts else 'N/A'}; age: "
                                f"{facts.created_days_ago if facts and facts.created_days_ago is not None else 'N/A'}d"},
                {"name": "Whois.com", "tag": "OFFLINE FIXTURE",
                 "link": f"https://www.whois.com/whois/{q}",
                 "conclusion": "Abuse contact: " + (facts.abuse_contact if facts and facts.abuse_contact else "N/A")},
            ],
        },
        {
            "category": "DNS & Historical Infrastructure",
            "relevance": "High",
            "sources": [
                {"name": "DNSDumpster", "tag": "OFFLINE FIXTURE",
                 "link": f"https://dnsdumpster.com/static/map/{q}.png",
                 "conclusion": "Resolves" if resolves else "Unresolved"},
                {"name": "SecurityTrails", "tag": "OFFLINE FIXTURE",
                 "link": f"https://securitytrails.com/domain/{q}/dns",
                 "conclusion": f"Past IPs observed: {len(facts.past_ips) if facts else 0}"},
                {"name": "ViewDNS", "tag": "OFFLINE FIXTURE",
                 "link": f"https://viewdns.info/iphistory/?domain={q}",
                 "conclusion": "Historical IP shifts: " + ("yes" if facts and facts.past_ips else "none")},
                {"name": "Mnemonic PassiveDNS", "tag": "OFFLINE FIXTURE",
                 "link": f"https://passivedns.mnemonic.no/search?query={q}",
                 "conclusion": "Passive DNS: " + ("observed" if resolves else "not observed")},
                {"name": "MXToolbox", "tag": "OFFLINE FIXTURE",
                 "link": f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{q}",
                 "conclusion": "MX: " + (facts.mx_records[0] if facts and facts.mx_records else "none")},
            ],
        },
        {
            "category": "Malicious Reputation & Web Analysis",
            "relevance": "Very high" if finding.score >= 60 else "High",
            "sources": [
                {"name": "VirusTotal", "tag": "OFFLINE FIXTURE",
                 "link": f"https://www.virustotal.com/gui/domain/{q}",
                 "conclusion": phishing_evidence},
                {"name": "URLScan.io", "tag": "OFFLINE FIXTURE",
                 "link": f"https://urlscan.io/domain/{q}",
                 "conclusion": "Login form / logo: " + (
                     "impersonation indicators present" if (has_login or has_logo) else "none")},
                {"name": "URLhaus", "tag": "OFFLINE FIXTURE",
                 "link": f"https://urlhaus.abuse.ch/browse.php?search={q}",
                 "conclusion": malware_evidence},
                {"name": "PhishTank", "tag": "OFFLINE FIXTURE",
                 "link": f"https://phishtank.org/search.php?q={q}",
                 "conclusion": "Campaign relationships: none observed"},
                {"name": "OpenPhish", "tag": "OFFLINE FIXTURE",
                 "link": "https://openphish.com/phishing_feeds.html",
                 "conclusion": "Redirects: " + redirects},
                {"name": "AlienVault OTX", "tag": "OFFLINE FIXTURE",
                 "link": f"https://otx.alienvault.com/indicator/domain/{q}",
                 "conclusion": "Community pulses: none in fixture"},
            ],
        },
        {
            "category": "Hosting, IP & Certificate",
            "relevance": "High",
            "sources": [
                {"name": "Shodan", "tag": "OFFLINE FIXTURE",
                 "link": f"https://www.shodan.io/host/{quote(ip)}" if ip else "#",
                 "conclusion": f"IP: {ip or 'N/A'}"},
                {"name": "Censys", "tag": "OFFLINE FIXTURE",
                 "link": f"https://search.censys.io/search?resource=hosts&q={q}",
                 "conclusion": f"ASN: {asn or 'N/A'} ({facts.asn_org if facts else 'N/A'})"},
                {"name": "Netlas", "tag": "OFFLINE FIXTURE",
                 "link": f"https://app.netlas.io/responses/?q=domain%3A%22{q}%22",
                 "conclusion": f"Infra role: {facts.infra_role if facts else 'N/A'}"},
                {"name": "Robtex", "tag": "OFFLINE FIXTURE",
                 "link": f"https://www.robtex.com/dns-lookup/{q}",
                 "conclusion": "Shared hosting/CDN caveat: " + (
                     "yes — co-location is not common ownership" if shared_infra else "not indicated")},
                {"name": "crt.sh", "tag": "OFFLINE FIXTURE",
                 "link": f"https://crt.sh/?q={q}",
                 "conclusion": "HTTPS cert: " + (facts.tls_issuer if https else "none observed")},
            ],
        },
    ]

    conclusions = {
        "registered": "Registered" if registered else "Unregistered / no record",
        "resolves": "Resolves" if resolves else "Unresolved",
        "recently_registered": "Yes (< 90d)" if recent else "No / unknown",
        "https_observed": "Yes — " + (facts.tls_issuer if https else "") if https else "No",
        "phishing_evidence": phishing_evidence,
        "malware_evidence": malware_evidence,
        "brand_impersonation": f"Yes — similarity {finding.similarity_pct}%, technique {finding.candidate.technique.replace('_', ' ').title()}",
        "login_form_observed": "Yes (fixture model)" if has_login else "No",
        "similar_logo_observed": "Yes (fixture model)" if has_logo else "No",
        "shared_infrastructure": (
            f"Likely — {facts.infra_role} (shared-hosting/CDN caveat applies)"
            if shared_infra else "Not indicated"
        ),
        "suspicious_redirects": redirects,
    }

    return {"sections": sections, "conclusions": conclusions}


def build_geo_data(findings: list[Finding]) -> list[dict]:
    agg: dict[str, dict] = {}
    for f in findings:
        facts = f.facts
        if not facts or not facts.country or facts.country not in COUNTRY_INFO:
            continue
        code = facts.country
        name, lat, lon = COUNTRY_INFO[code]
        g = agg.setdefault(code, {
            "code": code, "name": name,
            "coords": [(lon + 180.0) / 360.0, (90.0 - lat) / 180.0],
            "count": 0, "threats": 0, "asns": set(), "domains": [],
        })
        g["count"] += 1
        if facts.is_live:
            g["threats"] += 1
        if facts.asn:
            g["asns"].add(facts.asn)
        g["domains"].append(f.candidate.domain)

    return sorted(
        [
            {
                "code": g["code"], "name": g["name"], "coords": g["coords"],
                "count": g["count"], "threats": g["threats"],
                "asns": sorted(g["asns"])[:6],
                "domains": sorted(g["domains"])[:12],
            }
            for g in agg.values()
        ],
        key=lambda x: (-x["count"], x["code"]),
    )


def build_campaign_clusters(findings: list[Finding]) -> list[dict]:
    by_ip: dict[str, list[Finding]] = {}
    for f in findings:
        if not f.facts or not f.facts.a_records:
            continue
        by_ip.setdefault(f.facts.a_records[0], []).append(f)

    clusters: list[dict] = []
    for ip, members in by_ip.items():
        if len(members) < 2:
            continue
        sample = members[0].facts
        threats = sum(1 for m in members if m.facts and m.facts.is_live)
        clusters.append({
            "ip": ip,
            "asn": sample.asn or "N/A",
            "org": sample.asn_org or "N/A",
            "country": sample.country or "N/A",
            "role": sample.infra_role or "N/A",
            "members": [
                {"domain": m.candidate.domain, "tier": m.tier, "score": m.score}
                for m in sorted(members, key=lambda x: -x.score)
            ],
            "threats": threats,
            "confidence": min(97, 55 + 12 * len(members) + 4 * threats),
            "caveat": (
                "Shared hosting/CDN caveat: co-location does not prove common "
                "ownership. Corroborate with registrar, certificate, and timing data."
            ),
        })

    if not clusters:
        by_asn: dict[str, list[Finding]] = {}
        for f in findings:
            if f.facts and f.facts.asn:
                by_asn.setdefault(f.facts.asn, []).append(f)
        for asn, members in by_asn.items():
            if len(members) < 3:
                continue
            sample = members[0].facts
            clusters.append({
                "ip": (sample.a_records[0] if sample and sample.a_records else "N/A"),
                "asn": asn,
                "org": sample.asn_org or "N/A" if sample else "N/A",
                "country": sample.country or "N/A" if sample else "N/A",
                "role": sample.infra_role or "N/A" if sample else "N/A",
                "members": [
                    {"domain": m.candidate.domain, "tier": m.tier, "score": m.score}
                    for m in sorted(members, key=lambda x: -x.score)
                ],
                "threats": sum(1 for m in members if m.facts and m.facts.is_live),
                "confidence": min(88, 40 + 8 * len(members)),
                "caveat": (
                    "ASN-level grouping is weaker than IP-level grouping. "
                    "Large providers host unrelated tenants."
                ),
            })

    return sorted(clusters, key=lambda c: (-len(c["members"]), c["ip"]))


def calculate_aggregate_impact(findings: list[Finding]) -> dict:
    total = len(findings)
    live = sum(1 for f in findings if f.facts and f.facts.is_live)
    critical = sum(1 for f in findings if f.tier == "CRITICAL")
    triage_hours = round(total * 0.35 + live * 1.5 + critical * 2.0, 1)
    low = 8_000 + live * 4_500 + critical * 6_000
    high = low * 3 + 25_000
    return {
        "harm_category": "Credential phishing & brand impersonation",
        "triage_hours": triage_hours,
        "exposure_low": f"${low:,}",
        "exposure_high": f"${high:,}",
        "defensive_cost": f"${(low // 3):,}",
        "note": (
            "Modeled business impact derived from candidate volume, liveness, "
            "and tier distribution. Not a verified financial loss figure."
        ),
    }
