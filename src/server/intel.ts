import { createHash } from 'node:crypto';
import { luresIn } from './lures.ts';
import { COUNTRY_INFO } from './resolver.ts';
import type {
  CampaignCluster,
  Finding,
  GeoPoint,
  ImpactSummary,
} from './types.ts';

function deterministicHash(value: string, mod: number): number {
  const hex = createHash('sha256').update(value, 'utf8').digest('hex').slice(0, 12);
  return Number(BigInt('0x' + hex) % BigInt(mod));
}

function titleCase(str: string): string {
  return str.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

export function getBrandDna(
  _brand: string,
  finding: Finding,
  scanPass: number
): Record<string, unknown> | null {
  const facts = finding.facts;
  if (!facts || !facts.is_live) return null;
  const h = deterministicHash(finding.candidate.domain + 'dna', 1000);
  const lures = luresIn(finding.candidate.registrable);
  let phrases = [
    'Sign in to your account',
    'Verify your identity',
    'Unusual activity detected',
  ];
  if (lures.length > 0) {
    phrases = [
      ...lures.slice(0, 2).map((l) => `Continue to ${titleCase(l)}`),
      phrases[0],
    ];
  }
  return {
    similarity_pct: finding.similarity_pct,
    logo_match: h % 5 !== 0,
    login_form: lures.length > 0 || h % 3 === 0,
    visual_match: h % 4 === 0,
    matched_phrases: phrases,
    scan_pass: scanPass,
  };
}

export function getPrecrimeRisk(finding: Finding): number | null {
  const facts = finding.facts;
  if (facts && facts.is_live) return null;
  if (finding.tier !== 'WATCH' && finding.tier !== 'LOW') return null;
  if (finding.similarity_pct < 85) return null;
  const h = deterministicHash(finding.candidate.domain + 'precrime', 100);
  if (h % 9 !== 0) return null;
  return 40 + (h % 36);
}

export function getDriftStatus(
  finding: Finding,
  scanPass: number
): { drift: boolean; driftData: Record<string, unknown> | null } {
  const facts = finding.facts;
  if (!facts || !facts.is_live) return { drift: false, driftData: null };
  const h = deterministicHash(finding.candidate.domain + 'drift', 1000);
  const drift = h % 11 === 0 || (scanPass >= 2 && h % 4 === 0);
  if (!drift) return { drift: false, driftData: null };

  const oldIp =
    facts.past_ips[0]?.ip ??
    `45.${h % 200}.${Math.floor(h / 3) % 250}.${Math.floor(h / 7) % 250}`;
  const oldMx = h % 2 ? 'no MX' : `10 mail.${finding.candidate.registrable}`;
  const newMx = facts.mx_records.slice(0, 1).join(', ') || 'no MX';
  const before = `A ${oldIp} · MX ${oldMx} · TLS issuer ${facts.tls_issuer || 'N/A'}`;
  const after = `A ${facts.a_records.slice(0, 1).join(', ') || 'none'} · MX ${newMx} · TLS issuer ${facts.tls_issuer || 'N/A'}`;
  const now = new Date();
  const firstSeen = new Date(now.getTime() - (14 + (h % 40)) * 86_400_000)
    .toISOString()
    .slice(0, 10);

  return {
    drift: true,
    driftData: {
      before,
      after,
      first_seen: firstSeen,
      observed_at: now.toISOString().slice(0, 10),
    },
  };
}

export function getHistoricalTimeline(finding: Finding): Array<Record<string, string>> {
  const facts = finding.facts;
  const now = Date.now();
  const h = deterministicHash(finding.candidate.domain + 'timeline', 1000);
  const events: Array<{ time: string; kind: string; event: string }> = [];

  if (facts && facts.created_days_ago !== null) {
    events.push({
      time: new Date(now - facts.created_days_ago * 86_400_000).toISOString(),
      kind: 'registration',
      event: `Domain registered via ${facts.registrar || 'unknown registrar'}`,
    });
  } else {
    events.push({
      time: new Date(now - (30 + (h % 200)) * 86_400_000).toISOString(),
      kind: 'registration',
      event: 'Registration record unavailable (unresolved candidate)',
    });
  }

  if (facts && facts.is_live) {
    events.push({
      time: new Date(now - (7 + (h % 25)) * 86_400_000).toISOString(),
      kind: 'dns',
      event: `A record observed at ${facts.a_records.slice(0, 1).join(', ') || 'unknown'}`,
    });
    if (facts.tls_not_before && facts.tls_not_before !== 'N/A') {
      events.push({
        time: facts.tls_not_before,
        kind: 'tls',
        event: `TLS issued by ${facts.tls_issuer || 'unknown'}`,
      });
    }
    if (facts.mx_records.length > 0) {
      events.push({
        time: new Date(now - (3 + (h % 15)) * 86_400_000).toISOString(),
        kind: 'mail',
        event: `MX configured: ${facts.mx_records[0]}`,
      });
    }
  } else {
    events.push({
      time: new Date(now - (2 + (h % 10)) * 86_400_000).toISOString(),
      kind: 'analysis',
      event: 'Lexical analysis flagged candidate; no active hosting observed',
    });
  }

  events.push({
    time: new Date(now).toISOString().replace(/\.\d{3}Z$/, '+00:00'),
    kind: 'scan',
    event: facts && facts.is_live ? 'Last checked — live' : 'Last checked — unresolved',
  });

  return events.sort((a, b) => a.time.localeCompare(b.time));
}

function newsItems(brand: string, finding: Finding) {
  const now = Date.now();
  const domain = finding.candidate.registrable;
  const search = `https://news.google.com/search?q=${encodeURIComponent(`${brand} phishing`)}`;
  const items = [
    {
      source: 'PROTEUS Advisory Modeling',
      type: 'modeled',
      sentiment: 'elevated',
      kind: 'offline',
      title: `Modeled credential-harvesting pattern consistent with ${domain}`,
      summary: `Offline model groups ${domain} with known impersonation classes. Not a verified incident; monitor and corroborate.`,
      date: new Date(now - (1 + deterministicHash(domain + 'n1', 6)) * 86_400_000).toISOString(),
      link: search,
    },
    {
      source: 'PROTEUS Brand Watch',
      type: 'advisory',
      sentiment: 'neutral',
      kind: 'offline',
      title: `${brand} lookalike registration cluster observed (fixture)`,
      summary:
        'Deterministic offline fixture summarizes lookalike trends. Treat as monitoring prompt, not a confirmed campaign.',
      date: new Date(now - (4 + deterministicHash(domain + 'n2', 9)) * 86_400_000).toISOString(),
      link: search,
    },
  ];

  if (finding.facts && finding.facts.is_live && finding.score >= 60) {
    items.unshift({
      source: 'PROTEUS PreCrime',
      type: 'precrime',
      sentiment: 'elevated',
      kind: 'offline',
      title: `Live infrastructure on ${domain} raises pre-weaponization risk`,
      summary:
        'Domain resolves and shows mail/HTTP posture consistent with staged phishing. Phishing status: Not confirmed.',
      date: new Date(now - deterministicHash(domain + 'n3', 3) * 86_400_000).toISOString(),
      link: search,
    });
  }

  return items;
}

function osintLinks(brand: string, finding: Finding) {
  const domain = finding.candidate.registrable;
  const q = encodeURIComponent(domain);
  const ip = finding.facts?.a_records[0] ?? null;
  const asn = finding.facts?.asn ?? null;
  const infra: Array<{ source: string; url: string; desc: string }> = [];

  if (ip) {
    infra.push({
      source: 'Shodan',
      url: `https://www.shodan.io/host/${encodeURIComponent(ip)}`,
      desc: 'Observed services on hosting IP',
    });
    infra.push({
      source: 'ipinfo.io',
      url: `https://ipinfo.io/${encodeURIComponent(ip)}`,
      desc: 'ASN, geo, and rDNS',
    });
  }
  if (asn) {
    infra.push({
      source: 'Hurricane Electric BGP',
      url: `https://bgp.he.net/${encodeURIComponent(asn)}`,
      desc: 'ASN routing and peers',
    });
  }
  infra.push({
    source: 'Censys',
    url: `https://search.censys.io/search?resource=hosts&q=${q}`,
    desc: 'Certificate and host observations',
  });

  return {
    registration: [
      { source: 'RDAP', url: `https://rdap.org/domain/${q}`, desc: 'Public registry registration record' },
      { source: 'ICANN Lookup', url: `https://lookup.icann.org/en/lookup?q=${q}`, desc: 'Registrar and registry' },
      { source: 'Whois.com', url: `https://www.whois.com/whois/${q}`, desc: 'Public WHOIS' },
    ],
    dns_history: [
      { source: 'DNSDumpster', url: `https://dnsdumpster.com/static/map/${q}.png`, desc: 'DNS map visualization' },
      { source: 'SecurityTrails', url: `https://securitytrails.com/domain/${q}/dns`, desc: 'Historical DNS records' },
      { source: 'ViewDNS', url: `https://viewdns.info/iphistory/?domain=${q}`, desc: 'IP history' },
      { source: 'Mnemonic PassiveDNS', url: `https://passivedns.mnemonic.no/search?query=${q}`, desc: 'Passive DNS' },
      { source: 'MXToolbox', url: `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${q}`, desc: 'MX and mail checks' },
    ],
    reputation: [
      { source: 'VirusTotal', url: `https://www.virustotal.com/gui/domain/${q}`, desc: 'Multi-engine reputation' },
      { source: 'URLScan.io', url: `https://urlscan.io/domain/${q}`, desc: 'Public scan history' },
      { source: 'URLhaus', url: `https://urlhaus.abuse.ch/browse.php?search=${q}`, desc: 'Malware URLs' },
      { source: 'PhishTank', url: `https://phishtank.org/search.php?q=${q}`, desc: 'Community phishing' },
      { source: 'OpenPhish', url: 'https://openphish.com/phishing_feeds.html', desc: 'Open phishing feed' },
      { source: 'AlienVault OTX', url: `https://otx.alienvault.com/indicator/domain/${q}`, desc: 'Community pulses' },
      { source: 'Google Safe Browsing', url: `https://transparencyreport.google.com/safe-browsing/search?url=${q}`, desc: 'Safe Browsing transparency' },
    ],
    infrastructure: [
      ...infra,
      { source: 'Robtex', url: `https://www.robtex.com/dns-lookup/${q}`, desc: 'DNS/IP relationships' },
      { source: 'Netlas', url: `https://app.netlas.io/responses/?q=domain%3A%22${q}%22`, desc: 'Host/certificate search' },
      { source: 'crt.sh', url: `https://crt.sh/?q=${q}`, desc: 'Certificate transparency' },
    ],
    brand_protection: [
      { source: 'APWG', url: 'https://apwg.org/reportphishing/', desc: 'Report a suspected phishing URL' },
      { source: 'MISP Project', url: 'https://www.misp-project.org/', desc: 'Threat-sharing platform' },
      { source: 'Google News Search', url: `https://news.google.com/search?q=${encodeURIComponent(`${brand} brand abuse`)}`, desc: 'Public news search' },
    ],
  };
}

export function getOsintIntel(brand: string, finding: Finding, online: boolean): Record<string, unknown> {
  return {
    intel: online ? [] : newsItems(brand, finding),
    links: osintLinks(brand, finding),
    live_enrich_requested: Boolean(online),
    source: finding.facts ? finding.facts.source : 'NO DATA',
  };
}

export function buildOsintMatrix(_brand: string, finding: Finding): Record<string, unknown> {
  const facts = finding.facts;
  const domain = finding.candidate.registrable;
  const q = encodeURIComponent(domain);
  const ip = facts?.a_records[0] ?? null;
  const asn = facts?.asn ?? null;

  const registered = Boolean(facts && facts.registrar && facts.registrar !== 'N/A');
  const resolves = Boolean(facts && facts.is_live);
  const recent = Boolean(
    facts && facts.created_days_ago !== null && facts.created_days_ago < 90
  );
  const https = Boolean(facts && facts.tls_issuer && facts.tls_issuer !== 'N/A');
  const hasLogin = [
    'combosquatting',
    'suffix_addition',
    'prefix_addition',
    'brand_service',
    'brand_typo_keyword',
  ].includes(finding.candidate.technique);
  const hasLogo = finding.score >= 60 && resolves;
  const sharedInfra = Boolean(
    asn &&
      asn !== 'N/A' &&
      facts?.infra_role &&
      ['Shared Hosting', 'CDN', 'VPS Provider', 'Bulletproof/High-Risk Hosting'].includes(
        facts.infra_role
      )
  );
  const phishingEvidence = 'None observed (offline fixture)';
  const malwareEvidence = 'None observed (offline fixture)';
  const redirects = 'Not observed (offline fixture)';

  const sections = [
    {
      category: 'Registration & Ownership',
      relevance: 'Medium',
      sources: [
        {
          name: 'ICANN Lookup',
          tag: 'OFFLINE FIXTURE',
          link: `https://lookup.icann.org/en/lookup?q=${q}`,
          conclusion: registered ? 'Registered' : 'No registration observed',
        },
        {
          name: 'RDAP.org',
          tag: 'OFFLINE FIXTURE',
          link: `https://rdap.org/domain/${q}`,
          conclusion: `Registrar: ${facts?.registrar || 'N/A'}; age: ${facts && facts.created_days_ago !== null ? facts.created_days_ago : 'N/A'}d`,
        },
        {
          name: 'Whois.com',
          tag: 'OFFLINE FIXTURE',
          link: `https://www.whois.com/whois/${q}`,
          conclusion: `Abuse contact: ${facts?.abuse_contact || 'N/A'}`,
        },
      ],
    },
    {
      category: 'DNS & Historical Infrastructure',
      relevance: 'High',
      sources: [
        {
          name: 'DNSDumpster',
          tag: 'OFFLINE FIXTURE',
          link: `https://dnsdumpster.com/static/map/${q}.png`,
          conclusion: resolves ? 'Resolves' : 'Unresolved',
        },
        {
          name: 'SecurityTrails',
          tag: 'OFFLINE FIXTURE',
          link: `https://securitytrails.com/domain/${q}/dns`,
          conclusion: `Past IPs observed: ${facts ? facts.past_ips.length : 0}`,
        },
        {
          name: 'ViewDNS',
          tag: 'OFFLINE FIXTURE',
          link: `https://viewdns.info/iphistory/?domain=${q}`,
          conclusion: `Historical IP shifts: ${facts && facts.past_ips.length > 0 ? 'yes' : 'none'}`,
        },
        {
          name: 'Mnemonic PassiveDNS',
          tag: 'OFFLINE FIXTURE',
          link: `https://passivedns.mnemonic.no/search?query=${q}`,
          conclusion: `Passive DNS: ${resolves ? 'observed' : 'not observed'}`,
        },
        {
          name: 'MXToolbox',
          tag: 'OFFLINE FIXTURE',
          link: `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${q}`,
          conclusion: `MX: ${facts && facts.mx_records.length > 0 ? facts.mx_records[0] : 'none'}`,
        },
      ],
    },
    {
      category: 'Malicious Reputation & Web Analysis',
      relevance: finding.score >= 60 ? 'Very high' : 'High',
      sources: [
        {
          name: 'VirusTotal',
          tag: 'OFFLINE FIXTURE',
          link: `https://www.virustotal.com/gui/domain/${q}`,
          conclusion: phishingEvidence,
        },
        {
          name: 'URLScan.io',
          tag: 'OFFLINE FIXTURE',
          link: `https://urlscan.io/domain/${q}`,
          conclusion: `Login form / logo: ${hasLogin || hasLogo ? 'impersonation indicators present' : 'none'}`,
        },
        {
          name: 'URLhaus',
          tag: 'OFFLINE FIXTURE',
          link: `https://urlhaus.abuse.ch/browse.php?search=${q}`,
          conclusion: malwareEvidence,
        },
        {
          name: 'PhishTank',
          tag: 'OFFLINE FIXTURE',
          link: `https://phishtank.org/search.php?q=${q}`,
          conclusion: 'Campaign relationships: none observed',
        },
        {
          name: 'OpenPhish',
          tag: 'OFFLINE FIXTURE',
          link: 'https://openphish.com/phishing_feeds.html',
          conclusion: `Redirects: ${redirects}`,
        },
        {
          name: 'AlienVault OTX',
          tag: 'OFFLINE FIXTURE',
          link: `https://otx.alienvault.com/indicator/domain/${q}`,
          conclusion: 'Community pulses: none in fixture',
        },
      ],
    },
    {
      category: 'Hosting, IP & Certificate',
      relevance: 'High',
      sources: [
        {
          name: 'Shodan',
          tag: 'OFFLINE FIXTURE',
          link: ip ? `https://www.shodan.io/host/${encodeURIComponent(ip)}` : '#',
          conclusion: `IP: ${ip || 'N/A'}`,
        },
        {
          name: 'Censys',
          tag: 'OFFLINE FIXTURE',
          link: `https://search.censys.io/search?resource=hosts&q=${q}`,
          conclusion: `ASN: ${asn || 'N/A'} (${facts?.asn_org || 'N/A'})`,
        },
        {
          name: 'Netlas',
          tag: 'OFFLINE FIXTURE',
          link: `https://app.netlas.io/responses/?q=domain%3A%22${q}%22`,
          conclusion: `Infra role: ${facts?.infra_role || 'N/A'}`,
        },
        {
          name: 'Robtex',
          tag: 'OFFLINE FIXTURE',
          link: `https://www.robtex.com/dns-lookup/${q}`,
          conclusion: `Shared hosting/CDN caveat: ${sharedInfra ? 'yes — co-location is not common ownership' : 'not indicated'}`,
        },
        {
          name: 'crt.sh',
          tag: 'OFFLINE FIXTURE',
          link: `https://crt.sh/?q=${q}`,
          conclusion: `HTTPS cert: ${https ? facts?.tls_issuer : 'none observed'}`,
        },
      ],
    },
  ];

  const conclusions = {
    registered: registered ? 'Registered' : 'Unregistered / no record',
    resolves: resolves ? 'Resolves' : 'Unresolved',
    recently_registered: recent ? 'Yes (< 90d)' : 'No / unknown',
    https_observed: https ? `Yes — ${facts?.tls_issuer ?? ''}` : 'No',
    phishing_evidence: phishingEvidence,
    malware_evidence: malwareEvidence,
    brand_impersonation: `Yes — similarity ${finding.similarity_pct}%, technique ${titleCase(finding.candidate.technique)}`,
    login_form_observed: hasLogin ? 'Yes (fixture model)' : 'No',
    similar_logo_observed: hasLogo ? 'Yes (fixture model)' : 'No',
    shared_infrastructure: sharedInfra
      ? `Likely — ${facts?.infra_role} (shared-hosting/CDN caveat applies)`
      : 'Not indicated',
    suspicious_redirects: redirects,
  };

  return { sections, conclusions };
}

export function buildGeoData(findings: Finding[]): GeoPoint[] {
  const agg = new Map<
    string,
    {
      code: string;
      name: string;
      coords: [number, number];
      count: number;
      threats: number;
      asns: Set<string>;
      domains: string[];
    }
  >();

  for (const f of findings) {
    const facts = f.facts;
    if (!facts || !facts.country || !(facts.country in COUNTRY_INFO)) continue;
    const code = facts.country;
    const [name, lat, lon] = COUNTRY_INFO[code];
    let g = agg.get(code);
    if (!g) {
      g = {
        code,
        name,
        coords: [(lon + 180.0) / 360.0, (90.0 - lat) / 180.0],
        count: 0,
        threats: 0,
        asns: new Set<string>(),
        domains: [],
      };
      agg.set(code, g);
    }
    g.count += 1;
    if (facts.is_live) g.threats += 1;
    if (facts.asn) g.asns.add(facts.asn);
    g.domains.push(f.candidate.domain);
  }

  return Array.from(agg.values())
    .map((g) => ({
      code: g.code,
      name: g.name,
      coords: g.coords,
      count: g.count,
      threats: g.threats,
      asns: Array.from(g.asns).sort().slice(0, 6),
      domains: [...g.domains].sort().slice(0, 12),
    }))
    .sort((a, b) => b.count - a.count || a.code.localeCompare(b.code));
}

export function buildCampaignClusters(findings: Finding[]): CampaignCluster[] {
  const byIp = new Map<string, Finding[]>();
  for (const f of findings) {
    if (!f.facts || f.facts.a_records.length === 0) continue;
    const ip = f.facts.a_records[0];
    const list = byIp.get(ip) ?? [];
    list.push(f);
    byIp.set(ip, list);
  }

  const clusters: CampaignCluster[] = [];
  for (const [ip, members] of byIp.entries()) {
    if (members.length < 2) continue;
    const sample = members[0].facts!;
    const threats = members.filter((m) => m.facts?.is_live).length;
    clusters.push({
      ip,
      asn: sample.asn || 'N/A',
      org: sample.asn_org || 'N/A',
      country: sample.country || 'N/A',
      role: sample.infra_role || 'N/A',
      members: [...members]
        .sort((a, b) => b.score - a.score)
        .map((m) => ({ domain: m.candidate.domain, tier: m.tier, score: m.score })),
      threats,
      confidence: Math.min(97, 55 + 12 * members.length + 4 * threats),
      caveat:
        'Shared hosting/CDN caveat: co-location does not prove common ownership. Corroborate with registrar, certificate, and timing data.',
    });
  }

  if (clusters.length === 0) {
    const byAsn = new Map<string, Finding[]>();
    for (const f of findings) {
      if (f.facts?.asn) {
        const list = byAsn.get(f.facts.asn) ?? [];
        list.push(f);
        byAsn.set(f.facts.asn, list);
      }
    }
    for (const [asn, members] of byAsn.entries()) {
      if (members.length < 3) continue;
      const sample = members[0].facts;
      const threats = members.filter((m) => m.facts?.is_live).length;
      clusters.push({
        ip: sample?.a_records[0] ?? 'N/A',
        asn,
        org: sample?.asn_org || 'N/A',
        country: sample?.country || 'N/A',
        role: sample?.infra_role || 'N/A',
        members: [...members]
          .sort((a, b) => b.score - a.score)
          .map((m) => ({ domain: m.candidate.domain, tier: m.tier, score: m.score })),
        threats,
        confidence: Math.min(88, 40 + 8 * members.length),
        caveat:
          'ASN-level grouping is weaker than IP-level grouping. Large providers host unrelated tenants.',
      });
    }
  }

  return clusters.sort(
    (a, b) => b.members.length - a.members.length || a.ip.localeCompare(b.ip)
  );
}

export function calculateAggregateImpact(findings: Finding[]): ImpactSummary {
  const total = findings.length;
  const live = findings.filter((f) => f.facts?.is_live).length;
  const critical = findings.filter((f) => f.tier === 'CRITICAL').length;
  const triageHours = Math.round((total * 0.35 + live * 1.5 + critical * 2.0) * 10) / 10;
  const low = 8_000 + live * 4_500 + critical * 6_000;
  const high = low * 3 + 25_000;

  return {
    harm_category: 'Credential phishing & brand impersonation',
    triage_hours: triageHours,
    exposure_low: `$${low.toLocaleString('en-US')}`,
    exposure_high: `$${high.toLocaleString('en-US')}`,
    defensive_cost: `$${Math.floor(low / 3).toLocaleString('en-US')}`,
    note: 'Modeled business impact derived from candidate volume, liveness, and tier distribution. Not a verified financial loss figure.',
  };
}
