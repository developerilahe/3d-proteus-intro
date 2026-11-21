import { createHash } from 'node:crypto';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fromAscii, isValidDomainInput, registrableDomain, toAscii } from './normalize.ts';
import type {
  CertEntry,
  DnsFacts,
  DomainEnrichment,
  IpInfrastructure,
  IpNetworkData,
  LookupResult,
  RdapRegistrationData,
  ReputationData,
} from './types.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const COUNTRY_INFO: Record<string, [string, number, number]> = {
  US: ['United States', 39.8, -98.6],
  NL: ['Netherlands', 52.1, 5.3],
  RO: ['Romania', 45.9, 24.97],
  RU: ['Russia', 61.5, 105.3],
  CN: ['China', 35.9, 104.2],
  DE: ['Germany', 51.2, 10.4],
  GB: ['United Kingdom', 55.4, -3.4],
  FR: ['France', 46.2, 2.2],
  SG: ['Singapore', 1.35, 103.8],
  BR: ['Brazil', -14.2, -51.9],
  IN: ['India', 20.6, 78.9],
  TR: ['Turkey', 38.96, 35.24],
  UA: ['Ukraine', 48.4, 31.2],
  PA: ['Panama', 8.5, -80.8],
  SC: ['Seychelles', -4.7, 55.5],
  HK: ['Hong Kong', 22.3, 114.2],
  BG: ['Bulgaria', 42.7, 25.5],
  LT: ['Lithuania', 55.2, 23.9],
  SE: ['Sweden', 60.1, 18.6],
};

const ORG_POOL = [
  'HostSlick B.V.', 'M247 Europe SRL', 'Cloudflare, Inc.', 'DigitalOcean, LLC',
  'OVH SAS', 'Hetzner Online GmbH', 'Amazon.com, Inc.', 'Namecheap, Inc.',
  'Contabo GmbH', 'Frantech Solutions', 'Stark Industries Networks',
];

const ROLE_POOL = [
  'Shared Hosting', 'Bulletproof/High-Risk Hosting', 'CDN',
  'VPS Provider', 'Cloud Hosting', 'Parked/Proxy',
];

const COUNTRY_CODES = Object.keys(COUNTRY_INFO);

const ISSUERS = [
  "Let's Encrypt", 'DigiCert', 'Sectigo', 'ZeroSSL', 'Google Trust Services',
];

function deterministicHash(value: string, mod: number): number {
  const hex = createHash('sha256').update(value, 'utf8').digest('hex').slice(0, 12);
  return Number(BigInt('0x' + hex) % BigInt(mod));
}

function netblockOf(ip: string): string {
  const parts = ip.split('.');
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.0.0/16`;
  }
  return 'N/A';
}

function fingerprintOf(seed: string): string {
  const digest = createHash('sha256').update(seed, 'utf8').digest('hex').slice(0, 32).toUpperCase();
  const pairs: string[] = [];
  for (let i = 0; i < digest.length; i += 2) {
    pairs.push(digest.slice(i, i + 2));
  }
  return pairs.join(':');
}

function isPublicRoutableIp(ip: string): boolean {
  const version = net.isIP(ip);
  if (version === 4) {
    const octets = ip.split('.').map((o) => Number.parseInt(o, 10));
    if (octets.length !== 4 || octets.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
      return false;
    }
    const [a, b] = octets;
    if (a === 0 || a === 10 || a === 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a >= 224) return false;
    return true;
  }
  if (version === 6) {
    const low = ip.toLowerCase();
    if (low === '::' || low === '::1') return false;
    if (low.startsWith('fe80:') || low.startsWith('fc') || low.startsWith('fd')) return false;
    if (low.startsWith('::ffff:')) {
      return isPublicRoutableIp(low.slice(7));
    }
    return true;
  }
  return false;
}

interface RawFixtureEntry {
  a_records?: string[];
  aaaa_records?: string[];
  mx_records?: string[];
  ns_records?: string[];
  spf?: string | null;
  dmarc?: string | null;
  created_days_ago?: number | null;
  registrar?: string | null;
  asn?: string | null;
  asn_org?: string | null;
  country?: string | null;
  region?: string | null;
  netblock?: string | null;
  infra_role?: string | null;
  rdns?: string | null;
  abuse_contact?: string | null;
  past_ips?: Array<[string, string]>;
  tls_issuer?: string | null;
  tls_subject?: string | null;
  tls_sans?: string[];
  tls_not_before?: string | null;
  tls_not_after?: string | null;
  tls_fingerprint?: string | null;
}

export function enrichFixtureRecord(registrable: string, data: RawFixtureEntry): DnsFacts {
  const now = new Date();
  const seed = registrable.toLowerCase();
  const h = deterministicHash(seed, 1_000_003);

  const aRecords = [...(data.a_records ?? [])];
  const aaaaRecords = [...(data.aaaa_records ?? [])];
  const mxRecords = [...(data.mx_records ?? [])];
  const nsRecords = [...(data.ns_records ?? [])];

  let ip: string | null = aRecords[0] ?? null;
  if (!ip && (mxRecords.length > 0 || aaaaRecords.length > 0)) {
    ip = `185.${h % 250}.${Math.floor(h / 250) % 250}.${Math.floor(h / 62_500) % 250}`;
    aRecords.push(ip);
  }

  let created = data.created_days_ago ?? null;
  if (created === null && (ip || mxRecords.length > 0)) {
    created = 30 + (h % 900);
  }

  const asn = data.asn || `AS${1000 + (h % 39000)}`;
  const org = data.asn_org || ORG_POOL[h % ORG_POOL.length];
  let country = data.country ?? null;
  if (!country || !(country in COUNTRY_INFO)) {
    country = COUNTRY_CODES[h % COUNTRY_CODES.length];
  }
  const role = data.infra_role || ROLE_POOL[h % ROLE_POOL.length];
  const slug = org.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 14);
  const rdns = data.rdns || (ip ? `host-${h % 9999}.${slug}.net` : 'N/A');
  const abuse = data.abuse_contact || `abuse@${slug}.example`;

  let notBefore = 'N/A';
  let notAfter = 'N/A';
  if (ip || mxRecords.length > 0) {
    const age = Math.min(created ?? 90, 90);
    const nb = new Date(now.getTime() - age * 86_400_000);
    const na = new Date(nb.getTime() + 90 * 86_400_000);
    notBefore = nb.toISOString();
    notAfter = na.toISOString();
  }

  const pastIps = (data.past_ips ?? []).map(([pip, seen]) => ({ ip: pip, seen }));
  if (pastIps.length === 0 && created && h % 3 === 0) {
    const count = 1 + (h % 2);
    for (let i = 0; i < count; i++) {
      const oldIp = `45.${h % 200}.${(Math.floor(h / 3) + i) % 250}.${(Math.floor(h / 7) + i) % 250}`;
      const seenDays = Math.floor((created * (i + 1)) / 4);
      const seen = new Date(now.getTime() - seenDays * 86_400_000).toISOString();
      pastIps.push({ ip: oldIp, seen });
    }
  }

  const isLive = aRecords.length > 0 || aaaaRecords.length > 0 || mxRecords.length > 0;
  return {
    a_records: aRecords,
    aaaa_records: aaaaRecords,
    mx_records: mxRecords,
    ns_records: nsRecords,
    spf: data.spf ?? null,
    dmarc: data.dmarc ?? null,
    created_days_ago: created,
    registrar: data.registrar || 'N/A',
    asn,
    asn_org: org,
    country,
    region: data.region || country,
    netblock: data.netblock || (ip ? netblockOf(ip) : 'N/A'),
    infra_role: role,
    rdns,
    abuse_contact: abuse,
    past_ips: pastIps,
    tls_issuer: data.tls_issuer || ISSUERS[h % ISSUERS.length],
    tls_subject: data.tls_subject || registrable,
    tls_sans: data.tls_sans ?? [registrable, `www.${registrable}`],
    tls_not_before: data.tls_not_before || notBefore,
    tls_not_after: data.tls_not_after || notAfter,
    tls_fingerprint: data.tls_fingerprint || fingerprintOf(seed),
    source: 'OFFLINE FIXTURE',
    is_live: isLive,
    is_mail_enabled: mxRecords.length > 0,
  };
}

export class FixtureResolver {
  private data = new Map<string, RawFixtureEntry>();

  constructor(fixturePath?: string) {
    const resolved =
      fixturePath ?? path.resolve(__dirname, '../data/dns_fixture.json');
    if (fs.existsSync(resolved)) {
      const raw = JSON.parse(fs.readFileSync(resolved, 'utf-8')) as {
        domains?: Record<string, RawFixtureEntry>;
      } & Record<string, RawFixtureEntry>;
      const entries = raw.domains && typeof raw.domains === 'object' ? raw.domains : raw;
      for (const [k, v] of Object.entries(entries)) {
        this.data.set(k.toLowerCase(), v);
      }
    }
  }

  private keys(registrable: string): string[] {
    const out = [registrable.toLowerCase()];
    const a = toAscii(registrable).toLowerCase();
    if (a && !out.includes(a)) out.push(a);
    const d = fromAscii(registrable).toLowerCase();
    if (d && !out.includes(d)) out.push(d);
    return out;
  }

  lookup(registrable: string): DnsFacts | null {
    for (const key of this.keys(registrable)) {
      const entry = this.data.get(key);
      if (entry) return enrichFixtureRecord(key, entry);
    }
    return null;
  }

  hasMatch(registrable: string): boolean {
    return this.keys(registrable).some((k) => this.data.has(k));
  }
}

function emptyEnrichment(
  domain: string,
  registrable: string,
  note: string
): DomainEnrichment {
  const notCollected: LookupResult<never> = {
    status: 'not_collected',
    detail: note,
  };
  return {
    domain,
    registrable,
    collection_note: note,
    rdap: notCollected,
    dns: {
      a: notCollected,
      aaaa: notCollected,
      mx: notCollected,
      ns: notCollected,
      spf: notCollected,
      dmarc: notCollected,
    },
    certificates: notCollected,
    reputation: notCollected,
    infrastructure: [],
  };
}

async function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return await Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(`Timeout after ${ms}ms`)), ms)
    ),
  ]);
}

async function fetchJsonSafe<T>(url: string, headers: Record<string, string> = {}, timeoutMs = 3500): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      headers: { Accept: 'application/json', 'User-Agent': 'PROTEUS-ThreatIntel/1.0', ...headers },
      signal: controller.signal,
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    return (await res.json()) as T;
  } finally {
    clearTimeout(timer);
  }
}

async function lookupDnsLive(hostname: string): Promise<DomainEnrichment['dns']> {
  const checkedAt = new Date().toISOString();
  const wrap = async <T>(
    fn: () => Promise<T[]>,
    source = 'Node DNS Resolver'
  ): Promise<LookupResult<T[]>> => {
    try {
      const records = await withTimeout(fn(), 2000);
      if (!records || records.length === 0) {
        return { status: 'no_records', source, checked_at: checkedAt, data: [] };
      }
      return { status: 'found', source, checked_at: checkedAt, data: records };
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if (code === 'ENODATA' || code === 'ENOTFOUND' || code === 'NXDOMAIN') {
        return { status: 'no_records', source, checked_at: checkedAt, data: [] };
      }
      return {
        status: 'lookup_failed',
        source,
        checked_at: checkedAt,
        detail: err instanceof Error ? err.message : 'DNS lookup error',
      };
    }
  };

  const [a, aaaa, mx, ns, txt, dmarcTxt] = await Promise.all([
    wrap(() => dns.resolve4(hostname)),
    wrap(() => dns.resolve6(hostname)),
    wrap(async () => {
      const recs = await dns.resolveMx(hostname);
      return recs.map((r) => `${r.priority} ${r.exchange}`);
    }),
    wrap(() => dns.resolveNs(hostname)),
    wrap(async () => {
      const recs = await dns.resolveTxt(hostname);
      return recs.map((r) => r.join('')).filter((t) => t.toLowerCase().startsWith('v=spf1'));
    }),
    wrap(async () => {
      const recs = await dns.resolveTxt(`_dmarc.${hostname}`);
      return recs.map((r) => r.join('')).filter((t) => t.toLowerCase().startsWith('v=dmarc1'));
    }),
  ]);

  return { a, aaaa, mx, ns, spf: txt, dmarc: dmarcTxt };
}

async function lookupRdapLive(registrable: string): Promise<LookupResult<RdapRegistrationData>> {
  const checkedAt = new Date().toISOString();
  try {
    const json = await fetchJsonSafe<{
      events?: Array<{ eventAction?: string; eventDate?: string }>;
      status?: string[];
      nameservers?: Array<{ ldhName?: string }>;
      entities?: Array<{ roles?: string[]; vcardArray?: unknown[] }>;
    }>(`https://rdap.org/domain/${encodeURIComponent(registrable)}`);

    const regEvent = json.events?.find((e) => e.eventAction === 'registration');
    const expEvent = json.events?.find((e) => e.eventAction === 'expiration');
    const registrarEnt = json.entities?.find((e) => e.roles?.includes('registrar'));
    let registrarName: string | undefined;
    if (registrarEnt && Array.isArray(registrarEnt.vcardArray) && Array.isArray(registrarEnt.vcardArray[1])) {
      const fnEntry = (registrarEnt.vcardArray[1] as Array<unknown>).find(
        (row): row is [string, unknown, unknown, string] =>
          Array.isArray(row) && row[0] === 'fn'
      );
      if (fnEntry && typeof fnEntry[3] === 'string') {
        registrarName = fnEntry[3];
      }
    }

    return {
      status: 'found',
      source: 'rdap.org',
      checked_at: checkedAt,
      data: {
        registrar: registrarName,
        registration_date: regEvent?.eventDate,
        expiration_date: expEvent?.eventDate,
        domain_statuses: json.status,
        nameservers: json.nameservers?.map((n) => n.ldhName).filter((x): x is string => Boolean(x)),
      },
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'RDAP failed';
    return {
      status: msg.includes('404') ? 'no_records' : 'lookup_failed',
      source: 'rdap.org',
      checked_at: checkedAt,
      detail: msg,
    };
  }
}

async function lookupCertificatesLive(hostname: string): Promise<LookupResult<CertEntry[]>> {
  const checkedAt = new Date().toISOString();
  try {
    const rows = await fetchJsonSafe<
      Array<{
        name_value?: string;
        issuer_name?: string;
        entry_timestamp?: string;
        not_before?: string;
        not_after?: string;
      }>
    >(`https://crt.sh/?q=${encodeURIComponent(hostname)}&output=json`, {}, 3500);
    if (!Array.isArray(rows) || rows.length === 0) {
      return { status: 'no_records', source: 'crt.sh', checked_at: checkedAt, data: [] };
    }
    const entries: CertEntry[] = rows.slice(0, 10).map((r) => ({
      names: (r.name_value || hostname).split('\n').filter(Boolean),
      issuer: r.issuer_name || 'Unknown',
      logged_at: r.entry_timestamp || '',
      not_before: r.not_before || '',
      not_after: r.not_after || '',
    }));
    return { status: 'found', source: 'crt.sh', checked_at: checkedAt, data: entries };
  } catch (err) {
    return {
      status: 'lookup_failed',
      source: 'crt.sh',
      checked_at: checkedAt,
      detail: err instanceof Error ? err.message : 'CT lookup error',
    };
  }
}

async function lookupReputationLive(hostname: string): Promise<LookupResult<ReputationData>> {
  const checkedAt = new Date().toISOString();
  const vtKey = process.env.VIRUSTOTAL_API_KEY;
  if (!vtKey) {
    return {
      status: 'not_collected',
      source: 'Skipped',
      checked_at: checkedAt,
      detail: 'VirusTotal feed skipped (DNS, RDAP & Certificate Transparency active)',
    };
  }
  try {
    const json = await fetchJsonSafe<{
      data?: {
        attributes?: {
          last_analysis_stats?: Record<string, number>;
          last_analysis_date?: number;
        };
      };
    }>(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(hostname)}`, {
      'x-apikey': vtKey,
    });
    const stats = json.data?.attributes?.last_analysis_stats ?? {};
    const dateEpoch = json.data?.attributes?.last_analysis_date;
    return {
      status: 'found',
      source: 'VirusTotal API v3',
      checked_at: checkedAt,
      data: {
        malicious: stats.malicious ?? 0,
        suspicious: stats.suspicious ?? 0,
        harmless: stats.harmless ?? 0,
        undetected: stats.undetected ?? 0,
        last_analysis_at: dateEpoch ? new Date(dateEpoch * 1000).toISOString() : undefined,
      },
    };
  } catch (err) {
    return {
      status: 'lookup_failed',
      source: 'VirusTotal API v3',
      checked_at: checkedAt,
      detail: err instanceof Error ? err.message : 'Reputation lookup error',
    };
  }
}

async function lookupIpLive(ip: string): Promise<IpInfrastructure> {
  const checkedAt = new Date().toISOString();
  if (!isPublicRoutableIp(ip)) {
    const blocked: LookupResult<never> = {
      status: 'lookup_failed',
      source: 'SSRF Guard',
      checked_at: checkedAt,
      detail: 'Non-public IP address skipped',
    };
    return { address: ip, registration: blocked, ptr: blocked };
  }

  const [registration, ptr] = await Promise.all([
    (async (): Promise<LookupResult<IpNetworkData>> => {
      try {
        const json = await fetchJsonSafe<{
          name?: string;
          handle?: string;
          startAddress?: string;
          endAddress?: string;
          country?: string;
        }>(`https://rdap.org/ip/${encodeURIComponent(ip)}`);
        return {
          status: 'found',
          source: 'rdap.org/ip',
          checked_at: checkedAt,
          data: {
            name: json.name,
            handle: json.handle,
            start_address: json.startAddress,
            end_address: json.endAddress,
            country_code: json.country,
          },
        };
      } catch (err) {
        return {
          status: 'lookup_failed',
          source: 'rdap.org/ip',
          checked_at: checkedAt,
          detail: err instanceof Error ? err.message : 'IP RDAP failed',
        };
      }
    })(),
    (async (): Promise<LookupResult<string[]>> => {
      try {
        const names = await withTimeout(dns.reverse(ip), 2000);
        return names.length
          ? { status: 'found', source: 'PTR DNS', checked_at: checkedAt, data: names }
          : { status: 'no_records', source: 'PTR DNS', checked_at: checkedAt, data: [] };
      } catch {
        return { status: 'no_records', source: 'PTR DNS', checked_at: checkedAt, data: [] };
      }
    })(),
  ]);

  return { address: ip, registration, ptr };
}

function liveFactsFromEnrichment(enrichment: DomainEnrichment): DnsFacts | null {
  const d = enrichment.dns;
  const reg = enrichment.rdap.data;
  let age: number | null = null;
  if (reg?.registration_date) {
    const parsed = Date.parse(reg.registration_date);
    if (!Number.isNaN(parsed)) {
      const diff = Math.floor((Date.now() - parsed) / 86_400_000);
      if (diff >= 0) age = diff;
    }
  }
  const aRecords = d.a.data ?? [];
  const aaaaRecords = d.aaaa.data ?? [];
  const mxRecords = (d.mx.data ?? []).filter((r) => r.trim() !== '0 .');
  const nsRecords = d.ns.data ?? [];
  const spf = d.spf.data?.[0] ?? null;
  const dmarc = d.dmarc.data?.[0] ?? null;
  const firstIp = enrichment.infrastructure[0];
  const firstCert = enrichment.certificates.data?.[0];

  const isLive = aRecords.length > 0 || aaaaRecords.length > 0 || mxRecords.length > 0;
  if (!reg && !isLive && nsRecords.length === 0 && !spf && !dmarc) {
    return null;
  }

  return {
    a_records: aRecords,
    aaaa_records: aaaaRecords,
    mx_records: mxRecords,
    ns_records: nsRecords,
    spf,
    dmarc,
    created_days_ago: age,
    registrar: reg?.registrar ?? null,
    asn: null,
    asn_org: firstIp?.registration.data?.name ?? null,
    country: firstIp?.registration.data?.country_code ?? null,
    region: firstIp?.registration.data?.country_code ?? null,
    netblock:
      firstIp?.registration.data?.start_address && firstIp?.registration.data?.end_address
        ? `${firstIp.registration.data.start_address} - ${firstIp.registration.data.end_address}`
        : null,
    infra_role: null,
    rdns: firstIp?.ptr.data?.[0] ?? null,
    abuse_contact: null,
    past_ips: [],
    tls_issuer: firstCert?.issuer ?? null,
    tls_subject: enrichment.domain,
    tls_sans: firstCert?.names ?? [],
    tls_not_before: firstCert?.not_before ?? null,
    tls_not_after: firstCert?.not_after ?? null,
    tls_fingerprint: null,
    source: 'LIVE PUBLIC',
    is_live: isLive,
    is_mail_enabled: mxRecords.length > 0,
  };
}

export class DynamicResolver {
  static readonly LIVE_CAP = 8;
  static readonly IP_CAP = 4;

  private readonly online: boolean;
  private readonly fixture: FixtureResolver | null;
  private readonly cache = new Map<string, DomainEnrichment>();
  private liveAttempts = 0;

  constructor(online = false, fixturePath?: string) {
    this.online = Boolean(online);
    this.fixture = this.online ? null : new FixtureResolver(fixturePath);
  }

  async resolve(
    domain: string,
    registrable?: string
  ): Promise<{ facts: DnsFacts | null; enrichment: DomainEnrichment }> {
    const reg = registrable || registrableDomain(domain);
    const asciiDomain = toAscii(domain);
    const asciiReg = toAscii(reg);

    if (!this.online) {
      const enrichment = emptyEnrichment(asciiDomain, asciiReg, 'Live enrichment disabled');
      const facts = this.fixture ? this.fixture.lookup(reg) : null;
      return { facts, enrichment };
    }

    if (!isValidDomainInput(asciiDomain) || !isValidDomainInput(asciiReg)) {
      const enrichment = emptyEnrichment(asciiDomain, asciiReg, 'Invalid hostname');
      return { facts: null, enrichment };
    }

    const cached = this.cache.get(asciiDomain);
    if (cached) {
      return { facts: liveFactsFromEnrichment(cached), enrichment: cached };
    }

    if (this.liveAttempts >= DynamicResolver.LIVE_CAP) {
      const enrichment = emptyEnrichment(
        asciiDomain,
        asciiReg,
        'Scan lookup budget reached'
      );
      return { facts: null, enrichment };
    }

    this.liveAttempts += 1;
    const [dnsRes, rdapRes, repRes, certRes] = await Promise.all([
      lookupDnsLive(asciiDomain),
      lookupRdapLive(asciiReg),
      lookupReputationLive(asciiDomain),
      lookupCertificatesLive(asciiDomain),
    ]);

    const ips = Array.from(
      new Set([...(dnsRes.a.data ?? []), ...(dnsRes.aaaa.data ?? [])])
    );

    const skipped: LookupResult<never> = {
      status: 'not_collected',
      detail: 'IP lookup budget reached',
    };

    const infra = await Promise.all(
      ips.map((ip, idx) =>
        idx < DynamicResolver.IP_CAP
          ? lookupIpLive(ip)
          : Promise.resolve<IpInfrastructure>({
              address: ip,
              registration: skipped,
              ptr: skipped,
            })
      )
    );

    const enrichment: DomainEnrichment = {
      domain: asciiDomain,
      registrable: asciiReg,
      rdap: rdapRes,
      dns: dnsRes,
      certificates: certRes,
      reputation: repRes,
      infrastructure: infra,
    };

    this.cache.set(asciiDomain, enrichment);
    return { facts: liveFactsFromEnrichment(enrichment), enrichment };
  }
}
