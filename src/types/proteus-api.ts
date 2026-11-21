export type Tier = 'CRITICAL' | 'HIGH' | 'WATCH' | 'LOW';
export type FindingStatus = 'LIVE INFRA' | 'PRECRIME' | 'DRIFT DETECTED' | 'UNRESOLVED' | 'SAFE';

export interface CandidateDto {
  domain: string;
  ascii_form: string;
  registrable: string;
  family: string;
  rule: string;
  technique: string;
  importance: string;
  weight: number;
  provenance: Record<string, string>;
}

export interface SignalDto {
  key: string;
  label: string;
  points: number;
  evidence: string;
}

export interface DnsFactsDto {
  a_records: string[];
  aaaa_records: string[];
  mx_records: string[];
  ns_records: string[];
  spf: string | null;
  dmarc: string | null;
  created_days_ago: number | null;
  registrar: string | null;
  asn: string | null;
  asn_org: string | null;
  country: string | null;
  region: string | null;
  netblock: string | null;
  infra_role: string | null;
  rdns: string | null;
  abuse_contact: string | null;
  past_ips: Array<{ ip: string; seen: string }>;
  tls_issuer: string | null;
  tls_subject: string | null;
  tls_sans: string[];
  tls_not_before: string | null;
  tls_not_after: string | null;
  tls_fingerprint: string | null;
  source: string;
  is_live: boolean;
  is_mail_enabled: boolean;
}

export interface LookupResultDto<T = unknown> {
  status: 'found' | 'no_records' | 'lookup_failed' | 'source_unavailable' | 'not_collected';
  source?: string;
  checked_at?: string;
  detail?: string;
  retry_after_seconds?: number | null;
  data?: T | null;
}

export interface DomainEnrichmentDto {
  domain: string;
  registrable: string;
  collection_note?: string;
  rdap: LookupResultDto<{
    registrar?: string;
    registration_date?: string;
    expiration_date?: string;
    domain_statuses?: string[];
    nameservers?: string[];
  }>;
  dns: Record<string, LookupResultDto<string[]>>;
  certificates: LookupResultDto<
    Array<{
      names: string[];
      issuer: string;
      logged_at: string;
      not_before: string;
      not_after: string;
    }>
  >;
  reputation: LookupResultDto<{
    malicious?: number;
    suspicious?: number;
    harmless?: number;
    undetected?: number;
    matched_url_count?: number;
    last_analysis_at?: string;
  }>;
  infrastructure: Array<{
    address: string;
    registration: LookupResultDto<{
      name?: string;
      handle?: string;
      start_address?: string;
      end_address?: string;
      country_code?: string;
    }>;
    ptr: LookupResultDto<string[]>;
  }>;
}

export interface OsintNewsItem {
  source: string;
  type: string;
  sentiment: string;
  kind: string;
  title: string;
  summary: string;
  date: string;
  link: string;
}

export interface OsintLinkItem {
  source: string;
  url: string;
  desc: string;
}

export interface OsintMatrixSection {
  category: string;
  relevance: string;
  sources: Array<{
    name: string;
    tag: string;
    link: string;
    conclusion: string;
  }>;
}

export interface FindingDto {
  brand: string;
  domain: string;
  candidate: CandidateDto;
  facts: DnsFactsDto | null;
  signals: SignalDto[];
  tier: Tier;
  score: number;
  similarity_pct: number;
  mutation_type: string;
  status: FindingStatus;
  osint: {
    intel?: OsintNewsItem[];
    links?: Record<string, OsintLinkItem[]>;
    live_enrich_requested?: boolean;
    source?: string;
  };
  osint_matrix: {
    sections?: OsintMatrixSection[];
    conclusions?: Record<string, string>;
  };
  timeline: Array<{ time: string; kind: string; event: string }>;
  dna: {
    similarity_pct: number;
    logo_match: boolean;
    login_form: boolean;
    visual_match: boolean;
    matched_phrases: string[];
    scan_pass: number;
  } | null;
  precrime: number | null;
  drift: boolean;
  drift_data: {
    before: string;
    after: string;
    first_seen: string;
    observed_at: string;
  } | null;
  enrichment?: DomainEnrichmentDto | null;
}

export interface GeoPointDto {
  code: string;
  name: string;
  coords: [number, number];
  count: number;
  threats: number;
  asns: string[];
  domains: string[];
}

export interface ClusterDto {
  ip: string;
  asn: string;
  org: string;
  country: string;
  role: string;
  members: Array<{ domain: string; tier: Tier; score: number }>;
  threats: number;
  confidence: number;
  caveat: string;
}

export interface ScanResultsDto {
  scan_id: string;
  brand: string;
  scan_pass: 1 | 2;
  online_enrich: boolean;
  inspect_websites: boolean;
  generated: number;
  tiers: Record<Tier, number>;
  impact: {
    harm_category: string;
    triage_hours: number;
    exposure_low: string;
    exposure_high: string;
    defensive_cost: string;
    note: string;
  };
  findings: FindingDto[];
  geo: GeoPointDto[];
  clusters: ClusterDto[];
  completed_at: string;
}

export interface ScanProgressDto {
  scan_id: string;
  status: 'pending' | 'running' | 'complete' | 'failed';
  progress_pct: number;
  current_step: string;
  domains_total: number;
  domains_processed: number;
  findings_so_far: number;
  error?: string | null;
}
