export type Tier = 'CRITICAL' | 'HIGH' | 'WATCH' | 'LOW';

export type FindingStatus =
  | 'LIVE INFRA'
  | 'PRECRIME'
  | 'DRIFT DETECTED'
  | 'UNRESOLVED';

export type ScanState = 'pending' | 'running' | 'complete' | 'failed';

export type LookupStatus =
  | 'found'
  | 'no_records'
  | 'lookup_failed'
  | 'source_unavailable'
  | 'not_collected';

export const TIER_ORDER: Record<Tier, number> = {
  CRITICAL: 0,
  HIGH: 1,
  WATCH: 2,
  LOW: 3,
};

export interface Candidate {
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

export interface Signal {
  key: string;
  label: string;
  points: number;
  evidence: string;
}

export interface PastIp {
  ip: string;
  seen: string;
}

export interface DnsFacts {
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
  past_ips: PastIp[];
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

export interface LookupResult<T = unknown> {
  status: LookupStatus;
  source?: string;
  checked_at?: string;
  detail?: string;
  retry_after_seconds?: number | null;
  data?: T | null;
}

export interface RdapRegistrationData {
  registrar?: string;
  registration_date?: string;
  expiration_date?: string;
  domain_statuses?: string[];
  nameservers?: string[];
}

export interface CertEntry {
  names: string[];
  issuer: string;
  logged_at: string;
  not_before: string;
  not_after: string;
}

export interface IpNetworkData {
  name?: string;
  handle?: string;
  start_address?: string;
  end_address?: string;
  country_code?: string;
}

export interface IpInfrastructure {
  address: string;
  registration: LookupResult<IpNetworkData>;
  ptr: LookupResult<string[]>;
}

export interface ReputationData {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  matched_url_count?: number;
  last_analysis_at?: string;
}

export interface DomainEnrichment {
  domain: string;
  registrable: string;
  collection_note?: string;
  rdap: LookupResult<RdapRegistrationData>;
  dns: {
    a: LookupResult<string[]>;
    aaaa: LookupResult<string[]>;
    mx: LookupResult<string[]>;
    ns: LookupResult<string[]>;
    spf: LookupResult<string[]>;
    dmarc: LookupResult<string[]>;
  };
  certificates: LookupResult<CertEntry[]>;
  reputation: LookupResult<ReputationData>;
  infrastructure: IpInfrastructure[];
}

export interface Finding {
  brand: string;
  domain: string;
  candidate: Candidate;
  facts: DnsFacts | null;
  signals: Signal[];
  tier: Tier;
  score: number;
  similarity_pct: number;
  mutation_type: string;
  enrichment?: DomainEnrichment | null;
}

export interface EnrichedFindingSchema {
  brand: string;
  domain: string;
  candidate: Candidate;
  facts: DnsFacts | null;
  signals: Signal[];
  tier: Tier;
  score: number;
  similarity_pct: number;
  mutation_type: string;
  status: FindingStatus;
  osint: Record<string, unknown>;
  osint_matrix: Record<string, unknown>;
  timeline: Array<Record<string, unknown>>;
  dna: Record<string, unknown> | null;
  precrime: number | null;
  drift: boolean;
  drift_data: Record<string, unknown> | null;
  enrichment?: DomainEnrichment | null;
}

export interface GeoPoint {
  code: string;
  name: string;
  coords: [number, number];
  count: number;
  threats: number;
  asns: string[];
  domains: string[];
}

export interface ClusterMember {
  domain: string;
  tier: Tier;
  score: number;
}

export interface CampaignCluster {
  ip: string;
  asn: string;
  org: string;
  country: string;
  role: string;
  members: ClusterMember[];
  threats: number;
  confidence: number;
  caveat: string;
}

export interface ImpactSummary {
  harm_category: string;
  triage_hours: number;
  exposure_low: string;
  exposure_high: string;
  defensive_cost: string;
  note: string;
}

export interface ScanRequest {
  brand: string;
  scan_pass: 1 | 2;
  online_enrich: boolean;
  inspect_websites: boolean;
  allowlist: string[];
}

export interface ScanResults {
  scan_id: string;
  brand: string;
  scan_pass: 1 | 2;
  online_enrich: boolean;
  inspect_websites: boolean;
  generated: number;
  tiers: Record<Tier, number>;
  impact: ImpactSummary;
  findings: EnrichedFindingSchema[];
  geo: GeoPoint[];
  clusters: CampaignCluster[];
  completed_at: string;
}
