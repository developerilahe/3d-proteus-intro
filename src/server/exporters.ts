import { sortFindings } from './triage.ts';
import type { DnsFacts, EnrichedFindingSchema } from './types.ts';

const CSV_COLUMNS = [
  'domain', 'ascii_form', 'registrable', 'family', 'technique',
  'importance', 'weight', 'rule', 'tier', 'score', 'similarity_pct',
  'mutation_type', 'a_record', 'mx', 'spf', 'dmarc', 'age_days',
  'registrar', 'reasons',
];

function escapeCsvCell(value: string): string {
  // Neutralize spreadsheet formula triggers on untrusted domain/registrar fields
  let safe = value;
  if (/^[=+\-@\t\r]/.test(safe)) {
    safe = `'${safe}`;
  }
  if (/[",\r\n]/.test(safe)) {
    return `"${safe.replace(/"/g, '""')}"`;
  }
  return safe;
}

export function exportCsv(findings: EnrichedFindingSchema[]): string {
  const ordered = sortFindings(findings);
  const lines = [CSV_COLUMNS.join(',')];
  for (const f of ordered) {
    const facts = f.facts;
    const row: Record<string, string> = {
      domain: f.candidate.domain,
      ascii_form: f.candidate.ascii_form,
      registrable: f.candidate.registrable,
      family: f.candidate.family,
      technique: f.candidate.technique,
      importance: f.candidate.importance,
      weight: String(f.candidate.weight),
      rule: f.candidate.rule,
      tier: f.tier,
      score: String(f.score),
      similarity_pct: String(f.similarity_pct),
      mutation_type: f.mutation_type,
      a_record: facts && facts.a_records.length > 0 ? '1' : '0',
      mx: facts && facts.mx_records.length > 0 ? '1' : '0',
      spf: facts?.spf ? '1' : '0',
      dmarc: facts?.dmarc ? '1' : '0',
      age_days: facts && facts.created_days_ago !== null ? String(facts.created_days_ago) : '',
      registrar: facts?.registrar || '',
      reasons: f.signals.map((s) => `${s.key}:${s.points}`).join(' | '),
    };
    lines.push(CSV_COLUMNS.map((col) => escapeCsvCell(row[col] ?? '')).join(','));
  }
  return lines.join('\r\n') + '\r\n';
}

function factsDict(facts: DnsFacts | null): Record<string, unknown> | null {
  if (!facts) return null;
  return {
    a_records: [...facts.a_records],
    aaaa_records: [...facts.aaaa_records],
    mx_records: [...facts.mx_records],
    ns_records: [...facts.ns_records],
    spf: facts.spf,
    dmarc: facts.dmarc,
    created_days_ago: facts.created_days_ago,
    registrar: facts.registrar,
    asn: facts.asn,
    asn_org: facts.asn_org,
    country: facts.country,
    region: facts.region,
    netblock: facts.netblock,
    infra_role: facts.infra_role,
    rdns: facts.rdns,
    abuse_contact: facts.abuse_contact,
    past_ips: facts.past_ips.map((p) => [p.ip, p.seen]),
    tls: {
      issuer: facts.tls_issuer,
      subject_cn: facts.tls_subject,
      san_list: [...facts.tls_sans],
      not_before: facts.tls_not_before,
      not_after: facts.tls_not_after,
      sha256_prefix: facts.tls_fingerprint,
    },
    source: facts.source,
  };
}

export function exportJson(
  findings: EnrichedFindingSchema[],
  brand: string | null = null
): string {
  const ordered = sortFindings(findings);
  const records = ordered.map((f) => ({
    domain: f.candidate.domain,
    ascii_form: f.candidate.ascii_form,
    registrable: f.candidate.registrable,
    family: f.candidate.family,
    rule: f.candidate.rule,
    technique: f.candidate.technique,
    importance: f.candidate.importance,
    weight: f.candidate.weight,
    provenance: f.candidate.provenance,
    tier: f.tier,
    score: f.score,
    similarity_pct: f.similarity_pct,
    mutation_type: f.mutation_type,
    facts: factsDict(f.facts),
    signals: f.signals.map((s) => ({
      key: s.key,
      label: s.label,
      points: s.points,
      evidence: s.evidence,
    })),
    ...(f.enrichment ? { enrichment: f.enrichment } : {}),
  }));

  return JSON.stringify(
    {
      brand,
      count: ordered.length,
      findings: records,
    },
    null,
    2
  );
}

function recipientFor(channel: string, facts: DnsFacts | null): string {
  const map: Record<string, string> = {
    'Domain Registrar': `Registrar abuse desk — ${facts?.registrar || 'unknown'}`,
    'Hosting Provider': `Hosting abuse desk — ${facts?.asn_org || 'unknown'} (${facts?.abuse_contact || 'N/A'})`,
    'Google Safe Browsing': 'Google Safe Browsing — https://safebrowsing.google.com/',
    'Microsoft Defender SmartScreen': 'Microsoft — https://www.microsoft.com/wdsi/support/report-unsafe-site',
    APWG: 'APWG eCrime Exchange — https://apwg.org/reportphishing/',
    'National CERT / CSIRT': 'National CERT/CSIRT abuse intake',
  };
  return map[channel] ?? channel;
}

export function generateTakedownReport(
  f: EnrichedFindingSchema,
  channel = 'Domain Registrar'
): string {
  const facts = f.facts;
  const now = new Date().toISOString().replace(/\.\d{3}Z$/, '+00:00');
  const evidence = f.signals
    .map((s) => `  - ${s.label} (+${s.points})${s.evidence ? ` — ${s.evidence}` : ''}`)
    .join('\n');

  return `PROTEUS TAKEDOWN REQUEST
========================================
Generated (UTC): ${now}
Channel: ${channel}
Recipient: ${recipientFor(channel, facts)}

TARGET
  Domain:            ${f.candidate.domain}
  ASCII / Punycode:  ${f.candidate.ascii_form}
  Registrable:       ${f.candidate.registrable}
  Technique:         ${f.candidate.technique} (${f.candidate.importance}, weight ${f.candidate.weight}/100)
  Mutation type:     ${f.mutation_type}
  Name similarity:   ${f.similarity_pct}%
  Risk tier:         ${f.tier} (score ${f.score}/100)

HOSTING & REGISTRATION
  Registrar:         ${facts?.registrar || 'N/A'}
  Domain age:        ${facts && facts.created_days_ago !== null ? `${facts.created_days_ago} days` : 'N/A'}
  A records:         ${facts && facts.a_records.length ? facts.a_records.join(', ') : 'N/A'}
  MX records:        ${facts && facts.mx_records.length ? facts.mx_records.join(', ') : 'N/A'}
  NS records:        ${facts && facts.ns_records.length ? facts.ns_records.join(', ') : 'N/A'}
  ASN:               ${facts?.asn || 'N/A'} (${facts?.asn_org || 'N/A'})
  Netblock:          ${facts?.netblock || 'N/A'}
  Country:           ${facts?.country || 'N/A'}
  Infra role:        ${facts?.infra_role || 'N/A'}
  rDNS:              ${facts?.rdns || 'N/A'}
  Abuse contact:     ${facts?.abuse_contact || 'N/A'}

TLS
  Issuer:            ${facts?.tls_issuer || 'N/A'}
  Subject CN:        ${facts?.tls_subject || 'N/A'}
  SANs:              ${facts && facts.tls_sans.length ? facts.tls_sans.join(', ') : 'N/A'}
  Valid from:        ${facts?.tls_not_before || 'N/A'}
  Valid to:          ${facts?.tls_not_after || 'N/A'}
  SHA-256 prefix:    ${facts?.tls_fingerprint || 'N/A'}

EVIDENCE (explainable signals)
${evidence}

REQUESTED ACTION
  1. Suspend or sinkhole the domain pending abuse review.
  2. Preserve registration, DNS, and TLS records for the retention period.
  3. Confirm receipt and provide a case reference.

LEGAL / SAFETY NOTE
  This report is generated from defensive brand-protection analysis.
  All telemetry is fixture-derived unless explicitly tagged LIVE PUBLIC.
  No unauthorized access, scanning, or payload interaction was performed.

Signature: PROTEUS / Lookalike Sentinel — automated brand protection
`;
}

export function generateMispEvent(f: EnrichedFindingSchema): Record<string, unknown> {
  const facts = f.facts;
  const attributes: Array<Record<string, unknown>> = [
    { type: 'domain', category: 'Network activity', to_ids: true, value: f.candidate.domain },
    { type: 'domain', category: 'Network activity', to_ids: true, value: f.candidate.ascii_form },
  ];

  if (facts) {
    for (const ip of facts.a_records) {
      attributes.push({ type: 'ip-dst', category: 'Network activity', to_ids: true, value: ip });
    }
    if (facts.asn) {
      attributes.push({ type: 'AS', category: 'Network activity', to_ids: false, value: facts.asn });
    }
    if (facts.tls_fingerprint && facts.tls_fingerprint !== 'N/A') {
      attributes.push({
        type: 'x509-fingerprint-sha256',
        category: 'Network activity',
        to_ids: false,
        value: facts.tls_fingerprint.replace(/:/g, ''),
      });
    }
  }

  return {
    Event: {
      info: `PROTEUS lookalike: ${f.candidate.domain} — ${f.candidate.technique} (${f.tier} ${f.score})`,
      distribution: '0',
      threat_level_id: f.tier === 'CRITICAL' ? '1' : '2',
      analysis: '1',
      date: new Date().toISOString().slice(0, 10),
      published: false,
      Attribute: attributes,
      Tag: [
        { name: 'brand-abuse' },
        { name: 'lookalike-domain' },
        { name: `technique:${f.candidate.technique}` },
        { name: `tier:${f.tier.toLowerCase()}` },
        { name: 'tlp:amber' },
      ],
    },
  };
}
