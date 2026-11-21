import { Fragment } from 'react';
import type { DomainEnrichmentDto, LookupResultDto, SignalDto } from '../../types/proteus-api.ts';

export const LOOKUP_STATUS_LABELS: Record<string, string> = {
  found: 'Found',
  no_records: 'No records found',
  lookup_failed: 'Lookup failed',
  source_unavailable: 'Source unavailable',
  not_collected: 'Skipped / Not collected',
};

export function formatTechnique(technique: string): string {
  return technique
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

export function importanceClass(imp: string): string {
  if (imp === 'Very High') return 'imp-vhigh';
  if (imp === 'High') return 'imp-high';
  if (imp === 'Medium') return 'imp-med';
  return 'imp-low';
}

export function safeExternalUrl(url: string | undefined): string | null {
  if (!url) return null;
  if (url.startsWith('https://') || url.startsWith('http://')) {
    return url;
  }
  return null;
}

export function triggerUrlDownload(url: string, fallbackName?: string): void {
  const a = document.createElement('a');
  a.href = url;
  if (fallbackName) a.download = fallbackName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

export interface ScoreBuckets {
  technique: number;
  similarity: number;
  lure: number;
  infra: number;
}

export function computeScoreBuckets(signals: SignalDto[]): ScoreBuckets {
  let technique = 0;
  let similarity = 0;
  let lure = 0;
  let infra = 0;

  for (const s of signals) {
    if (s.key === 'technique_baseline') {
      technique += s.points;
    } else if (
      s.key === 'lure_present' ||
      s.key === 'technique_combo'
    ) {
      lure += s.points;
    } else if (
      s.key === 'a_record' ||
      s.key === 'mx_present' ||
      s.key === 'spf_absent' ||
      s.key === 'dmarc_absent' ||
      s.key === 'fresh_domain' ||
      s.key === 'risky_tld'
    ) {
      infra += s.points;
    } else {
      similarity += s.points;
    }
  }

  return {
    technique: Math.min(50, technique),
    similarity: Math.min(25, similarity),
    lure: Math.min(10, lure),
    infra: Math.min(15, infra),
  };
}

export function DomainWithConfusables({ domain }: { domain: string }) {
  const chars = Array.from(domain);
  return (
    <>
      {chars.map((ch, idx) => {
        const isNonAscii = (ch.codePointAt(0) ?? 0) > 0x7f;
        return isNonAscii ? (
          <span key={idx} className="confusable" title="Non-ASCII homoglyph character">
            {ch}
          </span>
        ) : (
          <Fragment key={idx}>{ch}</Fragment>
        );
      })}
    </>
  );
}

export function LookupRowsBlock({
  label,
  result,
  fields = [],
}: {
  label: string;
  result: LookupResultDto<unknown>;
  fields?: Array<[string, unknown]>;
}) {
  const statusText = LOOKUP_STATUS_LABELS[result.status] ?? result.status;
  const retry =
    result.retry_after_seconds != null
      ? `Retry after ${result.retry_after_seconds}s`
      : null;
  const provenance = [
    statusText,
    result.source,
    result.checked_at ? result.checked_at.slice(0, 19).replace('T', ' ') + ' UTC' : null,
    result.detail,
    retry,
  ]
    .filter(Boolean)
    .join(' · ');

  const firstRow: [string, unknown] = [label, provenance];
  const rows: Array<[string, unknown]> = [firstRow, ...fields].filter(
    ([, val]) =>
      val != null && val !== '' && (!Array.isArray(val) || val.length > 0)
  );

  return (
    <div className="data-block">
      {rows.map(([k, v], i) => (
        <div key={i} className="data-row">
          <span className="data-label">{k}</span>
          <span style={{ overflowWrap: 'anywhere', textAlign: 'right' }}>
            {Array.isArray(v) ? v.join(', ') : String(v)}
          </span>
        </div>
      ))}
    </div>
  );
}

export function LiveDnsSection({ enrichment }: { enrichment: DomainEnrichmentDto }) {
  const reg = enrichment.rdap.data ?? {};
  const rdapFields: Array<[string, unknown]> = [
    ['Registrar', reg.registrar],
    ['Registered', reg.registration_date],
    ['Expires', reg.expiration_date],
    ['Domain status', reg.domain_statuses],
    ['Registry nameservers', reg.nameservers],
  ];

  const certs = enrichment.certificates.data ?? [];
  const certFields: Array<[string, unknown]> = certs.length
    ? [['Entries', certs.length]]
    : [];
  certs.slice(0, 5).forEach((cert) => {
    certFields.push(
      ['Names', cert.names],
      ['Issuer', cert.issuer],
      ['Logged', cert.logged_at],
      ['Valid from', cert.not_before],
      ['Valid until', cert.not_after]
    );
  });
  if (certs.length > 5) {
    certFields.push(['Full list', 'Available in the JSON export']);
  }

  return (
    <>
      {enrichment.collection_note && (
        <p style={{ color: 'var(--text-dim)', marginBottom: 12 }}>
          {enrichment.collection_note}
        </p>
      )}
      <LookupRowsBlock label="RDAP" result={enrichment.rdap} fields={rdapFields} />
      {Object.entries(enrichment.dns).map(([type, result]) => (
        <LookupRowsBlock
          key={type}
          label={type.toUpperCase()}
          result={result}
          fields={[['Records', result.data]]}
        />
      ))}
      <LookupRowsBlock
        label="Certificate Transparency"
        result={enrichment.certificates}
        fields={certFields}
      />
    </>
  );
}

export function LiveIpSection({
  infrastructure,
}: {
  infrastructure: DomainEnrichmentDto['infrastructure'];
}) {
  if (!infrastructure.length) {
    return (
      <p style={{ color: 'var(--text-mute)' }}>
        No addresses available for infrastructure lookup.
      </p>
    );
  }
  return (
    <>
      {infrastructure.map((ip) => {
        const net = ip.registration.data ?? {};
        return (
          <Fragment key={ip.address}>
            <LookupRowsBlock
              label={`${ip.address} registration`}
              result={ip.registration}
              fields={[
                ['Allocation name', net.name],
                ['Registry handle', net.handle],
                ['Range start', net.start_address],
                ['Range end', net.end_address],
                ['Registration country', net.country_code],
              ]}
            />
            <LookupRowsBlock
              label={`${ip.address} PTR`}
              result={ip.ptr}
              fields={[['Names', ip.ptr.data]]}
            />
          </Fragment>
        );
      })}
    </>
  );
}

export function LiveReputationSection({
  reputation,
}: {
  reputation: DomainEnrichmentDto['reputation'];
}) {
  const data = reputation.data ?? {};
  return (
    <LookupRowsBlock
      label="Reputation Feed"
      result={reputation}
      fields={[
        ['Malicious', data.malicious],
        ['Suspicious', data.suspicious],
        ['Harmless', data.harmless],
        ['Undetected', data.undetected],
        ['Matched URLs', data.matched_url_count],
        ['Last analysis', data.last_analysis_at],
      ]}
    />
  );
}
