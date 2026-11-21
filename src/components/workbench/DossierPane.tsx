import { useState } from 'react';
import { Check, Copy, FileWarning, Share2 } from 'lucide-react';
import type { FindingDto, ScanResultsDto } from '../../types/proteus-api.ts';
import {
  computeScoreBuckets,
  DomainWithConfusables,
  formatTechnique,
  LiveDnsSection,
  LiveIpSection,
  LiveReputationSection,
  safeExternalUrl,
  triggerUrlDownload,
} from './shared.tsx';

export type DossierTab =
  | 'tab-overview'
  | 'tab-infra'
  | 'tab-dna'
  | 'tab-osint';

interface DossierPaneProps {
  activeFinding: FindingDto | null;
  currentData: ScanResultsDto | null;
  currentScanId: string | null;
  scanning: boolean;
  scanError: string | null;
  dossierTab: DossierTab;
  onChangeTab: (tab: DossierTab) => void;
  onOpenTakedown: (domain: string) => void;
}

export function DossierPane({
  activeFinding,
  currentData,
  currentScanId,
  scanning,
  scanError,
  dossierTab,
  onChangeTab,
  onOpenTakedown,
}: DossierPaneProps) {
  const [copiedDomain, setCopiedDomain] = useState(false);

  if (scanError) {
    return (
      <div className="dossier-pane" id="investigation-drawer">
        <div className="empty-state" style={{ color: 'var(--crit)' }}>
          <strong>Scan failed:</strong> {scanError}
        </div>
      </div>
    );
  }

  if (!activeFinding) {
    return (
      <div className="dossier-pane" id="investigation-drawer">
        <div className="empty-state">
          {scanning
            ? 'Initializing scan…'
            : currentData
              ? 'Scan returned zero findings.'
              : 'Select a finding to inspect.'}
        </div>
      </div>
    );
  }

  const isLiveThreat =
    activeFinding.status === 'LIVE INFRA' ||
    activeFinding.status === 'DRIFT DETECTED';
  const buckets = computeScoreBuckets(activeFinding.signals);

  const handleCopyDomain = async () => {
    try {
      await navigator.clipboard.writeText(activeFinding.domain);
      setCopiedDomain(true);
      window.setTimeout(() => setCopiedDomain(false), 1600);
    } catch {
      // Clipboard API may be restricted
    }
  };

  const tierTone =
    activeFinding.tier === 'CRITICAL'
      ? 'var(--crit)'
      : activeFinding.tier === 'HIGH'
        ? 'var(--high)'
        : activeFinding.tier === 'WATCH'
          ? 'var(--watch)'
          : 'var(--accent-text)';

  return (
    <div className="dossier-pane" id="investigation-drawer">
      <header className="dossier-header">
        <div className="dossier-top-row">
          <div className="dossier-identity">
            <div className="dossier-domain-wrap">
              <h3 className="dossier-domain">
                <DomainWithConfusables domain={activeFinding.domain} />
              </h3>
              <button
                type="button"
                className="btn-copy-inline"
                onClick={() => void handleCopyDomain()}
                aria-label="Copy domain name"
                title="Copy domain name"
              >
                {copiedDomain ? (
                  <>
                    <Check size={12} aria-hidden="true" />
                    <span>Copied</span>
                  </>
                ) : (
                  <>
                    <Copy size={12} aria-hidden="true" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>

            <div className="dossier-meta">
              <span>{activeFinding.candidate.ascii_form}</span>
              <span aria-hidden="true">·</span>
              <span>{activeFinding.status}</span>
              <span aria-hidden="true">·</span>
              <span>{activeFinding.candidate.registrable}</span>
              <span aria-hidden="true">·</span>
              <span
                style={{
                  color: currentData?.online_enrich ? 'var(--low)' : 'var(--text-mute)',
                }}
              >
                {currentData?.online_enrich ? 'Live DNS / RDAP / CT' : 'Fixture Model'}
              </span>
            </div>
          </div>

          <div className="dossier-score-col">
            <div className="dossier-score" style={{ color: tierTone }}>
              {activeFinding.score}
              <span className="dossier-score-denom">/100</span>
            </div>
            <div className="dossier-tier-line">{activeFinding.tier}</div>
          </div>
        </div>

        {/* Quiet Inline Context & Action Row */}
        <div className="dossier-context-row">
          <div className="dossier-context-line">
            <span className="dossier-tech-name">
              {formatTechnique(activeFinding.candidate.technique)}
            </span>
            <span aria-hidden="true">·</span>
            <span>{activeFinding.candidate.importance}</span>
            <span aria-hidden="true">·</span>
            <span>Weight {activeFinding.candidate.weight}/100</span>
            <span aria-hidden="true">·</span>
            <span>{activeFinding.similarity_pct}% similarity</span>
            <span aria-hidden="true">·</span>
            <span>{activeFinding.mutation_type}</span>
          </div>

          {isLiveThreat && currentScanId && (
            <div className="dossier-action-group">
              <button
                type="button"
                className="wb-btn-sm"
                onClick={() => onOpenTakedown(activeFinding.domain)}
              >
                <FileWarning size={12} aria-hidden="true" />
                <span>Takedown Report</span>
              </button>
              <button
                type="button"
                className="btn-inline-action"
                onClick={() =>
                  triggerUrlDownload(
                    `/api/export/misp/${encodeURIComponent(activeFinding.domain)}?scan_id=${currentScanId}`
                  )
                }
              >
                <Share2 size={12} aria-hidden="true" />
                <span>MISP JSON</span>
              </button>
            </div>
          )}
        </div>
      </header>

      <div className="dossier-tabs" role="tablist" aria-label="Dossier Sections">
        {(
          [
            ['tab-overview', 'Summary'],
            ['tab-infra', 'DNS & Network'],
            ['tab-dna', 'Brand DNA & Drift'],
            ['tab-osint', 'OSINT & Takedown'],
          ] as Array<[DossierTab, string]>
        ).map(([tabId, label]) => (
          <button
            key={tabId}
            type="button"
            role="tab"
            aria-selected={dossierTab === tabId}
            className={`dossier-tab ${dossierTab === tabId ? 'active' : ''}`}
            onClick={() => onChangeTab(tabId)}
          >
            {label}
          </button>
        ))}
      </div>

      <div className="dossier-content">
        {dossierTab === 'tab-overview' && (
          <div className="dossier-stack">
            <section>
              <div className="section-title">Score Composition</div>
              <div className="score-breakdown-card">
                <div className="score-stack-bar" aria-label="Score composition bar">
                  {buckets.technique > 0 && (
                    <div
                      className="score-seg seg-tech"
                      style={{ width: `${buckets.technique}%` }}
                      title={`Technique: +${buckets.technique}/50`}
                    />
                  )}
                  {buckets.similarity > 0 && (
                    <div
                      className="score-seg seg-sim"
                      style={{ width: `${buckets.similarity}%` }}
                      title={`Similarity: +${buckets.similarity}/25`}
                    />
                  )}
                  {buckets.lure > 0 && (
                    <div
                      className="score-seg seg-lure"
                      style={{ width: `${buckets.lure}%` }}
                      title={`Lure: +${buckets.lure}/10`}
                    />
                  )}
                  {buckets.infra > 0 && (
                    <div
                      className="score-seg seg-infra"
                      style={{ width: `${buckets.infra}%` }}
                      title={`Infrastructure: +${buckets.infra}/15`}
                    />
                  )}
                </div>
                <div className="score-legend-row">
                  <span>
                    <i className="dot seg-tech" /> Technique{' '}
                    <strong>{buckets.technique}</strong>/50
                  </span>
                  <span>
                    <i className="dot seg-sim" /> Similarity{' '}
                    <strong>{buckets.similarity}</strong>/25
                  </span>
                  <span>
                    <i className="dot seg-lure" /> Lure{' '}
                    <strong>{buckets.lure}</strong>/10
                  </span>
                  <span>
                    <i className="dot seg-infra" /> Infrastructure{' '}
                    <strong>{buckets.infra}</strong>/15
                  </span>
                </div>
              </div>
            </section>

            <section>
              <div className="section-title">Risk Signals</div>
              <div className="clean-kv-list">
                {activeFinding.signals.map((s, idx) => (
                  <div key={idx} className="signal-item">
                    <span className="signal-text">
                      {s.label}
                      {s.evidence && (
                        <span className="evidence"> — {s.evidence}</span>
                      )}
                    </span>
                    <span className="signal-pts">+{s.points}</span>
                  </div>
                ))}
              </div>
            </section>

            <section>
              <div className="section-title">Modeled Impact</div>
              <div className="data-grid">
                <div className="data-block">
                  <div className="data-row">
                    <span className="data-label">Harm Category</span>
                    <span>{currentData?.impact.harm_category || 'N/A'}</span>
                  </div>
                  <div className="data-row">
                    <span className="data-label">Triage Saved</span>
                    <span style={{ fontVariantNumeric: 'tabular-nums' }}>
                      {currentData?.impact.triage_hours ?? 0} hrs
                    </span>
                  </div>
                </div>
                <div className="data-block">
                  <div className="data-row">
                    <span className="data-label">Exposure</span>
                    <span style={{ fontVariantNumeric: 'tabular-nums' }}>
                      {currentData?.impact.exposure_low || 'N/A'} –{' '}
                      {currentData?.impact.exposure_high || 'N/A'}
                    </span>
                  </div>
                  <div className="data-row">
                    <span className="data-label">Defensive Cost</span>
                    <span style={{ fontVariantNumeric: 'tabular-nums' }}>
                      {currentData?.impact.defensive_cost || 'N/A'}
                    </span>
                  </div>
                </div>
              </div>
            </section>

            {!currentData?.online_enrich && activeFinding.timeline.length > 0 && (
              <section>
                <div className="section-title">Observed Timeline</div>
                <div className="timeline">
                  {activeFinding.timeline.map((t, idx) => (
                    <div key={idx} className="timeline-item">
                      <span className="timeline-date">{t.time.slice(0, 10)}</span>
                      <span className="timeline-event">
                        <span className="timeline-kind">{t.kind}</span>
                        {t.event}
                      </span>
                    </div>
                  ))}
                </div>
              </section>
            )}
          </div>
        )}

        {dossierTab === 'tab-infra' && (
          <div className="dossier-stack">
            {currentData?.online_enrich && activeFinding.enrichment ? (
              <>
                <section>
                  <div className="section-title">DNS, RDAP &amp; Certificates</div>
                  <LiveDnsSection enrichment={activeFinding.enrichment} />
                </section>
                <section>
                  <div className="section-title">IP Allocation &amp; Reverse DNS</div>
                  <LiveIpSection infrastructure={activeFinding.enrichment.infrastructure} />
                </section>
              </>
            ) : (
              <>
                <section>
                  <div className="section-title">DNS &amp; Mail Posture</div>
                  <div className="data-grid">
                    <div className="data-block">
                      <div className="data-row">
                        <span className="data-label">A Records</span>
                        <span>{activeFinding.facts?.a_records.join(', ') || 'N/A'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">AAAA Records</span>
                        <span>
                          {activeFinding.facts?.aaaa_records.join(', ') || 'N/A'}
                        </span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">MX Records</span>
                        <span>{activeFinding.facts?.mx_records.join(', ') || 'N/A'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">NS Records</span>
                        <span>{activeFinding.facts?.ns_records.join(', ') || 'N/A'}</span>
                      </div>
                    </div>
                    <div className="data-block">
                      <div className="data-row">
                        <span className="data-label">SPF</span>
                        <span>{activeFinding.facts?.spf ? 'Present' : 'Missing'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">DMARC</span>
                        <span>{activeFinding.facts?.dmarc ? 'Present' : 'Missing'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">Registrar</span>
                        <span>{activeFinding.facts?.registrar || 'N/A'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">Created</span>
                        <span>
                          {activeFinding.facts?.created_days_ago != null
                            ? `${activeFinding.facts.created_days_ago} days ago`
                            : 'N/A'}
                        </span>
                      </div>
                    </div>
                  </div>
                </section>

                <section>
                  <div className="section-title">TLS / SSL Certificate</div>
                  <div className="data-grid">
                    <div className="data-block">
                      <div className="data-row">
                        <span className="data-label">Issuer</span>
                        <span>{activeFinding.facts?.tls_issuer || 'N/A'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">Subject CN</span>
                        <span>{activeFinding.facts?.tls_subject || 'N/A'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">Fingerprint</span>
                        <span style={{ wordBreak: 'break-all' }}>
                          {activeFinding.facts?.tls_fingerprint || 'N/A'}
                        </span>
                      </div>
                    </div>
                    <div className="data-block">
                      <div className="data-row">
                        <span className="data-label">Not Before</span>
                        <span>
                          {activeFinding.facts?.tls_not_before &&
                          activeFinding.facts.tls_not_before !== 'N/A'
                            ? activeFinding.facts.tls_not_before.slice(0, 10)
                            : 'N/A'}
                        </span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">Not After</span>
                        <span>
                          {activeFinding.facts?.tls_not_after &&
                          activeFinding.facts.tls_not_after !== 'N/A'
                            ? activeFinding.facts.tls_not_after.slice(0, 10)
                            : 'N/A'}
                        </span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">SANs</span>
                        <span>{activeFinding.facts?.tls_sans.join(', ') || 'N/A'}</span>
                      </div>
                    </div>
                  </div>
                </section>

                <section>
                  <div className="section-title">IP, ASN &amp; Ownership</div>
                  <div className="data-grid">
                    <div className="data-block">
                      <div className="data-row">
                        <span className="data-label">ASN</span>
                        <span>{activeFinding.facts?.asn || 'N/A'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">ASN Org</span>
                        <span>{activeFinding.facts?.asn_org || 'N/A'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">Country</span>
                        <span>{activeFinding.facts?.country || 'N/A'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">Role</span>
                        <span>{activeFinding.facts?.infra_role || 'N/A'}</span>
                      </div>
                    </div>
                    <div className="data-block">
                      <div className="data-row">
                        <span className="data-label">Netblock</span>
                        <span>{activeFinding.facts?.netblock || 'N/A'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">rDNS / PTR</span>
                        <span>{activeFinding.facts?.rdns || 'N/A'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">Abuse Contact</span>
                        <span>{activeFinding.facts?.abuse_contact || 'N/A'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">Data Source</span>
                        <span>{activeFinding.facts?.source || 'NO DATA'}</span>
                      </div>
                    </div>
                  </div>
                </section>

                <section>
                  <div className="section-title">Historical IPs</div>
                  <div className="data-block">
                    {activeFinding.facts?.past_ips &&
                    activeFinding.facts.past_ips.length > 0 ? (
                      activeFinding.facts.past_ips.map((p, i) => (
                        <div key={i} className="data-row">
                          <span className="data-label">Past IP</span>
                          <span>
                            {p.ip} · {p.seen.slice(0, 10)}
                          </span>
                        </div>
                      ))
                    ) : (
                      <div className="data-row">
                        <span className="data-label">Past IPs</span>
                        <span>None recorded</span>
                      </div>
                    )}
                  </div>
                </section>
              </>
            )}
          </div>
        )}

        {dossierTab === 'tab-dna' && (
          <div className="dossier-stack">
            {currentData?.online_enrich ? (
              <p className="quiet-note">
                Brand DNA and identity drift telemetry were not collected in live lookup mode.
              </p>
            ) : activeFinding.dna ? (
              <>
                <section>
                  <div className="section-title">Brand DNA Match</div>
                  <div className="data-grid">
                    <div className="data-block">
                      <div className="data-row">
                        <span className="data-label">Impersonation Similarity</span>
                        <strong>{activeFinding.dna.similarity_pct}%</strong>
                      </div>
                      <div className="data-row">
                        <span className="data-label">Logo Match</span>
                        <span>{activeFinding.dna.logo_match ? 'YES' : 'NO'}</span>
                      </div>
                    </div>
                    <div className="data-block">
                      <div className="data-row">
                        <span className="data-label">Login Form</span>
                        <span>{activeFinding.dna.login_form ? 'YES' : 'NO'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">Visual Match</span>
                        <span>{activeFinding.dna.visual_match ? 'YES' : 'NO'}</span>
                      </div>
                    </div>
                  </div>
                  <div className="dna-phrases-row">
                    Matched phrases: {activeFinding.dna.matched_phrases.join(', ')}
                  </div>
                </section>

                <section>
                  <div className="section-title">Identity Drift</div>
                  {activeFinding.drift && activeFinding.drift_data ? (
                    <div className="drift-box">
                      <div className="drift-step-label">Scan #1 (Baseline)</div>
                      <div className="drift-step-val">{activeFinding.drift_data.before}</div>
                      <div className="drift-step-label" style={{ marginTop: 14 }}>
                        Scan #2 (Observed Change)
                      </div>
                      <div className="drift-step-val" style={{ color: 'var(--crit)' }}>
                        {activeFinding.drift_data.after}
                      </div>
                    </div>
                  ) : (
                    <p className="quiet-note">No infrastructure drift observed between passes.</p>
                  )}
                </section>
              </>
            ) : (
              <p className="quiet-note">Not observed — domain has no active surface.</p>
            )}
          </div>
        )}

        {dossierTab === 'tab-osint' && (
          <div className="dossier-stack">
            <section>
              <div className="section-title">Response &amp; Takedown</div>
              {isLiveThreat ? (
                <div className="response-action-bar">
                  <button
                    type="button"
                    className="wb-btn"
                    onClick={() => onOpenTakedown(activeFinding.domain)}
                  >
                    Generate Takedown Report
                  </button>
                  <a
                    className="btn-outline"
                    style={{ textDecoration: 'none', padding: '9px 14px' }}
                    href={
                      currentScanId
                        ? `/api/export/misp/${encodeURIComponent(
                            activeFinding.domain
                          )}?scan_id=${currentScanId}`
                        : '#'
                    }
                    download
                  >
                    Download MISP JSON
                  </a>
                </div>
              ) : (
                <div className="quiet-empty-box">
                  No active hosting observed. Takedown workflow is standby.
                </div>
              )}
            </section>

            <section>
              {currentData?.online_enrich && activeFinding.enrichment ? (
                <>
                  <div className="section-title">Live Threat Feeds</div>
                  <LiveReputationSection reputation={activeFinding.enrichment.reputation} />
                </>
              ) : (
                <>
                  <div className="section-title">News &amp; Advisories</div>
                  {(activeFinding.osint.intel ?? []).length > 0 ? (
                    activeFinding.osint.intel!.map((n, i) => {
                      const href = safeExternalUrl(n.link);
                      return (
                        <div key={i} className="news-card">
                          <div className="news-header">
                            <div>
                              <div className="news-source">{n.source}</div>
                              <div className="news-type">
                                {n.type} · {n.sentiment}
                              </div>
                            </div>
                            <span className={`news-badge ${n.kind}`}>
                              {n.kind === 'live' ? 'LIVE PUBLIC' : 'FIXTURE'}
                            </span>
                          </div>
                          <div className="news-title">{n.title}</div>
                          <div className="news-summary">{n.summary}</div>
                          <div className="news-meta">
                            <span>
                              {n.date.slice(0, 19).replace('T', ' ')} UTC
                            </span>
                            {href && (
                              <a
                                href={href}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="intel-link"
                              >
                                View Source ↗
                              </a>
                            )}
                          </div>
                        </div>
                      );
                    })
                  ) : (
                    <p className="quiet-note">No external news or advisories observed.</p>
                  )}
                </>
              )}
            </section>

            <section>
              <div className="section-title">External OSINT Pivot Links</div>
              <div className="osint-grid">
                {Object.entries(activeFinding.osint.links ?? {}).map(
                  ([category, links]) => (
                    <div key={category} className="osint-category">
                      <div className="osint-cat-title">{formatTechnique(category)}</div>
                      {links.map((l, idx) => {
                        const href = safeExternalUrl(l.url);
                        return (
                          <div key={idx} className="osint-link-item">
                            <div className="osint-link-top">
                              <span className="osint-source">{l.source}</span>
                              {href && (
                                <a
                                  href={href}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="intel-link"
                                >
                                  Open ↗
                                </a>
                              )}
                            </div>
                            <span className="osint-desc">{l.desc}</span>
                          </div>
                        );
                      })}
                    </div>
                  )
                )}
              </div>
            </section>
          </div>
        )}
      </div>
    </div>
  );
}
