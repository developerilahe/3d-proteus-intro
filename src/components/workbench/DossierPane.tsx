import { useCallback, useEffect, useRef, useState } from 'react';
import { Check, Copy, FileWarning, Share2 } from 'lucide-react';
import type { FindingDto, ScanResultsDto } from '../../types/proteus-api.ts';
import {
  DomainWithConfusables,
  formatRiskLevel,
  formatStatusLabel,
  formatTechnique,
  getPlainTakeaway,
  getPrimaryIp,
  getRecommendedStep,
  isLiveFinding,
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
  const contentRef = useRef<HTMLDivElement | null>(null);
  const stageRef = useRef<HTMLDivElement | null>(null);
  const rafRef = useRef<number>(0);

  const syncScrollVars = useCallback(() => {
    rafRef.current = 0;
    const scroller = contentRef.current;
    const stage = stageRef.current;
    if (!scroller || !stage) return;

    const maxScroll = Math.max(1, scroller.scrollHeight - scroller.clientHeight);
    const progress = Math.min(1, Math.max(0, scroller.scrollTop / maxScroll));
    const strokeOffset = Math.round(-(2400 * progress));
    const tabletOffset = `${Math.round(-(0.55 * scroller.clientHeight * progress))}px`;

    stage.style.setProperty('--strokeDashoffset', String(strokeOffset));
    stage.style.setProperty('--tabletVerticaloffset', tabletOffset);
  }, []);

  const handleContentScroll = useCallback(() => {
    if (dossierTab !== 'tab-overview') return;
    if (!rafRef.current) {
      rafRef.current = window.requestAnimationFrame(syncScrollVars);
    }
  }, [dossierTab, syncScrollVars]);

  useEffect(() => {
    if (contentRef.current) {
      contentRef.current.scrollTop = 0;
    }
    if (stageRef.current) {
      stageRef.current.style.setProperty('--strokeDashoffset', '0');
      stageRef.current.style.setProperty('--tabletVerticaloffset', '0px');
    }
    return () => {
      if (rafRef.current) {
        window.cancelAnimationFrame(rafRef.current);
        rafRef.current = 0;
      }
    };
  }, [activeFinding?.domain, dossierTab]);

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
            ? 'Checking domains and IP addresses…'
            : currentData
              ? 'No domains returned for this scan.'
              : 'Select a domain from the list to inspect.'}
        </div>
      </div>
    );
  }

  const liveNow = isLiveFinding(activeFinding);
  const isLiveThreat =
    activeFinding.score > 15 &&
    (activeFinding.status === 'LIVE INFRA' ||
      activeFinding.status === 'DRIFT DETECTED' ||
      activeFinding.status === 'PRECRIME');

  const primaryIp = getPrimaryIp(activeFinding);
  const statusLabel = formatStatusLabel(activeFinding.status);
  const riskLevelLabel = formatRiskLevel(activeFinding.score, activeFinding.status);
  const takeaway = getPlainTakeaway(activeFinding);
  const nextStep = getRecommendedStep(activeFinding);

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
    activeFinding.status === 'SAFE' || activeFinding.score <= 15
      ? 'var(--low)'
      : activeFinding.tier === 'CRITICAL'
        ? 'var(--crit)'
        : activeFinding.tier === 'HIGH'
          ? 'var(--high)'
          : 'var(--watch)';

  const facts = activeFinding.facts;
  const hasMail = Boolean(
    (facts?.mx_records?.length ?? 0) > 0 ||
      (activeFinding.enrichment?.dns?.mx?.data?.length ?? 0) > 0
  );
  const hasMailProtection = Boolean(facts?.spf || facts?.dmarc);
  const hostingLabel = facts?.asn_org
    ? `${facts.asn_org}${facts.country ? ` (${facts.country})` : ''}`
    : liveNow
      ? 'Active server'
      : 'Not active';
  const domainAgeLabel =
    facts?.created_days_ago != null
      ? `${facts.created_days_ago} days`
      : activeFinding.enrichment?.rdap?.data?.registration_date
        ? activeFinding.enrichment.rdap.data.registration_date.slice(0, 10)
        : 'Unknown';

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
              <span>
                IP: <strong className="dossier-ip-val">{primaryIp}</strong>
              </span>
              <span aria-hidden="true">·</span>
              <span>{statusLabel}</span>
              <span aria-hidden="true">·</span>
              <span>{formatTechnique(activeFinding.candidate.technique)}</span>
            </div>
          </div>

          <div className="dossier-score-col">
            <div className="dossier-score" style={{ color: tierTone }}>
              {activeFinding.score}
              <span className="dossier-score-denom">/100</span>
            </div>
            <div className="dossier-tier-line" style={{ color: tierTone }}>
              {riskLevelLabel}
            </div>
          </div>
        </div>

        {isLiveThreat && currentScanId && (
          <div className="dossier-context-row">
            <span className="dossier-context-note">{takeaway}</span>
            <div className="dossier-action-group">
              <button
                type="button"
                className="wb-btn-sm"
                onClick={() => onOpenTakedown(activeFinding.domain)}
              >
                <FileWarning size={12} aria-hidden="true" />
                <span>Takedown Notice</span>
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
                <span>Export MISP</span>
              </button>
            </div>
          </div>
        )}
      </header>

      <div className="dossier-tabs" role="tablist" aria-label="Domain details">
        {(
          [
            ['tab-overview', 'Overview'],
            ['tab-infra', 'Server & DNS'],
            ['tab-dna', 'Brand Check'],
            ['tab-osint', 'Actions & Links'],
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

      <div
        ref={contentRef}
        className={`dossier-content ${dossierTab === 'tab-overview' ? 'is-story-mode' : ''}`}
        onScroll={handleContentScroll}
      >
        {dossierTab === 'tab-overview' && (
          <div
            ref={stageRef}
            className="cp-main"
            style={
              {
                '--strokeDashoffset': '0',
                '--tabletVerticaloffset': '0px',
              } as React.CSSProperties
            }
          >
            {/* 3D Tilted Tablet Background */}
            <div className="cp-world3d" aria-hidden="true">
              <div className="cp-tablet" />
            </div>

            {/* Exact CodePen Glowing Gradient SVG Paths */}
            <svg
              id="cp-svgPaths"
              width="740"
              height="2000"
              viewBox="0 0 740 2000"
              xmlns="http://www.w3.org/2000/svg"
              aria-hidden="true"
            >
              <defs>
                <linearGradient id="cp-cl1" gradientUnits="objectBoundingBox" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="20%" stopColor="#b169db" />
                  <stop offset="45%" stopColor="#f7d152" />
                  <stop offset="65%" stopColor="#46cf71" />
                  <stop offset="85%" stopColor="#0fbffa" />
                  <stop offset="100%" stopColor="#0fbffa" />
                </linearGradient>
                <path
                  id="cp-linePath01"
                  d="m 106,45h 375c 114,0 226,128 226,235v 236c 0,136 -122,222 -224,221l -182,-2c -89,1 -141,42 -142,158l -2,204c -1,117 37,173 134,173h 186c 110,-3 230,111 230,220v 242c 0,113 -125,225 -248,225H 105"
                />
                <path
                  id="cp-linePath02"
                  d="m 33,85h 444c 96,0 190,107 190,201v 224c 0,116 -98,188 -190,187l -192,-2c -92,0 -166,75 -166,168v 278c 0,94 74,169 166,169h 194c 92,0 188,94 188,188v 228c 0,94 -104,191 -214,191H 105"
                />
                <path
                  id="cp-linePath03"
                  d="m 155,127h 308c 94,0 162,86 162,177v 178c 0,109 -50,174 -166,173L 277,653C 158,653 77,762 77,849v 302c 0,118 107,196 180,197l 204,4c 92,0 164,67 164,160v 200c 0,91 -89,163 -188,163H 105"
                />
                <path
                  id="cp-linePath04"
                  d="m 283,173c 2,0 165,0 165,0C 544,175 577,238 577,330v 156c 0,94 -48,126 -140,125L 269,609C 167,602 29,702 29,851v 312c 0,111 101,235 242,235h 162c 109,1 144,49 144,136v 162c 0,73 -53,130 -118,130l -353,1"
                />
              </defs>
              <use href="#cp-linePath01" className="cp-path-01" />
              <use href="#cp-linePath02" className="cp-path-02" />
              <use href="#cp-linePath03" className="cp-path-03" />
              <use href="#cp-linePath04" className="cp-path-04" />
            </svg>

            {/* 4 Exact 300x450 Glassmorphic Gradient Cards */}
            <div className="cp-cards">
              {/* Card 1: Verdict & IP */}
              <div className="cp-card-wrapper">
                <article className="cp-card cp-card-hero">
                  <div className="cp-card-inner">
                    <div>
                      <div className="cp-card-eyebrow">Overview</div>
                      <p className="cp-hero-lead">{takeaway}</p>
                    </div>
                    <div className="cp-hero-facts">
                      <div className="cp-fact-row">
                        <span className="cp-fact-k">IP Address</span>
                        <span className="cp-fact-v">{primaryIp}</span>
                      </div>
                      <div className="cp-fact-row">
                        <span className="cp-fact-k">Status</span>
                        <span className="cp-fact-v">{statusLabel}</span>
                      </div>
                      <div className="cp-fact-row">
                        <span className="cp-fact-k">Risk Score</span>
                        <span className="cp-fact-v" style={{ color: tierTone }}>
                          {activeFinding.score} / 100 · {riskLevelLabel}
                        </span>
                      </div>
                    </div>
                  </div>
                </article>
              </div>

              {/* Card 2: Key Findings */}
              <div className="cp-card-wrapper">
                <article className="cp-card">
                  <div className="cp-card-inner">
                    <div>
                      <div className="cp-card-eyebrow">Key Findings</div>
                      <h4 className="cp-card-heading">What we found</h4>
                    </div>
                    <div className="cp-card-body">
                      {activeFinding.signals.length > 0 ? (
                        <ul className="cp-plain-list">
                          {activeFinding.signals.slice(0, 4).map((s, idx) => (
                            <li key={idx} className="cp-plain-item">
                              <span className="cp-plain-title">{s.label}</span>
                              {s.evidence && (
                                <span className="cp-plain-sub">{s.evidence}</span>
                              )}
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="cp-plain-empty">No suspicious signs detected.</p>
                      )}
                    </div>
                  </div>
                </article>
              </div>

              {/* Card 3: Server & Safety */}
              <div className="cp-card-wrapper">
                <article className="cp-card">
                  <div className="cp-card-inner">
                    <div>
                      <div className="cp-card-eyebrow">Server &amp; Safety</div>
                      <h4 className="cp-card-heading">Where it points</h4>
                    </div>
                    <div className="cp-hero-facts">
                      <div className="cp-fact-row">
                        <span className="cp-fact-k">IP Address</span>
                        <span className="cp-fact-v">{primaryIp}</span>
                      </div>
                      <div className="cp-fact-row">
                        <span className="cp-fact-k">Hosting</span>
                        <span className="cp-fact-v">{hostingLabel}</span>
                      </div>
                      <div className="cp-fact-row">
                        <span className="cp-fact-k">Email Sending</span>
                        <span className="cp-fact-v">{hasMail ? 'Active' : 'None'}</span>
                      </div>
                      <div className="cp-fact-row">
                        <span className="cp-fact-k">Email Protection</span>
                        <span className="cp-fact-v">
                          {liveNow
                            ? hasMailProtection
                              ? 'Protected'
                              : 'Missing'
                            : 'Not active'}
                        </span>
                      </div>
                      <div className="cp-fact-row">
                        <span className="cp-fact-k">Domain Age</span>
                        <span className="cp-fact-v">{domainAgeLabel}</span>
                      </div>
                    </div>
                  </div>
                </article>
              </div>

              {/* Card 4: Next Step */}
              <div className="cp-card-wrapper">
                <article className="cp-card">
                  <div className="cp-card-inner">
                    <div>
                      <div className="cp-card-eyebrow">Next Step</div>
                      <h4 className="cp-card-heading">Recommended action</h4>
                      <p className="cp-plain-copy">{nextStep}</p>
                    </div>
                    <div className="cp-card-cta">
                      {isLiveThreat && currentScanId ? (
                        <button
                          type="button"
                          className="wb-btn-sm"
                          onClick={() => onOpenTakedown(activeFinding.domain)}
                        >
                          <FileWarning size={13} aria-hidden="true" />
                          <span>Create Takedown Notice</span>
                        </button>
                      ) : (
                        <button
                          type="button"
                          className="btn-inline-action"
                          onClick={() => onChangeTab('tab-infra')}
                        >
                          <span>View Server &amp; DNS</span>
                        </button>
                      )}
                    </div>
                  </div>
                </article>
              </div>
            </div>
          </div>
        )}

        {dossierTab === 'tab-infra' && (
          <div className="dossier-stack">
            {currentData?.online_enrich && activeFinding.enrichment ? (
              <>
                <section>
                  <div className="section-title">Live DNS, Registration &amp; SSL</div>
                  <LiveDnsSection enrichment={activeFinding.enrichment} />
                </section>
                <section>
                  <div className="section-title">IP Network Details</div>
                  <LiveIpSection infrastructure={activeFinding.enrichment.infrastructure} />
                </section>
              </>
            ) : (
              <>
                <section>
                  <div className="section-title">IP &amp; Mail Setup</div>
                  <div className="data-grid">
                    <div className="data-block">
                      <div className="data-row">
                        <span className="data-label">IPv4 Address</span>
                        <span>{facts?.a_records.join(', ') || 'None'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">IPv6 Address</span>
                        <span>{facts?.aaaa_records.join(', ') || 'None'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">Mail Servers</span>
                        <span>{facts?.mx_records.join(', ') || 'None'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">Name Servers</span>
                        <span>{facts?.ns_records.join(', ') || 'None'}</span>
                      </div>
                    </div>
                    <div className="data-block">
                      <div className="data-row">
                        <span className="data-label">SPF Protection</span>
                        <span>{facts?.spf ? 'Present' : 'Missing'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">DMARC Protection</span>
                        <span>{facts?.dmarc ? 'Present' : 'Missing'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">Registrar</span>
                        <span>{facts?.registrar || 'Unknown'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">Domain Age</span>
                        <span>
                          {facts?.created_days_ago != null
                            ? `${facts.created_days_ago} days`
                            : 'Unknown'}
                        </span>
                      </div>
                    </div>
                  </div>
                </section>

                <section>
                  <div className="section-title">SSL Padlock Certificate</div>
                  <div className="data-grid">
                    <div className="data-block">
                      <div className="data-row">
                        <span className="data-label">Issuer</span>
                        <span>{facts?.tls_issuer || 'None'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">Issued To</span>
                        <span>{facts?.tls_subject || 'None'}</span>
                      </div>
                    </div>
                    <div className="data-block">
                      <div className="data-row">
                        <span className="data-label">Valid From</span>
                        <span>
                          {facts?.tls_not_before && facts.tls_not_before !== 'N/A'
                            ? facts.tls_not_before.slice(0, 10)
                            : 'N/A'}
                        </span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">Valid Until</span>
                        <span>
                          {facts?.tls_not_after && facts.tls_not_after !== 'N/A'
                            ? facts.tls_not_after.slice(0, 10)
                            : 'N/A'}
                        </span>
                      </div>
                    </div>
                  </div>
                </section>

                <section>
                  <div className="section-title">Hosting Provider</div>
                  <div className="data-grid">
                    <div className="data-block">
                      <div className="data-row">
                        <span className="data-label">Provider</span>
                        <span>{facts?.asn_org || 'Unknown'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">Country</span>
                        <span>{facts?.country || 'Unknown'}</span>
                      </div>
                    </div>
                    <div className="data-block">
                      <div className="data-row">
                        <span className="data-label">Server Role</span>
                        <span>{facts?.infra_role || 'None'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">Abuse Contact</span>
                        <span>{facts?.abuse_contact || 'Unavailable'}</span>
                      </div>
                    </div>
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
                Page similarity and change history are checked in standard scan mode.
              </p>
            ) : activeFinding.dna ? (
              <>
                <section>
                  <div className="section-title">Brand Similarity</div>
                  <div className="data-grid">
                    <div className="data-block">
                      <div className="data-row">
                        <span className="data-label">Page Similarity</span>
                        <strong>{activeFinding.dna.similarity_pct}%</strong>
                      </div>
                      <div className="data-row">
                        <span className="data-label">Uses Brand Logo</span>
                        <span>{activeFinding.dna.logo_match ? 'Yes' : 'No'}</span>
                      </div>
                    </div>
                    <div className="data-block">
                      <div className="data-row">
                        <span className="data-label">Login Form Found</span>
                        <span>{activeFinding.dna.login_form ? 'Yes' : 'No'}</span>
                      </div>
                      <div className="data-row">
                        <span className="data-label">Visual Clone</span>
                        <span>{activeFinding.dna.visual_match ? 'Yes' : 'No'}</span>
                      </div>
                    </div>
                  </div>
                  <div className="dna-phrases-row">
                    Matched text: {activeFinding.dna.matched_phrases.join(', ')}
                  </div>
                </section>

                <section>
                  <div className="section-title">Recent Changes</div>
                  {activeFinding.drift && activeFinding.drift_data ? (
                    <div className="drift-box">
                      <div className="drift-step-label">Earlier Scan</div>
                      <div className="drift-step-val">{activeFinding.drift_data.before}</div>
                      <div className="drift-step-label" style={{ marginTop: 14 }}>
                        Latest Scan
                      </div>
                      <div className="drift-step-val" style={{ color: 'var(--crit)' }}>
                        {activeFinding.drift_data.after}
                      </div>
                    </div>
                  ) : (
                    <p className="quiet-note">No sudden changes detected for this domain.</p>
                  )}
                </section>
              </>
            ) : (
              <p className="quiet-note">No active web page or brand clone signs found.</p>
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
                    Create Takedown Notice
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
                  No takedown needed right now. This domain shows low risk.
                </div>
              )}
            </section>

            <section>
              {currentData?.online_enrich && activeFinding.enrichment ? (
                <>
                  <div className="section-title">Threat Reputation</div>
                  <LiveReputationSection reputation={activeFinding.enrichment.reputation} />
                </>
              ) : (
                <>
                  <div className="section-title">Reports &amp; Feeds</div>
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
                          </div>
                          <div className="news-title">{n.title}</div>
                          <div className="news-summary">{n.summary}</div>
                          <div className="news-meta">
                            <span>{n.date.slice(0, 10)}</span>
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
                    <p className="quiet-note">No external threat reports found.</p>
                  )}
                </>
              )}
            </section>

            <section>
              <div className="section-title">Quick Lookup Links</div>
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
