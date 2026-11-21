import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ArrowUp, Search, X } from 'lucide-react';
import type {
  FindingDto,
  GeoPointDto,
  ScanProgressDto,
  ScanResultsDto,
} from '../types/proteus-api.ts';
import { DossierPane, type DossierTab } from './workbench/DossierPane.tsx';
import {
  DomainWithConfusables,
  formatTechnique,
  importanceClass,
  LiveDnsSection,
  LiveIpSection,
  LiveReputationSection,
  safeExternalUrl,
  triggerUrlDownload,
} from './workbench/shared.tsx';
import { TakedownModal } from './workbench/TakedownModal.tsx';
import { WorldThreatMap } from './workbench/WorldThreatMap.tsx';

type MainView = 'view-triage' | 'view-constellation' | 'view-osint' | 'view-history';
type MapTab = 'geo' | 'clusters' | 'matrix';
type FilterMode = 'ALL' | 'CRITICAL' | 'HIGH' | 'LIVE' | 'DRIFT' | 'PRECRIME';

const FILTER_OPTIONS: Array<{ id: FilterMode; label: string }> = [
  { id: 'ALL', label: 'All' },
  { id: 'CRITICAL', label: 'Critical' },
  { id: 'HIGH', label: 'High' },
  { id: 'LIVE', label: 'Live' },
  { id: 'DRIFT', label: 'Drift' },
  { id: 'PRECRIME', label: 'PreCrime' },
];

const QUICK_BRAND_PRESETS = ['acmecorp.com', 'pashabank.az'] as const;

export interface ExternalBrandScanRequest {
  brand: string;
  nonce: number;
}

interface ProteusWorkbenchProps {
  onBackTo3D?: () => void;
  externalBrandRequest?: ExternalBrandScanRequest | null;
}

export function ProteusWorkbench({
  onBackTo3D,
  externalBrandRequest,
}: ProteusWorkbenchProps) {
  const [brandInput, setBrandInput] = useState<string>('acmecorp.com');
  const [scanPass, setScanPass] = useState<1 | 2>(1);
  const [onlineEnrich, setOnlineEnrich] = useState<boolean>(false);

  const [activeView, setActiveView] = useState<MainView>('view-triage');
  const [activeFilter, setActiveFilter] = useState<FilterMode>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [dossierTab, setDossierTab] = useState<DossierTab>('tab-overview');
  const [mapTab, setMapTab] = useState<MapTab>('geo');

  const [scanning, setScanning] = useState<boolean>(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [progress, setProgress] = useState<ScanProgressDto | null>(null);
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);
  const [currentData, setCurrentData] = useState<ScanResultsDto | null>(null);

  const [selectedDomain, setSelectedDomain] = useState<string | null>(null);
  const [activeOsintDomain, setActiveOsintDomain] = useState<string | null>(null);
  const [inspectedCountry, setInspectedCountry] = useState<GeoPointDto | null>(null);

  const [modalOpen, setModalOpen] = useState<boolean>(false);
  const [modalDomain, setModalDomain] = useState<string | null>(null);
  const [takedownChannel, setTakedownChannel] = useState<string>('Domain Registrar');
  const [reportText, setReportText] = useState<string>('');
  const [copiedNote, setCopiedNote] = useState<boolean>(false);

  const pollTimerRef = useRef<number | null>(null);
  const mountedRef = useRef<boolean>(true);
  const lastLoadedBrandRef = useRef<string>('acmecorp.com');

  const clearPoll = useCallback(() => {
    if (pollTimerRef.current !== null) {
      window.clearInterval(pollTimerRef.current);
      pollTimerRef.current = null;
    }
  }, []);

  const executeScan = useCallback(
    async (brandValue: string, passValue: 1 | 2, onlineValue: boolean) => {
      clearPoll();
      setScanning(true);
      setScanError(null);
      setSearchQuery('');
      setInspectedCountry(null);
      setProgress({
        scan_id: '',
        status: 'pending',
        progress_pct: 0,
        current_step: 'initializing scan',
        domains_total: 0,
        domains_processed: 0,
        findings_so_far: 0,
      });

      const targetBrand = brandValue.trim() || 'acmecorp.com';
      lastLoadedBrandRef.current = targetBrand.toLowerCase();

      try {
        const res = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            brand: targetBrand,
            scan_pass: passValue,
            online_enrich: onlineValue,
            inspect_websites: false,
          }),
        });

        if (!res.ok) {
          const text = await res.text();
          throw new Error(`HTTP ${res.status} — ${text.slice(0, 200)}`);
        }

        const startData = (await res.json()) as { scan_id: string };
        if (!mountedRef.current) return;
        const scanId = startData.scan_id;
        setCurrentScanId(scanId);

        await new Promise<void>((resolve, reject) => {
          const pollOnce = async () => {
            try {
              const sRes = await fetch(`/api/scan/${scanId}/status`);
              if (!sRes.ok) {
                const text = await sRes.text();
                throw new Error(`HTTP ${sRes.status} — ${text.slice(0, 200)}`);
              }
              const st = (await sRes.json()) as ScanProgressDto;
              if (!mountedRef.current) return;
              setProgress(st);
              if (st.status === 'complete') {
                clearPoll();
                resolve();
              } else if (st.status === 'failed') {
                clearPoll();
                reject(new Error(st.error || 'Scan failed'));
              }
            } catch (err) {
              clearPoll();
              reject(err);
            }
          };

          void pollOnce();
          pollTimerRef.current = window.setInterval(() => {
            void pollOnce();
          }, 350);
        });

        const resultsRes = await fetch(`/api/scan/${scanId}/results`);
        if (!resultsRes.ok) {
          const text = await resultsRes.text();
          throw new Error(`HTTP ${resultsRes.status} — ${text.slice(0, 200)}`);
        }
        const results = (await resultsRes.json()) as ScanResultsDto;
        if (!mountedRef.current) return;

        setCurrentData(results);
        setProgress(null);
        const firstDomain = results.findings[0]?.domain ?? null;
        setSelectedDomain(firstDomain);
        setActiveOsintDomain(firstDomain);
        setDossierTab('tab-overview');
      } catch (err) {
        if (!mountedRef.current) return;
        setProgress(null);
        setScanError(err instanceof Error ? err.message : 'Scan failed');
      } finally {
        clearPoll();
        if (mountedRef.current) setScanning(false);
      }
    },
    [clearPoll]
  );

  useEffect(() => {
    mountedRef.current = true;
    void executeScan('acmecorp.com', 1, false);
    return () => {
      mountedRef.current = false;
      clearPoll();
    };
  }, [executeScan, clearPoll]);

  useEffect(() => {
    if (!externalBrandRequest || externalBrandRequest.nonce === 0) return;
    const requested = externalBrandRequest.brand.trim().toLowerCase();
    if (!requested) return;
    setBrandInput(requested);
    if (requested !== lastLoadedBrandRef.current) {
      setActiveFilter('ALL');
      void executeScan(requested, scanPass, onlineEnrich);
    }
  }, [externalBrandRequest, executeScan, scanPass, onlineEnrich]);

  const findings = currentData?.findings ?? [];

  const filterCounts = useMemo<Record<FilterMode, number>>(() => {
    let critical = 0;
    let high = 0;
    let live = 0;
    let drift = 0;
    let precrime = 0;

    for (const f of findings) {
      if (f.tier === 'CRITICAL') critical += 1;
      else if (f.tier === 'HIGH') high += 1;

      if (f.status === 'LIVE INFRA') live += 1;
      else if (f.status === 'DRIFT DETECTED') drift += 1;
      else if (f.status === 'PRECRIME') precrime += 1;
    }

    return {
      ALL: findings.length,
      CRITICAL: critical,
      HIGH: high,
      LIVE: live,
      DRIFT: drift,
      PRECRIME: precrime,
    };
  }, [findings]);

  const filteredFindings = useMemo(() => {
    let items = findings;
    if (activeFilter !== 'ALL') {
      if (activeFilter === 'LIVE') {
        items = items.filter((f) => f.status === 'LIVE INFRA');
      } else if (activeFilter === 'DRIFT') {
        items = items.filter((f) => f.status === 'DRIFT DETECTED');
      } else if (activeFilter === 'PRECRIME') {
        items = items.filter((f) => f.status === 'PRECRIME');
      } else {
        items = items.filter((f) => f.tier === activeFilter);
      }
    }
    const q = searchQuery.trim().toLowerCase();
    if (q) {
      items = items.filter((f) => {
        const tech = f.candidate?.technique ?? '';
        const techHuman = formatTechnique(tech).toLowerCase();
        return (
          f.domain.toLowerCase().includes(q) ||
          f.candidate.ascii_form.toLowerCase().includes(q) ||
          tech.toLowerCase().includes(q) ||
          techHuman.includes(q)
        );
      });
    }
    return items;
  }, [findings, activeFilter, searchQuery]);

  const activeFinding = useMemo(() => {
    if (!findings.length) return null;
    return findings.find((f) => f.domain === selectedDomain) ?? findings[0];
  }, [findings, selectedDomain]);

  const osintTarget = useMemo(() => {
    if (!findings.length) return null;
    return findings.find((f) => f.domain === activeOsintDomain) ?? findings[0];
  }, [findings, activeOsintDomain]);

  const liveThreatsCount = useMemo(
    () =>
      findings.filter(
        (f) => f.status === 'LIVE INFRA' || f.status === 'DRIFT DETECTED'
      ).length,
    [findings]
  );

  const driftOrPrecrimeCount = useMemo(
    () => findings.filter((f) => f.drift || f.precrime !== null).length,
    [findings]
  );

  const driftFindings = useMemo(() => findings.filter((f) => f.drift), [findings]);
  const precrimeFindings = useMemo(
    () => findings.filter((f) => f.precrime !== null && !f.drift),
    [findings]
  );

  const fetchTakedown = useCallback(
    async (domain: string, channel: string) => {
      if (!currentScanId) return;
      try {
        const res = await fetch(
          `/api/takedown/${encodeURIComponent(domain)}?channel=${encodeURIComponent(channel)}&scan_id=${currentScanId}`
        );
        const data = (await res.json()) as { report?: string; error?: string };
        if (data.error) {
          setReportText(data.error);
          return;
        }
        setReportText(data.report ?? '');
      } catch (err) {
        setReportText(
          `Failed to fetch report: ${err instanceof Error ? err.message : 'Unknown error'}`
        );
      }
    },
    [currentScanId]
  );

  const openTakedown = (domain: string) => {
    setModalDomain(domain);
    setSelectedDomain(domain);
    setCopiedNote(false);
    setModalOpen(true);
    void fetchTakedown(domain, takedownChannel);
  };

  const handleChannelChange = (channel: string) => {
    setTakedownChannel(channel);
    if (modalDomain) {
      void fetchTakedown(modalDomain, channel);
    }
  };

  const copyReport = async () => {
    if (!reportText) return;
    try {
      await navigator.clipboard.writeText(reportText);
      setCopiedNote(true);
      window.setTimeout(() => setCopiedNote(false), 1800);
    } catch {
      // Clipboard API may be restricted
    }
  };

  const downloadTakedownTxt = () => {
    if (!reportText) return;
    const blob = new Blob([reportText], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    triggerUrlDownload(url, `proteus_takedown_${modalDomain || 'report'}.txt`);
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const selectFindingFromAnywhere = (f: FindingDto, switchToTriage = false) => {
    setSelectedDomain(f.domain);
    setActiveOsintDomain(f.domain);
    if (switchToTriage) {
      setActiveView('view-triage');
    }
  };

  const jumpToDomainByName = (domainName: string) => {
    const match = findings.find(
      (f) => f.domain === domainName || f.candidate.ascii_form === domainName
    );
    if (match) {
      selectFindingFromAnywhere(match, true);
      setDossierTab('tab-overview');
    }
  };

  const handleListKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (!filteredFindings.length) return;
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    e.preventDefault();
    const curIdx = filteredFindings.findIndex((f) => f.domain === activeFinding?.domain);
    const nextIdx =
      e.key === 'ArrowDown'
        ? Math.min(filteredFindings.length - 1, curIdx + 1)
        : Math.max(0, curIdx <= 0 ? 0 : curIdx - 1);
    const target = filteredFindings[nextIdx];
    if (target) selectFindingFromAnywhere(target);
  };

  const runPresetBrand = (preset: string) => {
    setBrandInput(preset);
    setActiveFilter('ALL');
    if (!scanning) {
      void executeScan(preset, scanPass, onlineEnrich);
    }
  };

  const triggerDriftCheck = () => {
    setScanPass(2);
    if (!scanning) {
      void executeScan(brandInput, 2, onlineEnrich);
    }
  };

  return (
    <section id="proteus-workbench" aria-label="PROTEUS — Threat Intelligence Workbench">
      <div className="wb-shell">
        {/* Minimal Executive Header */}
        <header className="wb-hero-head">
          <div className="wb-head-top">
            <span className="wb-eyebrow">THREAT INTELLIGENCE SUITE</span>
            {onBackTo3D && (
              <button type="button" className="btn-back-3d" onClick={onBackTo3D}>
                <ArrowUp size={12} aria-hidden="true" />
                <span>3D Pipeline</span>
              </button>
            )}
          </div>
          <h2 className="wb-title">Protect what you own.</h2>
          <p className="wb-subtitle">
            Scan any domain to uncover impersonation infrastructure, map global threat clusters, and trigger takedowns.
          </p>
        </header>

        {/* Single Hero Search & Scan Bar */}
        <div className="wb-search-hero">
          <Search size={17} className="wb-search-hero-icon" aria-hidden="true" />
          <input
            type="text"
            id="brand-input"
            aria-label="Target brand domain"
            placeholder="Enter a target domain (e.g. acmecorp.com or pashabank.az)"
            value={brandInput}
            onChange={(e) => setBrandInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !scanning) {
                void executeScan(brandInput, scanPass, onlineEnrich);
              }
            }}
          />
          <button
            type="button"
            id="scan-btn"
            className="wb-btn"
            disabled={scanning}
            onClick={() => void executeScan(brandInput, scanPass, onlineEnrich)}
          >
            {scanning ? 'Scanning…' : 'Run Scan'}
          </button>
        </div>

        {/* Quiet Sub-Controls Bar */}
        <div className="wb-subcontrols">
          <div className="wb-subcontrols-left">
            <div className="preset-group" role="group" aria-label="Fixture brand presets">
              <span className="subcontrol-label">Samples</span>
              {QUICK_BRAND_PRESETS.map((preset) => {
                const isCurrent =
                  (currentData?.brand.toLowerCase() ?? brandInput.trim().toLowerCase()) ===
                  preset;
                return (
                  <button
                    key={preset}
                    type="button"
                    disabled={scanning}
                    className={`preset-btn ${isCurrent ? 'active' : ''}`}
                    onClick={() => runPresetBrand(preset)}
                  >
                    {preset}
                  </button>
                );
              })}
            </div>

            <span className="subcontrol-sep" aria-hidden="true" />

            <div className="pass-segment" role="group" aria-label="Scan pass mode">
              <button
                type="button"
                className={`pass-seg-btn ${scanPass === 1 ? 'active' : ''}`}
                onClick={() => setScanPass(1)}
              >
                Baseline
              </button>
              <button
                type="button"
                className={`pass-seg-btn ${scanPass === 2 ? 'active' : ''}`}
                onClick={() => setScanPass(2)}
              >
                Drift Check
              </button>
            </div>

            <span className="subcontrol-sep" aria-hidden="true" />

            <label
              className="toggle-switch"
              title="Query live public DNS, RDAP, and crt.sh Certificate Transparency"
            >
              <input
                type="checkbox"
                id="online-toggle"
                checked={onlineEnrich}
                onChange={(e) => setOnlineEnrich(e.target.checked)}
              />
              <span>Live DNS &amp; RDAP</span>
            </label>
          </div>

          <div className="export-controls">
            <button
              type="button"
              className="btn-outline"
              disabled={!currentScanId || !currentData}
              onClick={() => {
                if (!currentScanId) return;
                triggerUrlDownload(
                  `/api/export/csv?scan_id=${currentScanId}`,
                  `proteus_triage_${currentScanId}.csv`
                );
              }}
            >
              CSV
            </button>
            <button
              type="button"
              className="btn-outline"
              disabled={!currentScanId || !currentData}
              onClick={() => {
                if (!currentScanId) return;
                triggerUrlDownload(
                  `/api/export/json?scan_id=${currentScanId}`,
                  `proteus_triage_${currentScanId}.json`
                );
              }}
            >
              JSON
            </button>
            <button
              type="button"
              className="btn-outline"
              disabled={!currentScanId || !activeFinding}
              onClick={() => {
                if (!currentScanId || !activeFinding) return;
                triggerUrlDownload(
                  `/api/export/misp/${encodeURIComponent(activeFinding.domain)}?scan_id=${currentScanId}`
                );
              }}
            >
              MISP
            </button>
          </div>
        </div>

        {/* Live Progress Bar */}
        {progress && (
          <div id="scan-progress" className="scan-progress" aria-live="polite">
            <div className="scan-progress-meta">
              <span id="progress-step">{progress.current_step}</span>
              <span id="progress-counts">
                {progress.domains_processed}/{progress.domains_total} domains ·{' '}
                {progress.findings_so_far} findings ({progress.progress_pct}%)
              </span>
            </div>
            <div className="scan-progress-track">
              <div
                id="progress-bar"
                className="scan-progress-fill"
                style={{ width: `${Math.min(100, progress.progress_pct)}%` }}
              />
            </div>
          </div>
        )}

        {/* Quiet 4-Stat Typographic Strip */}
        {currentData && (
          <div className="kpi-bar" id="kpi-bar">
            <div className="kpi-box">
              <span className="kpi-label">Target Domain</span>
              <span className="kpi-value kpi-target" title={currentData.brand}>
                {currentData.brand}
              </span>
            </div>
            <div className="kpi-box">
              <span className="kpi-label">Permutations</span>
              <span className="kpi-value">{currentData.generated}</span>
            </div>
            <div className="kpi-box">
              <span className="kpi-label">Live Threats</span>
              <span
                className="kpi-value"
                style={{ color: liveThreatsCount > 0 ? 'var(--crit)' : '#f3f4f8' }}
              >
                {liveThreatsCount}
              </span>
            </div>
            <div className="kpi-box">
              <span className="kpi-label">Clusters · Saved</span>
              <span className="kpi-value">
                {currentData.clusters.length}
                <span className="kpi-value-sub">
                  {' '}
                  · {currentData.impact.triage_hours} hrs
                </span>
              </span>
            </div>
          </div>
        )}

        {/* Unified Minimalist Workspace */}
        <div className="wb-frame">
          <nav className="topbar" aria-label="Workbench navigation">
            <div className="nav-links" role="tablist" aria-label="Workbench Views">
              <button
                type="button"
                role="tab"
                aria-selected={activeView === 'view-triage'}
                className={`nav-tab ${activeView === 'view-triage' ? 'active' : ''}`}
                onClick={() => setActiveView('view-triage')}
              >
                Triage ({findings.length})
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={activeView === 'view-constellation'}
                className={`nav-tab ${activeView === 'view-constellation' ? 'active' : ''}`}
                onClick={() => setActiveView('view-constellation')}
              >
                Threat Map ({currentData?.geo.length ?? 0})
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={activeView === 'view-osint'}
                className={`nav-tab ${activeView === 'view-osint' ? 'active' : ''}`}
                onClick={() => setActiveView('view-osint')}
              >
                OSINT Matrix
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={activeView === 'view-history'}
                className={`nav-tab ${activeView === 'view-history' ? 'active' : ''}`}
                onClick={() => setActiveView('view-history')}
              >
                Drift &amp; PreCrime
                {driftOrPrecrimeCount > 0 ? ` (${driftOrPrecrimeCount})` : ''}
              </button>
            </div>

            {currentData && (
              <div className="topbar-status">
                {currentData.scan_pass === 2 ? 'Pass #2 · Drift Active' : 'Pass #1 · Baseline'}
              </div>
            )}
          </nav>

          {/* Main View Body */}
          <div className="wb-container">
            {/* VIEW 1: TRIAGE & DOSSIER */}
            {activeView === 'view-triage' && (
              <div id="view-triage" className="view active">
                <div className="split-layout">
                  {/* Left List Pane */}
                  <div className="list-pane">
                    <div className="filter-bar" id="filter-pills">
                      {FILTER_OPTIONS.map((flt) => (
                        <button
                          key={flt.id}
                          type="button"
                          className={`filter-tab ${activeFilter === flt.id ? 'active' : ''}`}
                          onClick={() => setActiveFilter(flt.id)}
                        >
                          <span>{flt.label}</span>
                          <span className="filter-tab-count">{filterCounts[flt.id]}</span>
                        </button>
                      ))}
                    </div>

                    <div className="search-bar">
                      <div className="search-input-wrap">
                        <input
                          type="text"
                          id="search-input"
                          aria-label="Filter domains or techniques"
                          placeholder="Filter domains or techniques…"
                          value={searchQuery}
                          onChange={(e) => setSearchQuery(e.target.value)}
                        />
                        {searchQuery && (
                          <button
                            type="button"
                            className="search-clear-btn"
                            aria-label="Clear filter"
                            onClick={() => setSearchQuery('')}
                          >
                            <X size={13} aria-hidden="true" />
                          </button>
                        )}
                      </div>
                    </div>

                    <div
                      id="findings-list"
                      role="listbox"
                      aria-label="Triaged domains"
                      tabIndex={0}
                      onKeyDown={handleListKeyDown}
                    >
                      {scanError ? (
                        <div className="empty-state" style={{ color: 'var(--crit)' }}>
                          Error: {scanError}
                        </div>
                      ) : !currentData ? (
                        <div className="empty-state">Running baseline scan…</div>
                      ) : filteredFindings.length === 0 ? (
                        <div className="empty-state">No findings match this filter.</div>
                      ) : (
                        filteredFindings.map((f) => {
                          const dotClass =
                            f.status === 'DRIFT DETECTED'
                              ? 'dot-drift'
                              : f.status === 'LIVE INFRA'
                                ? 'dot-live'
                                : f.status === 'PRECRIME'
                                  ? 'dot-precrime'
                                  : 'dot-mute';
                          const techLabel = formatTechnique(f.candidate.technique);
                          const isActive = activeFinding?.domain === f.domain;
                          return (
                            <div
                              key={f.domain + '|' + f.candidate.rule}
                              role="option"
                              aria-selected={isActive}
                              className={`finding-row tier-${f.tier} ${isActive ? 'active' : ''}`}
                              onClick={() => selectFindingFromAnywhere(f)}
                            >
                              <div className="f-row-left">
                                <span className="f-domain">
                                  <DomainWithConfusables domain={f.domain} />
                                </span>
                                <div className="f-subrow">
                                  <span className="f-status-inline">
                                    <i className={`status-dot ${dotClass}`} aria-hidden="true" />
                                    <span>{f.status}</span>
                                  </span>
                                  <span aria-hidden="true">·</span>
                                  <span className="sub-label">{techLabel}</span>
                                </div>
                              </div>
                              <span className="f-score">{f.score}</span>
                            </div>
                          );
                        })
                      )}
                    </div>
                  </div>

                  {/* Right Dossier Pane */}
                  <DossierPane
                    activeFinding={activeFinding}
                    currentData={currentData}
                    currentScanId={currentScanId}
                    scanning={scanning}
                    scanError={scanError}
                    dossierTab={dossierTab}
                    onChangeTab={setDossierTab}
                    onOpenTakedown={openTakedown}
                  />
                </div>
              </div>
            )}

            {/* VIEW 2: THREAT MAP & INFRASTRUCTURE */}
            {activeView === 'view-constellation' && (
              <div id="view-constellation" className="view active">
                <div className="map-tabs" role="tablist" aria-label="Infrastructure Views">
                  {(
                    [
                      ['geo', `Global Map (${currentData?.geo.length ?? 0})`],
                      ['clusters', `Campaign Clusters (${currentData?.clusters.length ?? 0})`],
                      ['matrix', 'IP & ASN Matrix'],
                    ] as Array<[MapTab, string]>
                  ).map(([tab, label]) => (
                    <button
                      key={tab}
                      type="button"
                      role="tab"
                      aria-selected={mapTab === tab}
                      className={`map-tab ${mapTab === tab ? 'active' : ''}`}
                      onClick={() => setMapTab(tab)}
                    >
                      {label}
                    </button>
                  ))}
                </div>

                <div className="map-content">
                  {mapTab === 'geo' && (
                    <WorldThreatMap
                      geo={currentData?.geo ?? []}
                      inspectedCountry={inspectedCountry}
                      onSelectCountry={setInspectedCountry}
                      onSelectDomain={jumpToDomainByName}
                    />
                  )}

                  {mapTab === 'clusters' && (
                    <div id="map-clusters" className="map-pane active">
                      <div id="clusters-container" className="clusters-grid">
                        {!currentData || currentData.clusters.length === 0 ? (
                          <div className="empty-state" style={{ gridColumn: '1 / -1' }}>
                            No shared infrastructure clusters detected.
                          </div>
                        ) : (
                          currentData.clusters.map((c) => (
                            <div key={c.ip + c.asn} className="cluster-card">
                              <div className="cluster-header">
                                <div>
                                  <div className="cluster-ip">{c.ip}</div>
                                  <div className="cluster-meta">
                                    {c.asn} · {c.org}
                                  </div>
                                  <div className="cluster-meta">
                                    {c.country} · {c.role}
                                  </div>
                                </div>
                                <div className="cluster-conf">
                                  {c.confidence}%
                                  <br />
                                  confidence
                                </div>
                              </div>
                              <div className="cluster-count-line">
                                {c.members.length} domains · {c.threats} threats
                              </div>
                              {c.members.map((m) => (
                                <button
                                  key={m.domain}
                                  type="button"
                                  className="cluster-member cluster-member-btn"
                                  onClick={() => jumpToDomainByName(m.domain)}
                                >
                                  <span>
                                    <DomainWithConfusables domain={m.domain} />
                                  </span>
                                  <span
                                    style={{
                                      fontVariantNumeric: 'tabular-nums',
                                      color:
                                        m.tier === 'CRITICAL'
                                          ? 'var(--crit)'
                                          : m.tier === 'HIGH'
                                            ? 'var(--high)'
                                            : 'var(--text-mute)',
                                    }}
                                  >
                                    {m.score}
                                  </span>
                                </button>
                              ))}
                              <div className="cluster-caveat">{c.caveat}</div>
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  )}

                  {mapTab === 'matrix' && (
                    <div id="map-matrix" className="map-pane active">
                      <div style={{ padding: 24, overflowY: 'auto' }}>
                        <table className="data-table" id="ip-table">
                          <thead>
                            <tr>
                              <th>IP Address</th>
                              <th>ASN</th>
                              <th>Org</th>
                              <th>Country</th>
                              <th>Role</th>
                              <th>Connected Domains</th>
                            </tr>
                          </thead>
                          <tbody>
                            {!currentData || currentData.clusters.length === 0 ? (
                              <tr>
                                <td
                                  colSpan={6}
                                  style={{
                                    textAlign: 'center',
                                    color: 'var(--text-mute)',
                                    padding: 32,
                                  }}
                                >
                                  No shared infrastructure detected.
                                </td>
                              </tr>
                            ) : (
                              currentData.clusters.map((c) => (
                                <tr key={c.ip + c.asn}>
                                  <td style={{ color: 'var(--accent-text)' }}>{c.ip}</td>
                                  <td>{c.asn}</td>
                                  <td>{c.org}</td>
                                  <td>{c.country}</td>
                                  <td>{c.role}</td>
                                  <td>
                                    <div className="matrix-domain-links">
                                      {c.members.map((m) => (
                                        <button
                                          key={m.domain}
                                          type="button"
                                          className="matrix-domain-chip"
                                          onClick={() => jumpToDomainByName(m.domain)}
                                        >
                                          {m.domain}
                                        </button>
                                      ))}
                                    </div>
                                  </td>
                                </tr>
                              ))
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* VIEW 3: OSINT MATRIX */}
            {activeView === 'view-osint' && (
              <div id="view-osint" className="view active">
                <div className="view-scroll-pad">
                  <h3 className="view-heading">OSINT Source Matrix</h3>
                  <p className="view-subhead">
                    Source-to-indicator mapping across registration, DNS history, reputation, and hosting infrastructure.
                  </p>

                  {!osintTarget ? (
                    <div className="empty-state">
                      Run a scan first to populate the OSINT matrix.
                    </div>
                  ) : (
                    <>
                      <div className="osint-selector-row">
                        <label
                          htmlFor="osint-domain-select"
                          style={{ color: 'var(--text-dim)', fontSize: 12 }}
                        >
                          Inspecting:
                        </label>
                        <select
                          id="osint-domain-select"
                          value={osintTarget.domain}
                          onChange={(e) => setActiveOsintDomain(e.target.value)}
                        >
                          {findings.slice(0, 40).map((f) => (
                            <option key={f.domain} value={f.domain}>
                              {f.domain} · {f.tier} ({f.score})
                            </option>
                          ))}
                        </select>
                        <span className="badge" style={{ fontVariantNumeric: 'tabular-nums' }}>
                          {osintTarget.tier} · {osintTarget.score}/100 ·{' '}
                          {formatTechnique(osintTarget.candidate.technique)}
                        </span>
                        <button
                          type="button"
                          className="btn-inline-action"
                          onClick={() => selectFindingFromAnywhere(osintTarget, true)}
                        >
                          Open in Triage ↗
                        </button>
                      </div>

                      {currentData?.online_enrich && osintTarget.enrichment ? (
                        <div className="dossier-stack">
                          <LiveReputationSection
                            reputation={osintTarget.enrichment.reputation}
                          />
                          <LiveDnsSection enrichment={osintTarget.enrichment} />
                          <LiveIpSection
                            infrastructure={osintTarget.enrichment.infrastructure}
                          />
                        </div>
                      ) : (
                        <>
                          <div className="osint-conclusions">
                            <div
                              className="osint-section-title"
                              style={{ marginBottom: 12 }}
                            >
                              Discovery Matrix Conclusions
                            </div>
                            {Object.entries(
                              osintTarget.osint_matrix.conclusions ?? {}
                            ).map(([k, v]) => (
                              <div key={k} className="conclusion-item">
                                <span className="conclusion-key">
                                  {formatTechnique(k)}
                                </span>
                                <span className="conclusion-val">{v}</span>
                              </div>
                            ))}
                          </div>

                          {(osintTarget.osint_matrix.sections ?? []).map((sec) => (
                            <div key={sec.category} className="osint-section">
                              <div className="osint-section-head">
                                <div className="osint-section-title">{sec.category}</div>
                                <span
                                  className={`relevance rel-${sec.relevance
                                    .toLowerCase()
                                    .replace(/[^a-z]/g, '')}`}
                                >
                                  Relevance: {sec.relevance}
                                </span>
                              </div>
                              <div className="osint-sources">
                                {sec.sources.map((s) => {
                                  const href = safeExternalUrl(s.link);
                                  return (
                                    <div key={s.name} className="osint-source-row">
                                      <div className="osint-source-name">
                                        <span>{s.name}</span>
                                        <span className="news-badge">{s.tag}</span>
                                      </div>
                                      <div className="osint-source-conclusion">
                                        {s.conclusion}
                                      </div>
                                      {href ? (
                                        <a
                                          className="intel-link"
                                          href={href}
                                          target="_blank"
                                          rel="noopener noreferrer"
                                        >
                                          Open ↗
                                        </a>
                                      ) : (
                                        <span
                                          className="intel-link"
                                          style={{ color: 'var(--text-mute)' }}
                                        >
                                          —
                                        </span>
                                      )}
                                    </div>
                                  );
                                })}
                              </div>
                            </div>
                          ))}
                        </>
                      )}
                    </>
                  )}
                </div>
              </div>
            )}

            {/* VIEW 4: DRIFT & PRECRIME */}
            {activeView === 'view-history' && (
              <div id="view-history" className="view active">
                <div className="view-scroll-pad">
                  <div className="history-head-row">
                    <div>
                      <h3 className="view-heading">Drift &amp; PreCrime Staging</h3>
                      <p className="view-subhead" style={{ marginBottom: 0 }}>
                        Early pre-weaponization staging candidates and verified infrastructure drift across passes.
                      </p>
                    </div>
                    {currentData?.scan_pass !== 2 && (
                      <button
                        type="button"
                        className="wb-btn"
                        disabled={scanning}
                        onClick={triggerDriftCheck}
                      >
                        Run Scan #2 (Drift Check)
                      </button>
                    )}
                  </div>

                  <div id="drift-matrix" className="matrix-grid">
                    {driftFindings.length === 0 && precrimeFindings.length === 0 ? (
                      <div className="empty-state" style={{ gridColumn: '1 / -1' }}>
                        <p style={{ marginBottom: 14 }}>
                          No drift or PreCrime alerts in this baseline pass.
                        </p>
                        <button
                          type="button"
                          className="wb-btn"
                          disabled={scanning}
                          onClick={triggerDriftCheck}
                        >
                          Run Scan #2 (Drift Check)
                        </button>
                      </div>
                    ) : (
                      <>
                        {driftFindings.map((f) => (
                          <div
                            key={`drift-${f.domain}`}
                            className="matrix-card"
                            role="button"
                            tabIndex={0}
                            onClick={() => selectFindingFromAnywhere(f, true)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter' || e.key === ' ') {
                                e.preventDefault();
                                selectFindingFromAnywhere(f, true);
                              }
                            }}
                          >
                            <div className="matrix-card-top">
                              <div className="f-domain" style={{ fontSize: 15 }}>
                                <DomainWithConfusables domain={f.domain} />
                              </div>
                              <span className="badge drift">DRIFT</span>
                            </div>
                            <div
                              className={`technique-tag ${importanceClass(
                                f.candidate.importance
                              )}`}
                              style={{ marginBottom: 14 }}
                            >
                              {formatTechnique(f.candidate.technique)} ·{' '}
                              {f.candidate.importance} ({f.candidate.weight}/100)
                            </div>
                            <div className="drift-step-label">Scan #1</div>
                            <div className="drift-step-val" style={{ marginBottom: 10 }}>
                              {f.drift_data?.before || 'N/A'}
                            </div>
                            <div className="drift-step-label">Scan #2</div>
                            <div className="drift-step-val" style={{ color: 'var(--crit)' }}>
                              {f.drift_data?.after || 'N/A'}
                            </div>
                          </div>
                        ))}

                        {precrimeFindings.map((f) => (
                          <div
                            key={`precrime-${f.domain}`}
                            className="matrix-card"
                            role="button"
                            tabIndex={0}
                            onClick={() => selectFindingFromAnywhere(f, true)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter' || e.key === ' ') {
                                e.preventDefault();
                                selectFindingFromAnywhere(f, true);
                              }
                            }}
                          >
                            <div className="matrix-card-top">
                              <div className="f-domain" style={{ fontSize: 15 }}>
                                <DomainWithConfusables domain={f.domain} />
                              </div>
                              <span className="badge precrime">PRECRIME</span>
                            </div>
                            <div
                              className={`technique-tag ${importanceClass(
                                f.candidate.importance
                              )}`}
                              style={{ marginBottom: 14 }}
                            >
                              {formatTechnique(f.candidate.technique)} ·{' '}
                              {f.candidate.importance} ({f.candidate.weight}/100)
                            </div>
                            <div className="drift-step-label">PreCrime Likelihood</div>
                            <div
                              className="drift-step-val"
                              style={{
                                color: 'var(--watch)',
                                fontVariantNumeric: 'tabular-nums',
                              }}
                            >
                              {f.precrime}% pre-weaponization likelihood
                            </div>
                          </div>
                        ))}
                      </>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Takedown Modal */}
      <TakedownModal
        open={modalOpen}
        domain={modalDomain}
        channel={takedownChannel}
        reportText={reportText}
        copiedNote={copiedNote}
        onClose={() => setModalOpen(false)}
        onChannelChange={handleChannelChange}
        onCopy={() => void copyReport()}
        onDownload={downloadTakedownTxt}
      />
    </section>
  );
}
