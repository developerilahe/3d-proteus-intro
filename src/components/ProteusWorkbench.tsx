import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowUp,
  RotateCcw,
  Search,
  SlidersHorizontal,
  X,
} from 'lucide-react';
import type {
  FindingDto,
  GeoPointDto,
  ScanProgressDto,
  ScanResultsDto,
} from '../types/proteus-api.ts';
import { DossierPane, type DossierTab } from './workbench/DossierPane.tsx';
import {
  DomainWithConfusables,
  formatRiskLevel,
  formatStatusLabel,
  formatTechnique,
  getPrimaryIp,
  isLiveFinding,
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
type FilterMode = 'ALL' | 'ELEVATED' | 'LIVE' | 'PRECRIME' | 'SAFE';

const CANDIDATE_RANGE_OPTIONS = [25, 50, 100, 250] as const;

const FILTER_OPTIONS: Array<{ id: FilterMode; label: string }> = [
  { id: 'ALL', label: 'All Domains' },
  { id: 'ELEVATED', label: 'High & Critical' },
  { id: 'LIVE', label: 'Active Sites' },
  { id: 'PRECRIME', label: 'Early Warning' },
  { id: 'SAFE', label: 'Safe & Low' },
];

export interface ExternalBrandScanRequest {
  brand: string;
  nonce: number;
}

interface ProteusWorkbenchProps {
  onScanStart?: () => void;
  onExitDashboard?: () => void;
  onBackTo3D?: () => void;
  externalBrandRequest?: ExternalBrandScanRequest | null;
}

export function ProteusWorkbench({
  onScanStart,
  onExitDashboard,
  onBackTo3D,
  externalBrandRequest,
}: ProteusWorkbenchProps) {
  const [hasStartedScan, setHasStartedScan] = useState<boolean>(false);
  const [brandInput, setBrandInput] = useState<string>('');
  const [maxCandidates, setMaxCandidates] = useState<number>(50);
  const [scanPass, setScanPass] = useState<1 | 2>(1);
  const [onlineEnrich, setOnlineEnrich] = useState<boolean>(false);

  const [activeView, setActiveView] = useState<MainView>('view-triage');
  const [activeFilter, setActiveFilter] = useState<FilterMode>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [filterOpen, setFilterOpen] = useState<boolean>(false);
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
  const filterPopoverRef = useRef<HTMLDivElement | null>(null);

  const clearPoll = useCallback(() => {
    if (pollTimerRef.current !== null) {
      window.clearInterval(pollTimerRef.current);
      pollTimerRef.current = null;
    }
  }, []);

  const executeScan = useCallback(
    async (
      brandValue: string,
      passValue: 1 | 2,
      onlineValue: boolean,
      candidateLimit: number
    ) => {
      const targetBrand = brandValue.trim();
      if (!targetBrand) return;

      clearPoll();
      setHasStartedScan(true);
      onScanStart?.();
      setActiveView('view-triage');
      setFilterOpen(false);
      setScanning(true);
      setScanError(null);
      setSearchQuery('');
      setActiveFilter('ALL');
      setInspectedCountry(null);
      setProgress({
        scan_id: '',
        status: 'pending',
        progress_pct: 0,
        current_step: 'Scanning domains and checking servers',
        domains_total: candidateLimit,
        domains_processed: 0,
        findings_so_far: 0,
      });

      try {
        const res = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            brand: targetBrand,
            scan_pass: passValue,
            online_enrich: onlineValue,
            inspect_websites: false,
            max_candidates: candidateLimit,
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
          }, 300);
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
    [clearPoll, onScanStart]
  );

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      clearPoll();
    };
  }, [clearPoll]);

  useEffect(() => {
    if (!externalBrandRequest || externalBrandRequest.nonce === 0) return;
    const requested = externalBrandRequest.brand.trim().toLowerCase();
    if (!requested) return;
    setBrandInput(requested);
    void executeScan(requested, scanPass, onlineEnrich, maxCandidates);
  }, [externalBrandRequest, executeScan, scanPass, onlineEnrich, maxCandidates]);

  useEffect(() => {
    if (!filterOpen) return;
    const onPointerDown = (e: MouseEvent) => {
      if (
        filterPopoverRef.current &&
        !filterPopoverRef.current.contains(e.target as Node)
      ) {
        setFilterOpen(false);
      }
    };
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setFilterOpen(false);
    };
    window.addEventListener('mousedown', onPointerDown);
    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('mousedown', onPointerDown);
      window.removeEventListener('keydown', onKeyDown);
    };
  }, [filterOpen]);

  const findings = currentData?.findings ?? [];

  const filteredFindings = useMemo(() => {
    let items = findings;
    if (activeFilter === 'ELEVATED') {
      items = items.filter((f) => f.tier === 'CRITICAL' || f.tier === 'HIGH');
    } else if (activeFilter === 'LIVE') {
      items = items.filter((f) => isLiveFinding(f));
    } else if (activeFilter === 'PRECRIME') {
      items = items.filter(
        (f) => f.status === 'PRECRIME' || f.status === 'DRIFT DETECTED'
      );
    } else if (activeFilter === 'SAFE') {
      items = items.filter((f) => f.status === 'SAFE' || f.score <= 15);
    }

    const q = searchQuery.trim().toLowerCase();
    if (q) {
      items = items.filter((f) => {
        const ip = getPrimaryIp(f).toLowerCase();
        const statusText = formatStatusLabel(f.status).toLowerCase();
        return (
          f.domain.toLowerCase().includes(q) ||
          f.candidate.ascii_form.toLowerCase().includes(q) ||
          ip.includes(q) ||
          statusText.includes(q)
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

  const driftFindings = useMemo(() => findings.filter((f) => f.drift), [findings]);
  const precrimeFindings = useMemo(
    () => findings.filter((f) => f.precrime !== null && !f.drift && f.score > 15),
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
          `Failed to load notice: ${err instanceof Error ? err.message : 'Unknown error'}`
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

  const triggerDriftCheck = () => {
    setScanPass(2);
    if (!scanning && brandInput.trim()) {
      void executeScan(brandInput, 2, onlineEnrich, maxCandidates);
    }
  };

  const resetToLaunch = () => {
    clearPoll();
    setHasStartedScan(false);
    setScanning(false);
    setScanError(null);
    setProgress(null);
    setCurrentData(null);
    setCurrentScanId(null);
    setSelectedDomain(null);
    setFilterOpen(false);
    setSearchQuery('');
    setActiveFilter('ALL');
    onExitDashboard?.();
  };

  const hasActiveFilter = activeFilter !== 'ALL' || searchQuery.trim().length > 0;

  const handleLaunchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!brandInput.trim() || scanning) return;
    void executeScan(brandInput, scanPass, onlineEnrich, maxCandidates);
  };

  return (
    <section
      id="proteus-workbench"
      className={hasStartedScan ? 'is-dashboard' : 'is-launch'}
      aria-label="PROTEUS Domain Scanner"
    >
      {!hasStartedScan ? (
        /* ============================================================
           MINIMALIST CENTERED LAUNCH BLOCK (BEFORE SCAN RUNS)
           ============================================================ */
        <div className="wb-launch-screen">
          <form className="wb-launch-card" onSubmit={handleLaunchSubmit}>
            <h2 className="wb-launch-title">Enter any Domain!</h2>

            <div className="wb-launch-input-wrap">
              <Search size={16} className="wb-launch-icon" aria-hidden="true" />
              <input
                type="text"
                id="brand-input"
                aria-label="Domain to scan"
                placeholder="example.com"
                value={brandInput}
                onChange={(e) => setBrandInput(e.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
            </div>

            <div className="wb-range-presets" role="group" aria-label="Number of domains to scan">
              {CANDIDATE_RANGE_OPTIONS.map((count) => (
                <button
                  key={count}
                  type="button"
                  className={`wb-range-btn ${maxCandidates === count ? 'active' : ''}`}
                  onClick={() => setMaxCandidates(count)}
                >
                  {count}
                </button>
              ))}
            </div>

            <button
              type="submit"
              id="scan-btn"
              className="wb-launch-submit"
              disabled={!brandInput.trim() || scanning}
            >
              Start Scan
            </button>
          </form>
        </div>
      ) : (
        /* ============================================================
           FULL-SCREEN DASHBOARD (100vw ON SCAN)
           ============================================================ */
        <div className="wb-dashboard-screen">
          {/* Compact Top Bar */}
          <header className="wb-dash-topbar">
            <div className="wb-dash-brand-bar">
              <form
                className="wb-dash-search-form"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!scanning && brandInput.trim()) {
                    void executeScan(brandInput, scanPass, onlineEnrich, maxCandidates);
                  }
                }}
              >
                <Search size={14} className="wb-dash-search-icon" aria-hidden="true" />
                <input
                  type="text"
                  id="brand-input"
                  aria-label="Target domain"
                  placeholder="Enter domain"
                  value={brandInput}
                  onChange={(e) => setBrandInput(e.target.value)}
                />
                <select
                  aria-label="Domains to scan"
                  value={maxCandidates}
                  onChange={(e) => setMaxCandidates(Number(e.target.value))}
                  className="wb-dash-range-select"
                >
                  {CANDIDATE_RANGE_OPTIONS.map((count) => (
                    <option key={count} value={count}>
                      {count} domains
                    </option>
                  ))}
                </select>
                <button
                  type="submit"
                  id="scan-btn"
                  className="wb-btn-compact"
                  disabled={!brandInput.trim() || scanning}
                >
                  {scanning ? 'Scanning…' : 'Scan'}
                </button>
              </form>

              <button
                type="button"
                className="btn-outline"
                onClick={resetToLaunch}
                title="Start a new domain scan"
              >
                <RotateCcw size={12} aria-hidden="true" />
                <span>New</span>
              </button>
            </div>

            <nav className="nav-links" role="tablist" aria-label="Dashboard views">
              <button
                type="button"
                role="tab"
                aria-selected={activeView === 'view-triage'}
                className={`nav-tab ${activeView === 'view-triage' ? 'active' : ''}`}
                onClick={() => setActiveView('view-triage')}
              >
                Domains ({findings.length})
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={activeView === 'view-constellation'}
                className={`nav-tab ${activeView === 'view-constellation' ? 'active' : ''}`}
                onClick={() => setActiveView('view-constellation')}
              >
                Threat Map
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={activeView === 'view-osint'}
                className={`nav-tab ${activeView === 'view-osint' ? 'active' : ''}`}
                onClick={() => setActiveView('view-osint')}
              >
                OSINT
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={activeView === 'view-history'}
                className={`nav-tab ${activeView === 'view-history' ? 'active' : ''}`}
                onClick={() => setActiveView('view-history')}
              >
                Changes
              </button>
            </nav>

            <div className="wb-dash-actions">
              <label
                className="toggle-switch"
                title="Query live public DNS, RDAP, and SSL certificates"
              >
                <input
                  type="checkbox"
                  id="online-toggle"
                  checked={onlineEnrich}
                  onChange={(e) => setOnlineEnrich(e.target.checked)}
                />
                <span>Live DNS</span>
              </label>

              <button
                type="button"
                className="btn-outline"
                disabled={!currentScanId || !currentData}
                onClick={() => {
                  if (!currentScanId) return;
                  triggerUrlDownload(
                    `/api/export/csv?scan_id=${currentScanId}`,
                    `proteus_scan_${currentScanId}.csv`
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
                    `proteus_scan_${currentScanId}.json`
                  );
                }}
              >
                JSON
              </button>

              {onBackTo3D && (
                <button type="button" className="btn-back-3d" onClick={onBackTo3D}>
                  <ArrowUp size={12} aria-hidden="true" />
                  <span>3D View</span>
                </button>
              )}
            </div>
          </header>

          {/* Compact Progress Strip */}
          {progress && (
            <div id="scan-progress" className="scan-progress" aria-live="polite">
              <div className="scan-progress-meta">
                <span id="progress-step">{progress.current_step}</span>
                <span id="progress-counts">
                  {progress.domains_processed}/{progress.domains_total} ({progress.progress_pct}%)
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

          {/* Full-Screen Workspace Body */}
          <div className="wb-container">
            {/* VIEW 1: SCANNED DOMAINS SPLIT VIEW */}
            {activeView === 'view-triage' && (
              <div id="view-triage" className="view active">
                <div className="split-layout">
                  {/* Left Domain List with Single Filter Icon Popover */}
                  <div className="list-pane">
                    <div className="list-pane-header" ref={filterPopoverRef}>
                      <div className="list-pane-title-wrap">
                        <span className="list-pane-title">Scanned Domains</span>
                        <span className="list-pane-count">{filteredFindings.length}</span>
                      </div>

                      <button
                        type="button"
                        className={`filter-icon-btn ${hasActiveFilter ? 'is-filtered' : ''}`}
                        aria-label="Filter scanned domains"
                        aria-expanded={filterOpen}
                        onClick={() => setFilterOpen((v) => !v)}
                        title="Filter domains"
                      >
                        <SlidersHorizontal size={15} aria-hidden="true" />
                      </button>

                      {filterOpen && (
                        <div className="filter-popover" role="dialog" aria-label="Filter domains">
                          <div className="filter-popover-search">
                            <Search size={13} className="filter-pop-icon" aria-hidden="true" />
                            <input
                              type="text"
                              id="search-input"
                              aria-label="Search domain or IP"
                              placeholder="Search domain or IP…"
                              value={searchQuery}
                              onChange={(e) => setSearchQuery(e.target.value)}
                              autoFocus
                            />
                            {searchQuery && (
                              <button
                                type="button"
                                className="search-clear-btn"
                                aria-label="Clear search"
                                onClick={() => setSearchQuery('')}
                              >
                                <X size={12} aria-hidden="true" />
                              </button>
                            )}
                          </div>

                          <div className="filter-popover-options">
                            {FILTER_OPTIONS.map((flt) => (
                              <button
                                key={flt.id}
                                type="button"
                                className={`filter-pop-opt ${
                                  activeFilter === flt.id ? 'active' : ''
                                }`}
                                onClick={() => {
                                  setActiveFilter(flt.id);
                                  setFilterOpen(false);
                                }}
                              >
                                {flt.label}
                              </button>
                            ))}
                          </div>

                          {hasActiveFilter && (
                            <button
                              type="button"
                              className="filter-pop-reset"
                              onClick={() => {
                                setActiveFilter('ALL');
                                setSearchQuery('');
                                setFilterOpen(false);
                              }}
                            >
                              Reset filters
                            </button>
                          )}
                        </div>
                      )}
                    </div>

                    <div
                      id="findings-list"
                      role="listbox"
                      aria-label="Scanned domains"
                      tabIndex={0}
                      onKeyDown={handleListKeyDown}
                    >
                      {scanError ? (
                        <div className="empty-state" style={{ color: 'var(--crit)' }}>
                          Error: {scanError}
                        </div>
                      ) : !currentData ? (
                        <div className="empty-state">Scanning domains…</div>
                      ) : filteredFindings.length === 0 ? (
                        <div className="empty-state">No domains match your filter.</div>
                      ) : (
                        filteredFindings.map((f) => {
                          const isSafe = f.status === 'SAFE' || f.score <= 15;
                          const ipText = getPrimaryIp(f);
                          const statusText = formatStatusLabel(f.status);
                          const isActive = activeFinding?.domain === f.domain;
                          const scoreToneClass = isSafe
                            ? 'tier-SAFE'
                            : `tier-${f.tier}`;

                          return (
                            <div
                              key={f.domain + '|' + f.candidate.rule}
                              role="option"
                              aria-selected={isActive}
                              className={`finding-row ${scoreToneClass} ${isActive ? 'active' : ''}`}
                              onClick={() => selectFindingFromAnywhere(f)}
                            >
                              <div className="f-row-left">
                                <span className="f-domain">
                                  <DomainWithConfusables domain={f.domain} />
                                </span>
                                <div className="f-subrow">
                                  <span className="f-status-inline">{statusText}</span>
                                  <span aria-hidden="true">·</span>
                                  <span className="sub-label">{ipText}</span>
                                </div>
                              </div>
                              <span className="f-score">{f.score}</span>
                            </div>
                          );
                        })
                      )}
                    </div>
                  </div>

                  {/* Right Inspector Pane (First Domain Pre-Opened) */}
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
                <div className="map-tabs" role="tablist" aria-label="Infrastructure views">
                  {(
                    [
                      ['geo', `Global Map (${currentData?.geo.length ?? 0})`],
                      ['clusters', `Shared Servers (${currentData?.clusters.length ?? 0})`],
                      ['matrix', 'Server Table'],
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
                            No shared hosting clusters detected.
                          </div>
                        ) : (
                          currentData.clusters.map((c) => (
                            <div key={c.ip + c.asn} className="cluster-card">
                              <div className="cluster-header">
                                <div>
                                  <div className="cluster-ip">{c.ip}</div>
                                  <div className="cluster-meta">
                                    {c.org} · {c.country}
                                  </div>
                                </div>
                                <div className="cluster-conf">
                                  {c.members.length} domains
                                </div>
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
                                  <span style={{ fontVariantNumeric: 'tabular-nums' }}>
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
                              <th>Provider</th>
                              <th>Country</th>
                              <th>Role</th>
                              <th>Domains</th>
                            </tr>
                          </thead>
                          <tbody>
                            {!currentData || currentData.clusters.length === 0 ? (
                              <tr>
                                <td
                                  colSpan={5}
                                  style={{
                                    textAlign: 'center',
                                    color: 'var(--text-mute)',
                                    padding: 32,
                                  }}
                                >
                                  No shared servers detected.
                                </td>
                              </tr>
                            ) : (
                              currentData.clusters.map((c) => (
                                <tr key={c.ip + c.asn}>
                                  <td style={{ color: 'var(--accent-text)' }}>{c.ip}</td>
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
                  <h3 className="view-heading">Public Records &amp; Threat Checks</h3>
                  <p className="view-subhead">
                    Registration, DNS, and threat lookup summaries for any scanned domain.
                  </p>

                  {!osintTarget ? (
                    <div className="empty-state">
                      Scan a domain first to see public record summaries.
                    </div>
                  ) : (
                    <>
                      <div className="osint-selector-row">
                        <label
                          htmlFor="osint-domain-select"
                          style={{ color: 'var(--text-dim)', fontSize: 12 }}
                        >
                          Domain:
                        </label>
                        <select
                          id="osint-domain-select"
                          value={osintTarget.domain}
                          onChange={(e) => setActiveOsintDomain(e.target.value)}
                        >
                          {findings.slice(0, 40).map((f) => (
                            <option key={f.domain} value={f.domain}>
                              {f.domain} · {formatRiskLevel(f.score, f.status)} ({f.score})
                            </option>
                          ))}
                        </select>
                        <button
                          type="button"
                          className="btn-inline-action"
                          onClick={() => selectFindingFromAnywhere(osintTarget, true)}
                        >
                          Open Overview ↗
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
                              Summary
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
                              </div>
                              <div className="osint-sources">
                                {sec.sources.map((s) => {
                                  const href = safeExternalUrl(s.link);
                                  return (
                                    <div key={s.name} className="osint-source-row">
                                      <div className="osint-source-name">
                                        <span>{s.name}</span>
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

            {/* VIEW 4: RECENT CHANGES & EARLY WARNINGS */}
            {activeView === 'view-history' && (
              <div id="view-history" className="view active">
                <div className="view-scroll-pad">
                  <div className="history-head-row">
                    <div>
                      <h3 className="view-heading">Sudden Changes &amp; Early Warnings</h3>
                      <p className="view-subhead" style={{ marginBottom: 0 }}>
                        Lookalikes showing sudden server changes or early phishing setup signs.
                      </p>
                    </div>
                    {currentData?.scan_pass !== 2 && (
                      <button
                        type="button"
                        className="wb-btn-compact"
                        disabled={scanning}
                        onClick={triggerDriftCheck}
                      >
                        Check for Changes
                      </button>
                    )}
                  </div>

                  <div id="drift-matrix" className="matrix-grid">
                    {driftFindings.length === 0 && precrimeFindings.length === 0 ? (
                      <div className="empty-state" style={{ gridColumn: '1 / -1' }}>
                        <p style={{ marginBottom: 14 }}>
                          No sudden changes or early warnings detected in this scan.
                        </p>
                        <button
                          type="button"
                          className="wb-btn-compact"
                          disabled={scanning}
                          onClick={triggerDriftCheck}
                        >
                          Run Change Check
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
                              <span className="badge drift">Changed</span>
                            </div>
                            <div className="drift-step-label">Before</div>
                            <div className="drift-step-val" style={{ marginBottom: 10 }}>
                              {f.drift_data?.before || 'N/A'}
                            </div>
                            <div className="drift-step-label">Now</div>
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
                              <span className="badge precrime">Early Warning</span>
                            </div>
                            <div className="drift-step-label">IP Address</div>
                            <div className="drift-step-val" style={{ marginBottom: 10 }}>
                              {getPrimaryIp(f)}
                            </div>
                            <div className="drift-step-label">Risk Score</div>
                            <div
                              className="drift-step-val"
                              style={{
                                color: 'var(--watch)',
                                fontVariantNumeric: 'tabular-nums',
                              }}
                            >
                              {f.score} / 100
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
      )}

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
