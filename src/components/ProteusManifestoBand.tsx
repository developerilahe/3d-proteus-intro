import { useEffect, useRef } from 'react';

interface ProteusManifestoBandProps {
  onOpenArchitecture?: () => void;
  onOpenScanner?: () => void;
}

const MANIFESTO_ROWS = [
  {
    base: '17 MUTATIONS',
    hover: 'ZERO BLIND SPOTS',
    action: 'architecture' as const,
  },
  {
    base: 'LIVE TELEMETRY',
    hover: 'DNS · RDAP · CERT LOGS',
    action: 'scanner' as const,
  },
  {
    base: 'PRECRIME STAGING',
    hover: 'CAUGHT BEFORE LAUNCH',
    action: 'scanner' as const,
  },
  {
    base: 'ATTRIBUTION',
    hover: 'CLUSTERS · GEO · OSINT',
    action: 'scanner' as const,
  },
  {
    base: 'START SCANNING',
    hover: 'LAUNCH WORKBENCH →',
    action: 'scanner' as const,
  },
];

export function ProteusManifestoBand({
  onOpenArchitecture,
  onOpenScanner,
}: ProteusManifestoBandProps) {
  const sectionRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    const el = sectionRef.current;
    if (!el) return;

    const rows = Array.from(el.querySelectorAll<HTMLElement>('.cp-row-base'));
    if (!rows.length) return;

    let rafId = 0;

    const updateScrollProgress = () => {
      rafId = 0;
      const vh = window.innerHeight || 800;
      for (const row of rows) {
        const rect = row.getBoundingClientRect();
        const raw = (vh * 0.92 - rect.top) / (vh * 0.52);
        const pct = Math.max(0, Math.min(100, raw * 100));
        row.style.setProperty('--reveal-pct', `${pct.toFixed(1)}%`);
      }
    };

    const scheduleUpdate = () => {
      if (!rafId) {
        rafId = window.requestAnimationFrame(updateScrollProgress);
      }
    };

    updateScrollProgress();
    window.addEventListener('scroll', scheduleUpdate, { passive: true });
    window.addEventListener('resize', scheduleUpdate, { passive: true });

    return () => {
      if (rafId) window.cancelAnimationFrame(rafId);
      window.removeEventListener('scroll', scheduleUpdate);
      window.removeEventListener('resize', scheduleUpdate);
    };
  }, []);

  const handleRowClick = (action: 'architecture' | 'scanner') => {
    if (action === 'architecture') {
      onOpenArchitecture?.();
    } else {
      onOpenScanner?.();
    }
  };

  return (
    <section
      ref={sectionRef}
      id="proteus-manifesto"
      className="manifesto-band"
      aria-label="PROTEUS Capabilities Overview"
    >
      <div className="cp-container">
        {MANIFESTO_ROWS.map((row) => (
          <button
            key={row.base}
            type="button"
            className="cp-row-btn"
            onClick={() => handleRowClick(row.action)}
          >
            <span className="cp-row-base">{row.base}</span>
            <span className="cp-row-wipe" aria-hidden="true">
              {row.hover}
            </span>
          </button>
        ))}
      </div>
    </section>
  );
}
