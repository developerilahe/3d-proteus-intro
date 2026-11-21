import { useCallback, useEffect, useRef, useState } from 'react';
import { ArrowDown, ChevronLeft, ChevronRight, Pause, Play } from 'lucide-react';
import { createProteusScene3D } from '../proteus/scene3d.js';
import type { ProjectedCoord, ProteusScene3DHandle } from '../proteus/scene3d.d.ts';
import { BRAND_PROFILES, WALKTHROUGH_STEPS } from '../proteus/scenario-data.js';
import type { BrandProfileKey } from '../proteus/scenario-data.d.ts';

const BRAND_KEYS: BrandProfileKey[] = ['pashabank.az', 'acmecorp.com'];

interface ProteusBriefing3DProps {
  onOpenWorkbench?: (brand: BrandProfileKey) => void;
}

export function ProteusBriefing3D({ onOpenWorkbench }: ProteusBriefing3DProps) {
  const sectionRef = useRef<HTMLElement | null>(null);
  const mountRef = useRef<HTMLDivElement | null>(null);
  const engineRef = useRef<ProteusScene3DHandle | null>(null);
  const hasAutoStartedRef = useRef<boolean>(false);
  const nodeRefs = useRef<Record<string, HTMLDivElement | null>>({});
  const latestCoordsRef = useRef<{
    nodeCoords: Record<string, ProjectedCoord>;
  }>({ nodeCoords: {} });

  const [brandKey, setBrandKey] = useState<BrandProfileKey>('pashabank.az');
  const [stepIndex, setStepIndex] = useState<number>(1);
  const [autoplay, setAutoplay] = useState<boolean>(false);

  const brand = BRAND_PROFILES[brandKey];
  const step = WALKTHROUGH_STEPS[stepIndex];
  const activeLabels = step.labels(brand);
  const traceCard = step.traceCard(brand);

  const syncProjectedPositions = useCallback(() => {
    const { nodeCoords } = latestCoordsRef.current;

    Object.entries(nodeRefs.current).forEach(([nodeId, el]) => {
      if (!el) return;
      const pos = nodeCoords[nodeId];
      if (pos && pos.visible) {
        el.style.display = 'block';
        el.style.transform = `translate3d(${pos.x}px, ${pos.y}px, 0) translate(-50%, -100%)`;
      } else {
        el.style.display = 'none';
      }
    });
  }, []);

  useEffect(() => {
    const el = mountRef.current;
    if (!el) return;

    const engine = createProteusScene3D(el, {
      initialStep: 1,
      onSelectNode: (nodeId) => {
        setAutoplay(false);
        const matchIdx = WALKTHROUGH_STEPS.findIndex((s) => s.activeNodes.includes(nodeId));
        if (matchIdx !== -1) {
          setStepIndex(matchIdx);
          engine.setStep(matchIdx, true);
        }
      },
      onFrameProject: (nodeCoords) => {
        latestCoordsRef.current = { nodeCoords };
        syncProjectedPositions();
      },
    });
    engineRef.current = engine;

    const onKeyDown = (e: KeyboardEvent) => {
      // Do not hijack keys while user is typing in inputs or listbox
      const activeEl = document.activeElement;
      const activeTag = activeEl?.tagName;
      if (
        activeTag === 'INPUT' ||
        activeTag === 'TEXTAREA' ||
        activeTag === 'SELECT' ||
        activeEl?.getAttribute('role') === 'listbox'
      ) {
        return;
      }
      if (e.key === 'ArrowRight') {
        setAutoplay(false);
        setStepIndex((prev) => {
          const next = Math.min(WALKTHROUGH_STEPS.length - 1, prev + 1);
          engine.setStep(next, true);
          return next;
        });
      } else if (e.key === 'ArrowLeft') {
        setAutoplay(false);
        setStepIndex((prev) => {
          const next = Math.max(0, prev - 1);
          engine.setStep(next, true);
          return next;
        });
      } else if (/^[1-7]$/.test(e.key)) {
        const idx = Number(e.key) - 1;
        if (idx >= 0 && idx < WALKTHROUGH_STEPS.length) {
          setAutoplay(false);
          setStepIndex(idx);
          engine.setStep(idx, true);
        }
      }
    };
    window.addEventListener('keydown', onKeyDown);

    const sectionEl = sectionRef.current;
    let observer: IntersectionObserver | null = null;
    if (sectionEl && typeof IntersectionObserver !== 'undefined') {
      observer = new IntersectionObserver(
        (entries) => {
          const entry = entries[0];
          if (!entry) return;
          if (entry.isIntersecting && !hasAutoStartedRef.current) {
            hasAutoStartedRef.current = true;
            setStepIndex(1);
            engine.playScrollEntrance(1);
            setAutoplay(true);
          } else if (!entry.isIntersecting && hasAutoStartedRef.current) {
            setAutoplay(false);
          }
        },
        { threshold: 0.35 }
      );
      observer.observe(sectionEl);
    }

    return () => {
      observer?.disconnect();
      window.removeEventListener('keydown', onKeyDown);
      engine.dispose();
      engineRef.current = null;
    };
  }, [syncProjectedPositions]);

  useEffect(() => {
    syncProjectedPositions();
  }, [stepIndex, brandKey, syncProjectedPositions]);

  useEffect(() => {
    if (!autoplay) return;
    const timer = window.setInterval(() => {
      setStepIndex((prev) => {
        const next = (prev + 1) % WALKTHROUGH_STEPS.length;
        engineRef.current?.setStep(next, true);
        return next;
      });
    }, 6500);
    return () => window.clearInterval(timer);
  }, [autoplay]);

  const goToStep = (idx: number) => {
    setAutoplay(false);
    const bounded = Math.max(0, Math.min(WALKTHROUGH_STEPS.length - 1, idx));
    setStepIndex(bounded);
    engineRef.current?.setStep(bounded, true);
  };

  return (
    <section
      ref={sectionRef}
      id="proteus-briefing"
      aria-label="PROTEUS — How It Works"
    >
      {/* 100% Full-Bleed 3D Canvas */}
      <div ref={mountRef} className="pb-canvas" />

      {/* Top-Center Step Header Box */}
      <header className="pb-header-box">
        <div className="pb-header-tag">{step.tag}</div>
        <h1 className="pb-header-title">{step.headline}</h1>
        <p className="pb-header-sub">{step.subtitle}</p>
      </header>

      {/* Minimal Short Node Tags on Active Structures */}
      {activeLabels.slice(0, 2).map((lbl) => (
        <div
          key={lbl.nodeId}
          ref={(el) => {
            nodeRefs.current[lbl.nodeId] = el;
          }}
          className={`pb-node-pill ${lbl.tone ? `is-${lbl.tone}` : ''}`}
          style={{ display: 'none' }}
        >
          <div className="pb-node-pill-title">{lbl.title}</div>
          <div className="pb-node-pill-detail">{lbl.detail}</div>
        </div>
      ))}

      {/* Clean Right-Hand Summary Card */}
      <aside className="pb-telemetry-card" aria-label={traceCard.tag}>
        <div className="pb-tel-head">
          <div className="pb-tel-tag">{traceCard.tag}</div>
        </div>
        <h2 className="pb-tel-title">{traceCard.title}</h2>

        {traceCard.rows.length > 0 && (
          <div className="pb-tel-rows">
            {traceCard.rows.slice(0, 3).map((r, i) => (
              <div key={i} className="pb-tel-row">
                <span className="pb-tel-k">{r.k}</span>
                <span className={`pb-tel-v ${r.tone ? `is-${r.tone}` : ''}`}>{r.v}</span>
              </div>
            ))}
          </div>
        )}

        {traceCard.signals && (
          <div className="pb-tel-rows">
            {traceCard.signals.slice(0, 3).map((sig, i) => (
              <div key={i} className="pb-tel-row">
                <span className="pb-tel-k">{sig.label}</span>
                <span className={`pb-tel-v ${sig.tone ? `is-${sig.tone}` : ''}`}>
                  {sig.weight}
                </span>
              </div>
            ))}
          </div>
        )}

        {traceCard.bar && (
          <div className="pb-score-wrap">
            <div className="pb-score-head">
              <span className="pb-tel-k">{traceCard.bar.label}</span>
              <span
                className={`pb-score-val ${
                  traceCard.bar.tone === 'rust' ? 'is-rust' : ''
                }`}
              >
                {traceCard.bar.valueText}
              </span>
            </div>
            <div className="pb-score-track">
              <div
                className={`pb-score-fill ${
                  traceCard.bar.tone ? `is-${traceCard.bar.tone}` : ''
                }`}
                style={{ width: `${Math.min(100, traceCard.bar.percent)}%` }}
              />
            </div>
          </div>
        )}

        <div
          className={`pb-stat-grid ${
            traceCard.stats.slice(0, 2).length === 2 ? 'cols-2' : 'cols-3'
          }`}
        >
          {traceCard.stats.slice(0, 2).map((st, idx) => (
            <div key={idx} className="pb-stat-box">
              <div className={`pb-stat-val ${st.tone ? `is-${st.tone}` : ''}`}>
                {st.value}
              </div>
              <div className="pb-stat-lbl">{st.label}</div>
            </div>
          ))}
        </div>
      </aside>

      {/* Bottom Pill Control Bar */}
      <nav className="pb-bottom-bar" aria-label="Walkthrough controls">
        <button
          type="button"
          className="pb-ctrl-btn"
          disabled={stepIndex === 0}
          onClick={() => goToStep(stepIndex - 1)}
          aria-label="Previous step"
        >
          <ChevronLeft size={14} aria-hidden="true" />
        </button>

        <div className="pb-dashes" role="group" aria-label="Step progress">
          {WALKTHROUGH_STEPS.map((s, idx) => (
            <button
              key={s.id}
              type="button"
              onClick={() => goToStep(idx)}
              className={`pb-dash ${stepIndex === idx ? 'is-active' : ''}`}
              aria-label={`Step ${idx + 1}: ${s.tag}`}
            />
          ))}
        </div>

        <span className="pb-step-counter">
          {stepIndex + 1} / {WALKTHROUGH_STEPS.length}
        </span>

        <span className="pb-sep" aria-hidden="true" />

        <button
          type="button"
          onClick={() => setAutoplay((v) => !v)}
          className={`pb-ctrl-btn ${autoplay ? 'is-active' : ''}`}
        >
          {autoplay ? <Pause size={12} aria-hidden="true" /> : <Play size={12} aria-hidden="true" />}
          <span>{autoplay ? 'Pause' : 'Autoplay'}</span>
        </button>

        <button
          type="button"
          disabled={stepIndex === WALKTHROUGH_STEPS.length - 1}
          onClick={() => goToStep(stepIndex + 1)}
          className="pb-ctrl-btn is-primary"
        >
          <span>Next</span>
          <ChevronRight size={14} aria-hidden="true" />
        </button>

        <span className="pb-sep" aria-hidden="true" />

        <div className="pb-brand-switch" role="group" aria-label="Target brand">
          {BRAND_KEYS.map((key) => (
            <button
              key={key}
              type="button"
              onClick={() => setBrandKey(key)}
              className={`pb-brand-btn ${brandKey === key ? 'is-active' : ''}`}
            >
              {key}
            </button>
          ))}
        </div>

        {onOpenWorkbench && (
          <>
            <span className="pb-sep" aria-hidden="true" />
            <button
              type="button"
              onClick={() => onOpenWorkbench(brandKey)}
              className="pb-launch-btn"
              title={`Open Threat Scanner for ${brandKey}`}
            >
              <span>Threat Scanner</span>
              <ArrowDown size={12} aria-hidden="true" />
            </button>
          </>
        )}
      </nav>
    </section>
  );
}
