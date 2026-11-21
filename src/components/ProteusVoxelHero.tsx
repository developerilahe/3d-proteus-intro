import { useCallback, useEffect, useRef, useState } from 'react';
import { ArrowDown } from 'lucide-react';
import {
  createVoxelTypingScene,
  type KineticTypingHandle,
} from '../proteus/voxelTypingScene.ts';

interface ProteusVoxelHeroProps {
  onScrollToManifesto?: () => void;
  onScrollToArchitecture?: () => void;
  onScrollToWorkbench?: () => void;
}

interface HeroSlide {
  headline: string;
  caption: string;
  holdMs: number;
  typeMs: number;
}

const HERO_SLIDES: HeroSlide[] = [
  {
    headline: 'PROTEUS',
    caption: 'Autonomous brand impersonation intelligence and threat neutralization.',
    holdMs: 2400,
    typeMs: 92,
  },
  {
    headline: 'SLEEP WHILE\nWE MONITOR.',
    caption: 'Continuous DNS, RDAP, and Certificate Transparency surveillance around the clock.',
    holdMs: 2700,
    typeMs: 56,
  },
  {
    headline: 'CAUGHT BEFORE\nIT LAUNCHES.',
    caption: 'Seventeen mutation engines intercept lookalikes during pre-weaponization staging.',
    holdMs: 2700,
    typeMs: 54,
  },
  {
    headline: 'ALL IN\nYOUR HANDS.',
    caption: 'Full infrastructure attribution, identity drift alerts, and one-click takedowns.',
    holdMs: 2700,
    typeMs: 58,
  },
];

export function ProteusVoxelHero({
  onScrollToManifesto,
  onScrollToArchitecture,
  onScrollToWorkbench,
}: ProteusVoxelHeroProps) {
  const mountRef = useRef<HTMLDivElement | null>(null);
  const sceneRef = useRef<KineticTypingHandle | null>(null);
  const timeoutRef = useRef<number | null>(null);
  const runIdRef = useRef<number>(0);

  const [slideIndex, setSlideIndex] = useState<number>(0);

  const clearScheduled = useCallback(() => {
    if (timeoutRef.current !== null) {
      window.clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
  }, []);

  const playFromSlide = useCallback(
    (startIdx: number) => {
      clearScheduled();
      const myRun = ++runIdRef.current;

      const schedule = (fn: () => void, ms: number) => {
        timeoutRef.current = window.setTimeout(() => {
          if (runIdRef.current !== myRun) return;
          fn();
        }, ms);
      };

      const runSlide = (idx: number, currentDisplayed: string) => {
        if (runIdRef.current !== myRun) return;
        const slide = HERO_SLIDES[idx];
        setSlideIndex(idx);

        // Phase 1: Delete existing characters swiftly if any
        const eraseStep = (cur: string) => {
          if (runIdRef.current !== myRun) return;
          if (cur.length === 0) {
            schedule(() => typeStep(1), 240);
            return;
          }
          const next = cur.slice(0, -1);
          sceneRef.current?.setText(next);
          schedule(() => eraseStep(next), 28);
        };

        // Phase 2: Type target headline character by character
        const typeStep = (len: number) => {
          if (runIdRef.current !== myRun) return;
          const next = slide.headline.slice(0, len);
          sceneRef.current?.setText(next);

          if (len < slide.headline.length) {
            const ch = slide.headline[len];
            const delay = ch === '\n' ? 140 : slide.typeMs;
            schedule(() => typeStep(len + 1), delay);
          } else {
            // Phase 3: Hold cleanly, then advance to next slide
            schedule(() => {
              const nextIdx = (idx + 1) % HERO_SLIDES.length;
              runSlide(nextIdx, slide.headline);
            }, slide.holdMs);
          }
        };

        if (currentDisplayed.length > 0) {
          eraseStep(currentDisplayed);
        } else {
          typeStep(1);
        }
      };

      // Clear any leftover text first when jumping manually
      sceneRef.current?.setText('');
      runSlide(startIdx, '');
    },
    [clearScheduled]
  );

  useEffect(() => {
    const el = mountRef.current;
    if (!el) return;

    const handle = createVoxelTypingScene(el, '');
    sceneRef.current = handle;

    let cancelled = false;
    const readyPromise =
      document.fonts && document.fonts.ready
        ? Promise.race([
            document.fonts.ready,
            new Promise<void>((resolve) => window.setTimeout(resolve, 300)),
          ])
        : Promise.resolve();

    void readyPromise.then(() => {
      if (!cancelled) {
        playFromSlide(0);
      }
    });

    if (document.fonts && document.fonts.ready) {
      void document.fonts.ready.then(() => {
        if (!cancelled) {
          handle.refreshFont();
        }
      });
    }

    return () => {
      cancelled = true;
      runIdRef.current += 1;
      clearScheduled();
      handle.dispose();
      sceneRef.current = null;
    };
  }, [playFromSlide, clearScheduled]);

  const activeSlide = HERO_SLIDES[slideIndex] ?? HERO_SLIDES[0];

  return (
    <section
      id="proteus-intro"
      className="voxel-hero"
      aria-label="PROTEUS Brand Intelligence Hero"
    >
      <div ref={mountRef} className="voxel-canvas" />

      {/* Top Executive Eyebrow */}
      <div className="voxel-top-bar">
        <span className="voxel-kicker">PROTEUS INTELLIGENCE PLATFORM</span>
      </div>

      {/* Dynamic Narrative Subtitle */}
      <div className="voxel-narrative" aria-live="polite">
        <p key={slideIndex} className="voxel-caption">
          {activeSlide.caption}
        </p>
      </div>

      {/* Bottom Executive Navigation Dock */}
      <nav className="voxel-bottom-dock" aria-label="Hero navigation">
        <div className="voxel-slide-dots" role="group" aria-label="Intro sequence">
          {HERO_SLIDES.map((s, idx) => (
            <button
              key={s.headline}
              type="button"
              className={`voxel-slide-dot ${slideIndex === idx ? 'is-active' : ''}`}
              onClick={() => playFromSlide(idx)}
              aria-label={`Show message ${idx + 1}`}
            />
          ))}
        </div>

        <span className="voxel-dock-sep" aria-hidden="true" />

        {onScrollToManifesto && (
          <button
            type="button"
            className="voxel-btn-ghost"
            onClick={onScrollToManifesto}
          >
            <span>Capabilities</span>
            <ArrowDown size={13} aria-hidden="true" />
          </button>
        )}
        {onScrollToArchitecture && (
          <button
            type="button"
            className="voxel-btn-ghost"
            onClick={onScrollToArchitecture}
          >
            <span>3D Pipeline</span>
            <ArrowDown size={13} aria-hidden="true" />
          </button>
        )}
        {onScrollToWorkbench && (
          <button
            type="button"
            className="voxel-btn-primary"
            onClick={onScrollToWorkbench}
          >
            <span>Threat Scanner</span>
            <ArrowDown size={13} aria-hidden="true" />
          </button>
        )}
      </nav>
    </section>
  );
}
