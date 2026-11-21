/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { ProteusVoxelHero } from './components/ProteusVoxelHero.tsx';
import { ProteusManifestoBand } from './components/ProteusManifestoBand.tsx';
import { ProteusBriefing3D } from './components/ProteusBriefing3D.tsx';
import {
  ProteusWorkbench,
  type ExternalBrandScanRequest,
} from './components/ProteusWorkbench.tsx';
import type { BrandProfileKey } from './proteus/scenario-data.d.ts';

function readPathname(): string {
  return window.location.pathname === '/dashboard' ? '/dashboard' : '/';
}

export default function App() {
  const [route, setRoute] = useState<string>(() => readPathname());
  const introRef = useRef<HTMLDivElement | null>(null);
  const manifestoRef = useRef<HTMLDivElement | null>(null);
  const architectureRef = useRef<HTMLDivElement | null>(null);
  const workbenchRef = useRef<HTMLDivElement | null>(null);
  const pendingScrollTargetRef = useRef<'architecture' | 'workbench' | null>(null);
  const [brandRequest, setBrandRequest] =
    useState<ExternalBrandScanRequest | null>(null);

  useEffect(() => {
    const onPopState = () => {
      setRoute(readPathname());
    };
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  useEffect(() => {
    if (route === '/dashboard') {
      window.scrollTo(0, 0);
      return;
    }
    const target = pendingScrollTargetRef.current;
    if (!target) return;
    pendingScrollTargetRef.current = null;
    window.requestAnimationFrame(() => {
      if (target === 'architecture') {
        architectureRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      } else if (target === 'workbench') {
        workbenchRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  }, [route]);

  const navigateToDashboard = useCallback(() => {
    if (window.location.pathname !== '/dashboard') {
      window.history.pushState({}, '', '/dashboard');
    }
    setRoute('/dashboard');
    window.scrollTo(0, 0);
  }, []);

  const navigateHome = useCallback((scrollTarget?: 'architecture' | 'workbench') => {
    if (scrollTarget) {
      pendingScrollTargetRef.current = scrollTarget;
    }
    if (window.location.pathname !== '/') {
      window.history.pushState({}, '', '/');
    }
    setRoute('/');
    if (!scrollTarget) {
      window.scrollTo(0, 0);
    } else {
      window.requestAnimationFrame(() => {
        if (scrollTarget === 'architecture') {
          architectureRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        } else {
          workbenchRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      });
    }
  }, []);

  const scrollToManifesto = () => {
    manifestoRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const scrollToArchitecture = () => {
    if (route === '/dashboard') {
      navigateHome('architecture');
      return;
    }
    architectureRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const scrollToWorkbench = (brand?: BrandProfileKey) => {
    if (brand) {
      setBrandRequest((prev) => ({
        brand,
        nonce: (prev?.nonce ?? 0) + 1,
      }));
      navigateToDashboard();
      return;
    }
    if (route === '/dashboard') {
      navigateHome('workbench');
      return;
    }
    workbenchRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  return (
    <main className="w-full">
      {route !== '/dashboard' ? (
        <>
          <div ref={introRef}>
            <ProteusVoxelHero
              onScrollToManifesto={scrollToManifesto}
              onScrollToArchitecture={scrollToArchitecture}
              onScrollToWorkbench={() => scrollToWorkbench()}
            />
          </div>

          <div ref={manifestoRef}>
            <ProteusManifestoBand
              onOpenArchitecture={scrollToArchitecture}
              onOpenScanner={() => scrollToWorkbench()}
            />
          </div>

          <div ref={architectureRef}>
            <ProteusBriefing3D onOpenWorkbench={scrollToWorkbench} />
          </div>
        </>
      ) : null}

      <div ref={workbenchRef}>
        <ProteusWorkbench
          onScanStart={navigateToDashboard}
          onExitDashboard={() => navigateHome('workbench')}
          onBackTo3D={scrollToArchitecture}
          externalBrandRequest={brandRequest}
        />
      </div>
    </main>
  );
}
