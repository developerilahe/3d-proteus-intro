/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useRef, useState } from 'react';
import { ProteusVoxelHero } from './components/ProteusVoxelHero.tsx';
import { ProteusManifestoBand } from './components/ProteusManifestoBand.tsx';
import { ProteusBriefing3D } from './components/ProteusBriefing3D.tsx';
import {
  ProteusWorkbench,
  type ExternalBrandScanRequest,
} from './components/ProteusWorkbench.tsx';
import type { BrandProfileKey } from './proteus/scenario-data.d.ts';

export default function App() {
  const introRef = useRef<HTMLDivElement | null>(null);
  const manifestoRef = useRef<HTMLDivElement | null>(null);
  const architectureRef = useRef<HTMLDivElement | null>(null);
  const workbenchRef = useRef<HTMLDivElement | null>(null);
  const [brandRequest, setBrandRequest] =
    useState<ExternalBrandScanRequest | null>(null);

  const scrollToManifesto = () => {
    manifestoRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const scrollToArchitecture = () => {
    architectureRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const scrollToWorkbench = (brand?: BrandProfileKey) => {
    if (brand) {
      setBrandRequest((prev) => ({
        brand,
        nonce: (prev?.nonce ?? 0) + 1,
      }));
    }
    workbenchRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  return (
    <main className="w-full">
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

      <div ref={workbenchRef}>
        <ProteusWorkbench
          onBackTo3D={scrollToArchitecture}
          externalBrandRequest={brandRequest}
        />
      </div>
    </main>
  );
}
