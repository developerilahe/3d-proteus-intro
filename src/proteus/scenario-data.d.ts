export type BrandProfileKey = 'pashabank.az' | 'acmecorp.com';

export interface SignalItem {
  label: string;
  weight: string;
  tone: 'amber' | 'rust' | 'blue' | 'violet';
}

export interface StatBoxItem {
  value: string;
  label: string;
  tone?: 'amber' | 'rust' | 'blue' | 'violet';
}

export interface BrandProfile {
  brand: BrandProfileKey;
  baselineIp: string;
  baselinePosture: string;
  lookalikeDomain: string;
  homoglyphSample: string;
  parkedSample: string;
  activeIp: string;
  asnGeo: string;
  spfStatus: string;
  dmarcStatus: string;
  tlsAge: string;
  preCrimeScore: number;
  preCrimeThreshold: string;
  exposureLow: string;
  exposureHigh: string;
  signals: SignalItem[];
  driftBefore: string;
  driftAfter: string;
  osintRows: { k: string; v: string }[];
  takedownTarget: string;
}

export interface TraceCardSpec {
  tag: string;
  provenance: string;
  title: string;
  rows: { k: string; v: string; tone?: 'amber' | 'rust' | 'blue' | 'violet' }[];
  signals?: SignalItem[];
  bar?: { label: string; valueText: string; percent: number; tone?: 'amber' | 'rust' | 'blue' };
  stats: StatBoxItem[];
  note?: string;
}

export interface StepLabelSpec {
  nodeId: string;
  title: string;
  detail: string;
  tone?: 'amber' | 'rust' | 'blue' | 'violet';
}

export interface RoutePacketSpec {
  arcId: string;
  label: string;
  kind?: 'flow' | 'handoff' | 'drop';
}

export interface WalkthroughStep {
  id: string;
  index: string;
  tag: string;
  headline: string;
  subtitle: string;
  activeNodes: string[];
  activeArcs: string[];
  routePackets: (b: BrandProfile) => RoutePacketSpec[];
  camera: {
    position: [number, number, number];
    target: [number, number, number];
  };
  labels: (b: BrandProfile) => StepLabelSpec[];
  traceCard: (b: BrandProfile) => TraceCardSpec;
}

export const TECHNIQUES_17_WEIGHTS: number[];
export const BRAND_PROFILES: Record<BrandProfileKey, BrandProfile>;
export const WALKTHROUGH_STEPS: WalkthroughStep[];
