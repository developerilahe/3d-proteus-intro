import { TIER_ORDER } from './types.ts';
import type { Finding, Tier } from './types.ts';

export function sortFindings<T extends Pick<Finding, 'tier' | 'score' | 'candidate'>>(
  findings: T[]
): T[] {
  return [...findings].sort((a, b) => {
    const tDiff = TIER_ORDER[a.tier] - TIER_ORDER[b.tier];
    if (tDiff !== 0) return tDiff;
    if (b.score !== a.score) return b.score - a.score;
    return a.candidate.registrable.localeCompare(b.candidate.registrable);
  });
}

export function tierCounts(findings: Array<Pick<Finding, 'tier'>>): Record<Tier, number> {
  const counts: Record<Tier, number> = {
    CRITICAL: 0,
    HIGH: 0,
    WATCH: 0,
    LOW: 0,
  };
  for (const f of findings) {
    counts[f.tier] = (counts[f.tier] ?? 0) + 1;
  }
  return counts;
}
