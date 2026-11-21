import { skeleton } from './confusables.ts';
import { luresIn, RISKY_TLDS, tldOf, TYPO_TLDS } from './lures.ts';
import { brandInSubdomainOnly, hasMixedScript, normalize, toAscii } from './normalize.ts';
import { damerauLevenshtein } from './similarity.ts';
import type { Candidate, DnsFacts, DomainEnrichment, Finding, Signal, Tier } from './types.ts';

const TECHNIQUE_CAP = 50;
const SIMILARITY_CAP = 25;
const LURE_CAP = 10;
const INFRA_CAP = 15;

const MUTATION_LABELS: Record<string, string> = {
  digit_for_letter: 'Digit-for-letter substitution',
  drop_char: 'Character omission',
  insert_char: 'Character insertion',
  double_char: 'Character repetition',
  swap_adjacent: 'Adjacent character transposition',
  insert_hyphen: 'Hyphenation',
  prepend_token: 'Prefix token addition',
  append_token: 'Suffix token addition',
  brand_plus_token: 'Combosquatting (brand + token)',
  token_plus_brand: 'Combosquatting (token + brand)',
  swap_tld: 'TLD substitution',
  single_char_swap: 'Single-character homoglyph swap',
  full_idn_label: 'Full IDN label (Punycode)',
  partial_idn_label: 'Partial IDN label (Punycode)',
  brand_as_subdomain: 'Brand as subdomain of attacker parent',
  drop_inner_letter: 'Brand abbreviation',
  first_plus_last_two: 'Abbreviated brand (first + last two)',
  initial_plus_keyword: 'Initial + keyword abbreviation',
  brand_plus_geo: 'Brand + geography',
  brand_geo_concat: 'Brand + geography (concatenated)',
  brand_plus_service: 'Brand + service word',
  typo_plus_keyword: 'Typo + keyword combo',
  transposed_plus_keyword: 'Transposition + keyword combo',
  unknown: 'Unclassified mutation',
};

function titleTechnique(technique: string): string {
  return technique
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function sig(key: string, label: string, points: number, evidence = ''): Signal {
  return { key, label, points, evidence };
}

function capSignals(signals: Signal[], cap: number): Signal[] {
  const out: Signal[] = [];
  let total = 0;
  for (const s of signals) {
    if (total + s.points <= cap) {
      out.push(s);
      total += s.points;
    }
  }
  return out;
}

function brandLabelOf(brand: string): string {
  return normalize(brand).split('.')[0];
}

export function computeSimilarityPct(brandLabel: string, regLabel: string): number {
  if (!regLabel) return 0;
  if (regLabel === brandLabel) return 100;
  const brandSk = skeleton(brandLabel);
  const regSk = skeleton(regLabel);
  if (regSk === brandSk && regLabel !== brandLabel) return 96;
  if (brandSk && regSk.includes(brandSk)) {
    const extra = Math.max(0, regSk.length - brandSk.length);
    return Math.max(65, 100 - 3 * extra);
  }
  const dist = damerauLevenshtein(brandLabel, regLabel);
  const ratio = 1.0 - dist / Math.max(brandLabel.length, regLabel.length);
  return Math.max(0, Math.min(100, Math.round(ratio * 100)));
}

function techniqueSignal(candidate: Candidate): Signal {
  const base = Math.min(TECHNIQUE_CAP, Math.floor(candidate.weight / 2));
  return sig(
    'technique_baseline',
    `Technique: ${titleTechnique(candidate.technique)} (${candidate.importance})`,
    base,
    `Initial heuristic weight ${candidate.weight}/100 — adjusted by context`
  );
}

function similaritySignals(brand: string, candidate: Candidate): Signal[] {
  const out: Signal[] = [];
  const bLabel = brandLabelOf(brand);
  const bSk = skeleton(bLabel);
  const reg = candidate.registrable.toLowerCase();
  const regLabel = reg.split('.')[0];
  const regLabelSk = skeleton(regLabel);

  if (brandInSubdomainOnly(bLabel, candidate.domain)) {
    out.push(
      sig('brand_in_subdomain_only', 'Brand only in subdomain', 15, `eTLD+1=${candidate.registrable}`)
    );
  } else if (regLabelSk === bSk && regLabel !== bLabel) {
    out.push(
      sig('homoglyph_clone', 'Skeleton-identical clone', 15, `'${regLabel}' folds to '${regLabelSk}'`)
    );
  } else if (regLabel === bLabel && reg !== normalize(brand)) {
    out.push(
      sig(
        'tld_swap_same_label',
        'Brand label reused on another TLD',
        12,
        `eTLD+1=${candidate.registrable}`
      )
    );
  } else {
    const dist = damerauLevenshtein(bLabel, regLabel);
    if (dist === 1) {
      out.push(sig('typosquat_distance_1', 'Edit distance 1 from brand', 12));
    } else if (dist === 2) {
      out.push(sig('typosquat_distance_2', 'Edit distance 2 from brand', 7));
    } else if (reg.includes(bLabel)) {
      out.push(
        sig('brand_in_registrable', 'Brand embedded in registrable', 12, `'${bLabel}' in '${reg}'`)
      );
    }
  }

  if (hasMixedScript(reg)) {
    out.push(sig('mixed_script', 'Mixed-script label (Latin + Cyrillic/Greek)', 3));
  }
  if (
    toAscii(candidate.registrable)
      .split('.')
      .some((lbl) => lbl.startsWith('xn--'))
  ) {
    out.push(
      sig(
        'punycode_label',
        'Punycode (xn--) label present',
        2,
        candidate.ascii_form || candidate.domain
      )
    );
  }

  return capSignals(out, SIMILARITY_CAP);
}

function lureSignals(candidate: Candidate): Signal[] {
  const out: Signal[] = [];
  const lures = luresIn(candidate.registrable);
  if (lures.length > 0) {
    out.push(sig('lure_present', 'Brand-lure token present', 6, lures.join(', ')));
  }
  if (candidate.technique === 'brand_typo_keyword' || candidate.technique === 'combosquatting') {
    out.push(sig('technique_combo', 'Combined typo + lure construction', 4));
  }
  return capSignals(out, LURE_CAP);
}

function infraSignals(
  facts: DnsFacts | null,
  candidate: Candidate,
  enrichment?: DomainEnrichment | null
): Signal[] {
  const out: Signal[] = [];
  if (facts) {
    if (facts.a_records.length > 0 || facts.aaaa_records.length > 0) {
      const ips = [...facts.a_records, ...facts.aaaa_records].slice(0, 2).join(', ');
      out.push(sig('a_record', 'Live DNS (A/AAAA)', 5, ips));
    }
    if (facts.mx_records.length > 0) {
      out.push(
        sig('mx_present', 'Mail-enabled (MX present)', 4, facts.mx_records.slice(0, 2).join(', '))
      );
    }
    if (!enrichment && !facts.spf) {
      out.push(sig('spf_absent', 'SPF record absent or weak', 2));
    }
    if (!enrichment && !facts.dmarc) {
      out.push(sig('dmarc_absent', 'DMARC record absent', 2));
    }
    if (facts.created_days_ago !== null && facts.created_days_ago < 30) {
      out.push(sig('fresh_domain', `Registered ${facts.created_days_ago}d ago`, 2));
    }
  }
  if (enrichment && facts && facts.is_live) {
    if (enrichment.dns.spf.status === 'no_records') {
      out.push(sig('spf_absent', 'SPF record absent', 2));
    }
    if (
      enrichment.domain === enrichment.registrable &&
      enrichment.dns.dmarc.status === 'no_records'
    ) {
      out.push(sig('dmarc_absent', 'DMARC record absent', 2));
    }
  }
  const tld = tldOf(candidate.registrable);
  if (RISKY_TLDS.includes(tld) || TYPO_TLDS.includes(tld)) {
    out.push(sig('risky_tld', `Risky/typo TLD .${tld}`, 2));
  }
  return capSignals(out, INFRA_CAP);
}

function tierOf(score: number, facts: DnsFacts | null, candidate: Candidate): Tier {
  const live = Boolean(facts && facts.is_live);
  const isSub = candidate.technique === 'subdomain_impersonation';
  if (live && score >= 75) return 'CRITICAL';
  if (live && isSub && score >= 60) return 'CRITICAL';
  if (live && score >= 55) return 'HIGH';
  if (score >= 35) return 'WATCH';
  return 'LOW';
}

function mutationTypeOf(candidate: Candidate): string {
  return MUTATION_LABELS[candidate.rule] ?? titleTechnique(candidate.technique);
}

export function analyzeCandidate(
  brand: string,
  candidate: Candidate,
  facts: DnsFacts | null,
  allowlist?: Set<string>,
  enrichment?: DomainEnrichment | null
): Finding | null {
  if (candidate.registrable.toLowerCase() === normalize(brand)) {
    return null;
  }
  if (allowlist && allowlist.has(candidate.registrable.toLowerCase())) {
    return null;
  }

  const bLabel = brandLabelOf(brand);
  const regLabel = candidate.registrable.toLowerCase().split('.')[0];
  const similarityPct = computeSimilarityPct(bLabel, regLabel);

  const signals = [
    techniqueSignal(candidate),
    ...similaritySignals(brand, candidate),
    ...lureSignals(candidate),
    ...infraSignals(facts, candidate, enrichment),
  ];

  if (signals.length === 0) return null;
  const total = Math.min(100, signals.reduce((sum, s) => sum + s.points, 0));
  const tier = tierOf(total, facts, candidate);

  return {
    brand,
    domain: candidate.domain,
    candidate,
    facts,
    signals,
    tier,
    score: total,
    similarity_pct: similarityPct,
    mutation_type: mutationTypeOf(candidate),
    enrichment: enrichment ?? null,
  };
}
