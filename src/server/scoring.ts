import { skeleton } from './confusables.ts';
import { luresIn, RISKY_TLDS, tldOf, TYPO_TLDS } from './lures.ts';
import { brandInSubdomainOnly, hasMixedScript, normalize, toAscii } from './normalize.ts';
import { damerauLevenshtein } from './similarity.ts';
import type { Candidate, DnsFacts, DomainEnrichment, Finding, Signal, Tier } from './types.ts';

const TECHNIQUE_CAP = 32;
const SIMILARITY_CAP = 20;
const LURE_CAP = 14;
const INFRA_CAP = 34;

const KNOWN_SAFE_DOMAINS = new Set<string>([
  'google.com',
  'google.net',
  'google.org',
  'google.co',
  'google.co.uk',
  'google.de',
  'google.fr',
  'youtube.com',
  'gmail.com',
  'googleapis.com',
  'apple.com',
  'icloud.com',
  'microsoft.com',
  'live.com',
  'outlook.com',
  'office.com',
  'github.com',
  'githubusercontent.com',
  'amazon.com',
  'aws.amazon.com',
  'cloudflare.com',
  'stripe.com',
  'openai.com',
  'wikipedia.org',
  'mozilla.org',
  'linkedin.com',
  'meta.com',
  'facebook.com',
  'instagram.com',
  'netflix.com',
  'paypal.com',
  'adobe.com',
  'salesforce.com',
  'zoom.us',
  'dropbox.com',
  'slack.com',
  'spotify.com',
  'vercel.com',
  'netlify.com',
]);

const TRUSTED_REGISTRAR_HINTS = [
  'markmonitor',
  'csc corporate',
  'safenames',
  'nom-iq',
  'corporate registrar',
  'aznic registrar',
  'google llc',
  'cloudflare',
];

const MUTATION_LABELS: Record<string, string> = {
  target_baseline: 'Verified target domain',
  digit_for_letter: 'Number-for-letter lookalike',
  drop_char: 'Missing-letter typo',
  insert_char: 'Extra-letter typo',
  double_char: 'Repeated-letter typo',
  swap_adjacent: 'Swapped-letters typo',
  insert_hyphen: 'Hyphenated lookalike',
  prepend_token: 'Added word at start',
  append_token: 'Added word at end',
  brand_plus_token: 'Brand + extra word',
  token_plus_brand: 'Extra word + brand',
  swap_tld: 'Different domain ending',
  single_char_swap: 'Lookalike foreign letter',
  full_idn_label: 'Lookalike foreign characters',
  partial_idn_label: 'Lookalike foreign characters',
  brand_as_subdomain: 'Brand name used as subdomain',
  drop_inner_letter: 'Shortened brand name',
  first_plus_last_two: 'Abbreviated brand name',
  initial_plus_keyword: 'Initial + keyword name',
  brand_plus_geo: 'Brand + region name',
  brand_geo_concat: 'Brand + region name',
  brand_plus_service: 'Brand + service word',
  typo_plus_keyword: 'Typo + trust word',
  transposed_plus_keyword: 'Swapped letters + trust word',
  unknown: 'Lookalike variation',
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

export function isKnownSafeDomain(domain: string): boolean {
  const norm = toAscii(normalize(domain)).toLowerCase();
  if (KNOWN_SAFE_DOMAINS.has(norm)) return true;
  for (const safe of KNOWN_SAFE_DOMAINS) {
    if (norm.endsWith(`.${safe}`)) return true;
  }
  return false;
}

export function isBenignDomain(
  brand: string,
  candidate: Candidate,
  facts: DnsFacts | null,
  enrichment?: DomainEnrichment | null
): boolean {
  const reg = toAscii(candidate.registrable).toLowerCase();
  const normBrand = toAscii(normalize(brand)).toLowerCase();
  const hasSpoofChars =
    hasMixedScript(candidate.registrable) ||
    toAscii(candidate.registrable)
      .split('.')
      .some((lbl) => lbl.startsWith('xn--'));

  if (candidate.rule === 'target_baseline' || reg === normBrand) {
    const repMalicious = enrichment?.reputation.data?.malicious ?? 0;
    return repMalicious === 0;
  }

  if (isKnownSafeDomain(reg) && !hasSpoofChars) {
    return true;
  }

  if (!facts || !facts.is_live) {
    return false;
  }

  const repMalicious = enrichment?.reputation.data?.malicious ?? 0;
  const repSuspicious = enrichment?.reputation.data?.suspicious ?? 0;
  if (repMalicious > 0 || repSuspicious > 1) {
    return false;
  }

  if (hasSpoofChars) return false;

  const lures = luresIn(reg);
  if (lures.length > 0) return false;

  const registrarLow = (facts.registrar || '').toLowerCase();
  const trustedRegistrar = TRUSTED_REGISTRAR_HINTS.some((hint) =>
    registrarLow.includes(hint)
  );
  const established = facts.created_days_ago !== null && facts.created_days_ago >= 365;
  const hasMailAuth = Boolean(facts.spf && facts.dmarc);

  if (trustedRegistrar && established) return true;
  if (established && hasMailAuth && facts.infra_role !== 'Bulletproof/High-Risk Hosting') {
    return true;
  }

  return false;
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
  const base = Math.min(TECHNIQUE_CAP, Math.round(candidate.weight * 0.34));
  return sig(
    'technique_baseline',
    MUTATION_LABELS[candidate.rule] ?? titleTechnique(candidate.technique),
    base,
    `Matches ${candidate.registrable}`
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
      sig('brand_in_subdomain_only', 'Uses your brand inside another site address', 12, candidate.registrable)
    );
  } else if (regLabelSk === bSk && regLabel !== bLabel) {
    out.push(
      sig('homoglyph_clone', 'Swaps letters to look visually identical', 14, candidate.domain)
    );
  } else if (regLabel === bLabel && reg !== normalize(brand)) {
    out.push(
      sig(
        'tld_swap_same_label',
        'Same brand name on a different domain ending',
        8,
        candidate.registrable
      )
    );
  } else {
    const dist = damerauLevenshtein(bLabel, regLabel);
    if (dist === 1) {
      out.push(sig('typosquat_distance_1', 'One-letter typo of your brand', 10));
    } else if (dist === 2) {
      out.push(sig('typosquat_distance_2', 'Close spelling typo of your brand', 6));
    } else if (reg.includes(bLabel)) {
      out.push(
        sig('brand_in_registrable', 'Includes your brand name in the address', 10, candidate.registrable)
      );
    }
  }

  if (hasMixedScript(reg)) {
    out.push(sig('mixed_script', 'Uses foreign lookalike characters', 4));
  }
  if (
    toAscii(candidate.registrable)
      .split('.')
      .some((lbl) => lbl.startsWith('xn--'))
  ) {
    out.push(
      sig(
        'punycode_label',
        'Internationalized lookalike spelling',
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
    out.push(sig('lure_present', 'Uses login or trust wording', 9, lures.join(', ')));
  }
  if (candidate.technique === 'brand_typo_keyword' || candidate.technique === 'combosquatting') {
    out.push(sig('technique_combo', 'Combines brand typo with trust wording', 5));
  }
  return capSignals(out, LURE_CAP);
}

function infraSignals(
  facts: DnsFacts | null,
  candidate: Candidate,
  enrichment?: DomainEnrichment | null
): Signal[] {
  const out: Signal[] = [];
  if (facts && facts.is_live) {
    if (facts.a_records.length > 0 || facts.aaaa_records.length > 0) {
      const ips = [...facts.a_records, ...facts.aaaa_records].slice(0, 2).join(', ');
      out.push(sig('a_record', 'Active website server online', 12, ips));
    }
    if (facts.mx_records.length > 0) {
      out.push(
        sig('mx_present', 'Email sending is active', 8, facts.mx_records.slice(0, 2).join(', '))
      );
    }
    if (!enrichment && !facts.spf) {
      out.push(sig('spf_absent', 'Missing email sender protection', 4));
    }
    if (!enrichment && !facts.dmarc) {
      out.push(sig('dmarc_absent', 'Missing email spoofing protection', 4));
    }
    if (facts.created_days_ago !== null && facts.created_days_ago < 30) {
      out.push(sig('fresh_domain', `Newly registered (${facts.created_days_ago} days ago)`, 10));
    } else if (facts.created_days_ago !== null && facts.created_days_ago < 90) {
      out.push(sig('recent_domain', `Registered ${facts.created_days_ago} days ago`, 5));
    }
    if (facts.infra_role === 'Bulletproof/High-Risk Hosting') {
      out.push(sig('high_risk_host', 'Hosted on high-risk infrastructure', 8, facts.asn_org || ''));
    }
  }
  if (enrichment && facts && facts.is_live) {
    if (enrichment.dns.spf.status === 'no_records') {
      out.push(sig('spf_absent', 'Missing email sender protection', 4));
    }
    if (
      enrichment.domain === enrichment.registrable &&
      enrichment.dns.dmarc.status === 'no_records'
    ) {
      out.push(sig('dmarc_absent', 'Missing email spoofing protection', 4));
    }
  }
  const tld = tldOf(candidate.registrable);
  if (facts?.is_live && (RISKY_TLDS.includes(tld) || TYPO_TLDS.includes(tld))) {
    out.push(sig('risky_tld', `High-abuse domain ending (.${tld})`, 3));
  }
  return capSignals(out, INFRA_CAP);
}

function tierOf(score: number, facts: DnsFacts | null, candidate: Candidate): Tier {
  const live = Boolean(facts && facts.is_live);
  const isSub = candidate.technique === 'subdomain_impersonation';
  if (score <= 15) return 'LOW';
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
  if (
    candidate.rule !== 'target_baseline' &&
    allowlist &&
    allowlist.has(candidate.registrable.toLowerCase())
  ) {
    return null;
  }

  const bLabel = brandLabelOf(brand);
  const regLabel = candidate.registrable.toLowerCase().split('.')[0];
  const similarityPct = computeSimilarityPct(bLabel, regLabel);

  // 1. Verified safe / legitimate / benign corporate domains score 0-12 (Low / Safe)
  if (isBenignDomain(brand, candidate, facts, enrichment)) {
    const benignSignals: Signal[] = [
      sig(
        'verified_legitimate',
        candidate.rule === 'target_baseline'
          ? 'Official target domain verified'
          : 'Established legitimate domain',
        0,
        facts?.registrar && facts.registrar !== 'N/A' ? facts.registrar : candidate.registrable
      ),
    ];

    let benignScore = 2;
    if (facts?.spf && facts?.dmarc) {
      benignSignals.push(sig('email_protected', 'Email protection active (SPF & DMARC)', 0));
      benignScore = 0;
    } else if (facts && facts.is_live && !facts.dmarc) {
      benignSignals.push(sig('dmarc_absent', 'Optional email policy (DMARC) not set', 6));
      benignScore = 6;
    } else if (candidate.rule !== 'target_baseline') {
      benignScore = 8;
    }

    if (facts && facts.a_records.length > 0) {
      benignSignals.push(
        sig('live_host', 'Active website server', 0, facts.a_records.slice(0, 2).join(', '))
      );
    }

    return {
      brand,
      domain: candidate.domain,
      candidate,
      facts,
      signals: benignSignals,
      tier: 'LOW',
      score: Math.min(15, benignScore),
      similarity_pct: similarityPct,
      mutation_type: mutationTypeOf(candidate),
      enrichment: enrichment ?? null,
    };
  }

  // 2. Dormant / unregistered / non-resolving permutations stay low-risk noise (2-14)
  if (!facts || !facts.is_live) {
    const lures = luresIn(candidate.registrable);
    const dormantBase = Math.min(14, Math.max(2, Math.round(candidate.weight / 9) + (lures.length > 0 ? 2 : 0)));
    const dormantSignals: Signal[] = [
      sig(
        'inactive_domain',
        facts?.created_days_ago !== null && facts?.created_days_ago !== undefined
          ? `Registered ${facts.created_days_ago} days ago, no active website`
          : 'Domain is inactive or unregistered',
        dormantBase,
        'No active website or mail server found'
      ),
    ];

    return {
      brand,
      domain: candidate.domain,
      candidate,
      facts,
      signals: dormantSignals,
      tier: 'LOW',
      score: dormantBase,
      similarity_pct: similarityPct,
      mutation_type: mutationTypeOf(candidate),
      enrichment: enrichment ?? null,
    };
  }

  // 3. Genuine active lookalike infrastructure with active signals
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
