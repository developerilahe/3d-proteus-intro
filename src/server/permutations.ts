import { RISKY_TLDS, TYPO_TLDS } from './lures.ts';
import { normalize, registrableDomain, toAscii } from './normalize.ts';
import type { Candidate } from './types.ts';

export const TECHNIQUES: Record<
  string,
  { importance: string; weight: number; family: string }
> = {
  character_substitution: { importance: 'High', weight: 70, family: 'substitution' },
  character_omission: { importance: 'Medium', weight: 50, family: 'typo' },
  character_insertion: { importance: 'Medium', weight: 50, family: 'typo' },
  character_repetition: { importance: 'Medium', weight: 45, family: 'typo' },
  character_transposition: { importance: 'Medium', weight: 55, family: 'typo' },
  hyphenation: { importance: 'Medium', weight: 45, family: 'keyword' },
  prefix_addition: { importance: 'High', weight: 65, family: 'keyword' },
  suffix_addition: { importance: 'High', weight: 70, family: 'keyword' },
  combosquatting: { importance: 'High', weight: 75, family: 'keyword' },
  tld_substitution: { importance: 'High', weight: 70, family: 'tld' },
  homoglyph: { importance: 'Very High', weight: 90, family: 'homoglyph' },
  idn_punycode: { importance: 'Very High', weight: 90, family: 'homoglyph' },
  subdomain_impersonation: { importance: 'High', weight: 65, family: 'subdomain' },
  brand_abbreviation: { importance: 'Medium', weight: 45, family: 'keyword' },
  brand_geography: { importance: 'Medium', weight: 50, family: 'keyword' },
  brand_service: { importance: 'High', weight: 70, family: 'keyword' },
  brand_typo_keyword: { importance: 'Very High', weight: 90, family: 'hybrid' },
};

const SUBSTITUTIONS: Record<string, string[]> = {
  a: ['4'], e: ['3'], i: ['1'], l: ['1'],
  o: ['0'], s: ['5'], g: ['9'], t: ['7'], b: ['8'],
};

const HOMOGLYPHS: Record<string, string[]> = {
  a: ['\u0430', '\u03b1'], b: ['\u044c'], c: ['\u0441'],
  d: ['\u0501'], e: ['\u0435', '\u03b5'], g: ['\u0261'],
  h: ['\u04bb'], i: ['\u0456', '\u03b9'], j: ['\u0458'],
  k: ['\u03ba'], l: ['\u04cf', '\u217c'], m: ['\u043c'],
  n: ['\u043f'], o: ['\u043e', '\u03bf'], p: ['\u0440', '\u03c1'],
  q: ['\u051b'], s: ['\u0455'], t: ['\u0442', '\u03c4'],
  u: ['\u03c5'], v: ['\u03bd'], w: ['\u051d'],
  x: ['\u0445'], y: ['\u0443'], z: ['\u03b6'],
};

const PREFIX_TOKENS = [
  'secure-', 'login-', 'signin-', 'verify-', 'account-', 'my-',
  'official-', 'support-', 'help-', 'auth-',
];

const SUFFIX_TOKENS = [
  '-login', '-signin', '-verify', '-secure', '-account',
  '-support', '-billing', '-help', '-portal', '-auth',
];

const COMBO_TOKENS = [
  'security', 'verification', 'support', 'billing', 'payment',
  'login', 'account', 'wallet', 'recovery', 'portal', 'help',
  'auth', 'safe', 'trust',
];

const SERVICE_TOKENS = [
  'verification', 'security', 'support', 'billing', 'recovery',
  'onboarding', 'compliance', 'kyc',
];

const GEOGRAPHY_TOKENS = [
  'azerbaijan', 'turkey', 'usa', 'uk', 'europe', 'asia',
  'germany', 'france', 'uae', 'india', 'global',
];

const SUBDOMAIN_PARENTS = [
  'login-portal.xyz',
  'secure-auth.click',
  'verify-billing.top',
  'account-verify.icu',
];

function emit(
  domain: string,
  technique: string,
  rule: string,
  prov: Record<string, string> = {}
): Candidate {
  const meta = TECHNIQUES[technique];
  return {
    domain,
    ascii_form: toAscii(domain),
    registrable: registrableDomain(domain),
    family: meta.family,
    rule,
    technique,
    importance: meta.importance,
    weight: meta.weight,
    provenance: prov,
  };
}

function baseBrand(brand: string): [string, string] {
  const norm = normalize(brand);
  if (norm.includes('.')) {
    const parts = norm.split('.');
    return [parts[0], parts.slice(1).join('.')];
  }
  return [norm, 'com'];
}

function joinLabel(label: string, tld: string): string {
  return `${label}.${tld}`;
}

function genSubstitution(label: string, tld: string): Candidate[] {
  const out: Candidate[] = [];
  for (let i = 0; i < label.length; i++) {
    const ch = label[i];
    for (const alt of SUBSTITUTIONS[ch] ?? []) {
      out.push(
        emit(
          joinLabel(label.slice(0, i) + alt + label.slice(i + 1), tld),
          'character_substitution',
          'digit_for_letter',
          { index: String(i), from_char: ch, to_char: alt }
        )
      );
    }
  }
  return out;
}

function genOmission(label: string, tld: string): Candidate[] {
  const out: Candidate[] = [];
  for (let i = 0; i < label.length; i++) {
    out.push(
      emit(
        joinLabel(label.slice(0, i) + label.slice(i + 1), tld),
        'character_omission',
        'drop_char',
        { index: String(i) }
      )
    );
  }
  return out;
}

function genInsertion(label: string, tld: string): Candidate[] {
  const out: Candidate[] = [];
  const insertChars = 'aeioulnrst';
  for (let i = 0; i <= label.length; i++) {
    for (const ch of insertChars) {
      out.push(
        emit(
          joinLabel(label.slice(0, i) + ch + label.slice(i), tld),
          'character_insertion',
          'insert_char',
          { index: String(i), to_char: ch }
        )
      );
    }
  }
  return out;
}

function genRepetition(label: string, tld: string): Candidate[] {
  const out: Candidate[] = [];
  for (let i = 0; i < label.length; i++) {
    out.push(
      emit(
        joinLabel(label.slice(0, i + 1) + label[i] + label.slice(i + 1), tld),
        'character_repetition',
        'double_char',
        { index: String(i) }
      )
    );
  }
  return out;
}

function genTransposition(label: string, tld: string): Candidate[] {
  const out: Candidate[] = [];
  for (let i = 0; i < label.length - 1; i++) {
    if (label[i] === label[i + 1]) continue;
    const swapped = label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2);
    out.push(
      emit(joinLabel(swapped, tld), 'character_transposition', 'swap_adjacent', {
        index: String(i),
      })
    );
  }
  return out;
}

function genHyphenation(label: string, tld: string): Candidate[] {
  const out: Candidate[] = [];
  for (let i = 1; i < label.length; i++) {
    out.push(
      emit(joinLabel(`${label.slice(0, i)}-${label.slice(i)}`, tld), 'hyphenation', 'insert_hyphen', {
        index: String(i),
      })
    );
  }
  return out;
}

function genPrefix(label: string, tld: string): Candidate[] {
  return PREFIX_TOKENS.map((tok) =>
    emit(joinLabel(tok + label, tld), 'prefix_addition', 'prepend_token', {
      token: tok.replace(/^-|-$/g, ''),
    })
  );
}

function genSuffix(label: string, tld: string): Candidate[] {
  return SUFFIX_TOKENS.map((tok) =>
    emit(joinLabel(label + tok, tld), 'suffix_addition', 'append_token', {
      token: tok.replace(/^-|-$/g, ''),
    })
  );
}

function genCombosquat(label: string, tld: string): Candidate[] {
  const out: Candidate[] = [];
  for (const tok of COMBO_TOKENS) {
    out.push(
      emit(joinLabel(`${label}${tok}`, tld), 'combosquatting', 'brand_plus_token', {
        token: tok,
      })
    );
    out.push(
      emit(joinLabel(`${tok}${label}`, tld), 'combosquatting', 'token_plus_brand', {
        token: tok,
      })
    );
  }
  return out;
}

function genTldSub(label: string, tld: string): Candidate[] {
  const allTlds = new Set<string>([
    ...RISKY_TLDS,
    ...TYPO_TLDS,
    'com', 'net', 'org', 'info', 'biz', 'io', 'co', 'tr', 'az',
  ]);
  allTlds.delete(tld);
  return Array.from(allTlds)
    .sort()
    .map((alt) =>
      emit(joinLabel(label, alt), 'tld_substitution', 'swap_tld', { to_tld: alt })
    );
}

function genHomoglyph(label: string, tld: string): Candidate[] {
  const out: Candidate[] = [];
  for (let i = 0; i < label.length; i++) {
    const ch = label[i];
    for (const alt of HOMOGLYPHS[ch] ?? []) {
      const codeHex = alt.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0');
      out.push(
        emit(
          joinLabel(label.slice(0, i) + alt + label.slice(i + 1), tld),
          'homoglyph',
          'single_char_swap',
          { index: String(i), from_char: ch, to_codepoint: `U+${codeHex}` }
        )
      );
    }
  }
  return out;
}

function genIdn(label: string, tld: string): Candidate[] {
  const out: Candidate[] = [];
  const idx = Array.from(label)
    .map((ch, i) => (ch in HOMOGLYPHS ? i : -1))
    .filter((i) => i >= 0);

  if (idx.length >= 2) {
    const chars = Array.from(label);
    for (const pos of idx) {
      const alts = HOMOGLYPHS[chars[pos]];
      if (alts?.length) chars[pos] = alts[0];
    }
    out.push(
      emit(joinLabel(chars.join(''), tld), 'idn_punycode', 'full_idn_label', {
        swapped: 'multiple',
      })
    );
  }
  if (idx.length > 0) {
    const chars = Array.from(label);
    for (const pos of idx) {
      const alts = HOMOGLYPHS[chars[pos]];
      if (alts?.length) chars[pos] = alts[0];
    }
    out.push(
      emit(joinLabel(chars.join(''), tld), 'idn_punycode', 'partial_idn_label', {
        swapped: String(idx.length),
      })
    );
  }
  return out;
}

function genSubdomain(label: string): Candidate[] {
  return SUBDOMAIN_PARENTS.map((parent) =>
    emit(`${label}.${parent}`, 'subdomain_impersonation', 'brand_as_subdomain', {
      parent,
    })
  );
}

function genAbbreviation(label: string, tld: string): Candidate[] {
  const out: Candidate[] = [];
  if (label.length < 4) return out;
  const first = label[0];
  const rest = label.slice(1);
  if (rest.length >= 3) {
    out.push(
      emit(joinLabel(first + rest.slice(1), tld), 'brand_abbreviation', 'drop_inner_letter', {
        index: '1',
      })
    );
  }
  out.push(
    emit(joinLabel(first + rest.slice(-2), tld), 'brand_abbreviation', 'first_plus_last_two', {
      index: 'last_two',
    })
  );
  for (const tok of ['login', 'secure', 'verify']) {
    out.push(
      emit(joinLabel(`${label[0]}${tok}`, tld), 'brand_abbreviation', 'initial_plus_keyword', {
        token: tok,
      })
    );
  }
  return out;
}

function genGeography(label: string, tld: string): Candidate[] {
  const out: Candidate[] = [];
  for (const geo of GEOGRAPHY_TOKENS) {
    out.push(
      emit(joinLabel(`${label}-${geo}`, tld), 'brand_geography', 'brand_plus_geo', {
        geo,
      })
    );
    out.push(
      emit(joinLabel(`${label}${geo}`, tld), 'brand_geography', 'brand_geo_concat', {
        geo,
      })
    );
  }
  return out;
}

function genService(label: string, tld: string): Candidate[] {
  return SERVICE_TOKENS.map((svc) =>
    emit(joinLabel(`${label}-${svc}`, tld), 'brand_service', 'brand_plus_service', {
      service: svc,
    })
  );
}

function genTypoKeyword(label: string, tld: string): Candidate[] {
  const out: Candidate[] = [];
  for (let i = 0; i < label.length; i++) {
    const ch = label[i];
    for (const alt of SUBSTITUTIONS[ch] ?? []) {
      const typo = label.slice(0, i) + alt + label.slice(i + 1);
      for (const kw of ['secure', 'login', 'verify']) {
        out.push(
          emit(joinLabel(`${typo}-${kw}`, tld), 'brand_typo_keyword', 'typo_plus_keyword', {
            index: String(i),
            keyword: kw,
          })
        );
      }
    }
  }
  if (label.length >= 3) {
    for (let i = 0; i < label.length - 1; i++) {
      const swapped = label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2);
      for (const kw of ['secure', 'verify']) {
        out.push(
          emit(
            joinLabel(`${swapped}-${kw}`, tld),
            'brand_typo_keyword',
            'transposed_plus_keyword',
            { keyword: kw }
          )
        );
      }
    }
  }
  return out;
}

// IMPORTANT ORDERING: repetition MUST run before insertion.
const GENERATORS: Array<(label: string, tld: string) => Candidate[]> = [
  genSubstitution,
  genOmission,
  genRepetition,
  genTransposition,
  genHyphenation,
  genPrefix,
  genSuffix,
  genCombosquat,
  genTldSub,
  genHomoglyph,
  genIdn,
  (label) => genSubdomain(label),
  genAbbreviation,
  genGeography,
  genService,
  genTypoKeyword,
  genInsertion,
];

export function generateCandidates(brand: string, maxCandidates = 2000): Candidate[] {
  const [label, tld] = baseBrand(brand);
  const seen = new Map<string, Candidate>();
  for (const gen of GENERATORS) {
    for (const c of gen(label, tld)) {
      if (c.ascii_form && !seen.has(c.ascii_form)) {
        seen.set(c.ascii_form, c);
      }
      if (seen.size >= maxCandidates) {
        return Array.from(seen.values());
      }
    }
  }
  return Array.from(seen.values());
}
