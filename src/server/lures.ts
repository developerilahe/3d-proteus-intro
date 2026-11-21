import { fromAscii, normalize, registrableDomain } from './normalize.ts';

export const LURE_WORDS: string[] = [
  'login', 'signin', 'verify', 'secure', 'account', 'update',
  'support', 'billing', 'payment', 'invoice', 'auth', 'portal',
  'confirm', 'recovery', 'wallet', 'helpdesk', 'unlock', 'alert',
  'notice', 'mail',
];

export const RISKY_TLDS: string[] = [
  'zip', 'mov', 'xyz', 'top', 'buzz', 'click', 'live', 'icu',
  'cyou', 'rest', 'shop', 'cam', 'sbs', 'cfd', 'monster', 'lol',
];

export const TYPO_TLDS: string[] = [
  'cm', 'co', 'om', 'con', 'comm', 'net', 'org', 'info',
];

export function luresIn(domain: string): string[] {
  const reg = fromAscii(registrableDomain(domain)).toLowerCase();
  return LURE_WORDS.filter((w) => reg.includes(w));
}

export function hasHyphenatedLure(domain: string): boolean {
  const decoded = fromAscii(registrableDomain(domain)).toLowerCase();
  if (!decoded.includes('-')) return false;
  return LURE_WORDS.some((w) => decoded.includes(`-${w}`) || decoded.includes(`${w}-`));
}

export function tldOf(domain: string): string {
  const parts = normalize(domain).split('.');
  return parts.length ? parts[parts.length - 1] : '';
}
