import { domainToASCII, domainToUnicode } from 'node:url';

export const MULTI_PART_SUFFIXES = new Set<string>([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'net.uk', 'ltd.uk', 'plc.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'net.nz', 'org.nz',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'co.in', 'net.in', 'org.in',
  'com.br', 'net.br', 'org.br',
  'co.za', 'org.za', 'net.za',
  'com.mx', 'org.mx', 'net.mx',
  'com.cn', 'net.cn', 'org.cn',
  'co.kr', 'or.kr',
  'co.il', 'org.il',
  'com.sg', 'com.hk', 'com.tw',
  'co.id', 'or.id',
  'com.ar', 'com.tr', 'com.pl', 'com.ua', 'com.vn',
]);

const SCRIPT_RANGES: Array<[number, number, string]> = [
  [0x0041, 0x005a, 'latin'],
  [0x0061, 0x007a, 'latin'],
  [0x00c0, 0x024f, 'latin'],
  [0x0370, 0x03ff, 'greek'],
  [0x0400, 0x04ff, 'cyrillic'],
  [0x0500, 0x052f, 'cyrillic'],
];

function scriptOf(ch: string): string | null {
  const cp = ch.codePointAt(0);
  if (cp === undefined) return null;
  for (const [lo, hi, script] of SCRIPT_RANGES) {
    if (cp >= lo && cp <= hi) return script;
  }
  return null;
}

export function scriptsIn(label: string): Set<string> {
  const out = new Set<string>();
  for (const ch of label) {
    const s = scriptOf(ch);
    if (s) out.add(s);
  }
  return out;
}

export function hasMixedScript(label: string): boolean {
  return scriptsIn(label).size > 1;
}

export function normalize(domain: string): string {
  if (!domain) return domain;
  return domain.trim().replace(/\.+$/, '').toLowerCase().normalize('NFC');
}

function isAscii(s: string): boolean {
  return /^[\x00-\x7F]*$/.test(s);
}

export function toAsciiLabel(label: string): string {
  if (!label) return label;
  if (isAscii(label)) return label.toLowerCase();
  const converted = domainToASCII(label);
  return (converted || label).toLowerCase();
}

export function fromAsciiLabel(label: string): string {
  if (!label) return label;
  const low = label.toLowerCase();
  if (!low.startsWith('xn--')) return low;
  const converted = domainToUnicode(low);
  return (converted || low).toLowerCase();
}

export function toAscii(domain: string): string {
  const norm = normalize(domain);
  if (!norm) return norm;
  const ascii = domainToASCII(norm);
  if (ascii) return ascii.toLowerCase();
  return norm
    .split('.')
    .filter(Boolean)
    .map(toAsciiLabel)
    .join('.');
}

export function fromAscii(domain: string): string {
  const norm = normalize(domain);
  if (!norm) return norm;
  const uni = domainToUnicode(norm);
  if (uni) return uni.toLowerCase();
  return norm
    .split('.')
    .filter(Boolean)
    .map(fromAsciiLabel)
    .join('.');
}

export function registrableDomain(domain: string): string {
  const norm = normalize(domain);
  if (!norm) return norm;
  const decoded = fromAscii(norm);
  const labels = decoded.split('.').filter(Boolean);
  if (labels.length < 2) return decoded;
  const tail2 = labels.slice(-2).join('.');
  if (labels.length >= 3 && MULTI_PART_SUFFIXES.has(tail2)) {
    return labels.slice(-3).join('.');
  }
  return tail2;
}

export function brandInSubdomainOnly(brandLabel: string, domain: string): boolean {
  const brand = brandLabel.split('.')[0].toLowerCase();
  const decoded = fromAscii(normalize(domain));
  const reg = registrableDomain(domain).toLowerCase();
  if (reg.includes(brand)) return false;
  const regLabels = new Set(reg.split('.'));
  const subLabels = decoded
    .split('.')
    .filter((l) => l && !regLabels.has(l.toLowerCase()))
    .map((l) => l.toLowerCase());
  return subLabels.some((l) => l.includes(brand));
}

export function isValidDomainInput(input: string): boolean {
  const trimmed = normalize(input);
  if (!trimmed || trimmed.length > 253) return false;
  if (/[\s/\\?#&:@]/.test(trimmed)) return false;
  const ascii = toAscii(trimmed);
  if (!ascii || ascii.length > 253) return false;
  return /^[a-z0-9.-]+$/.test(ascii) && !ascii.startsWith('.') && !ascii.endsWith('.');
}
