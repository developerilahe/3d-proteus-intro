import { fromAsciiLabel, normalize } from './normalize.ts';

export const CONFUSABLES: Record<string, string> = {
  '\u0430': 'a', '\u0432': 'b', '\u0435': 'e', '\u0451': 'e', '\u043a': 'k', '\u043c': 'm',
  '\u043d': 'h', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c', '\u0442': 't', '\u0443': 'y',
  '\u0445': 'x', '\u0456': 'i', '\u0458': 'j', '\u0455': 's', '\u0501': 'd', '\u0261': 'g',
  '\u04bb': 'h', '\u04cf': 'l', '\u051b': 'q', '\u051d': 'w', '\u0475': 'v', '\u044c': 'b',
  '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041a': 'K', '\u041c': 'M', '\u041d': 'H',
  '\u041e': 'O', '\u0420': 'P', '\u0421': 'C', '\u0422': 'T', '\u0423': 'Y', '\u0425': 'X',
  '\u0406': 'I', '\u0408': 'J', '\u0405': 'S',
  '\u03b1': 'a', '\u03b2': 'b', '\u03b3': 'y', '\u03b5': 'e', '\u03b7': 'n', '\u03b9': 'i',
  '\u03ba': 'k', '\u03bd': 'v', '\u03bf': 'o', '\u03c1': 'p', '\u03c4': 't', '\u03c5': 'u',
  '\u03c7': 'x', '\u03b6': 'z', '\u03bc': 'u',
  '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0397': 'H', '\u0399': 'I', '\u039a': 'K',
  '\u039d': 'N', '\u039f': 'O', '\u03a1': 'P', '\u03a4': 'T', '\u03a5': 'Y', '\u03a7': 'X',
  '\u0396': 'Z',
  '\u00e0': 'a', '\u00e1': 'a', '\u00e2': 'a', '\u00e3': 'a', '\u00e4': 'a', '\u00e5': 'a',
  '\u0101': 'a',
  '\u00e8': 'e', '\u00e9': 'e', '\u00ea': 'e', '\u00eb': 'e', '\u0113': 'e',
  '\u00ec': 'i', '\u00ed': 'i', '\u00ee': 'i', '\u00ef': 'i', '\u012b': 'i',
  '\u00f2': 'o', '\u00f3': 'o', '\u00f4': 'o', '\u00f5': 'o', '\u00f6': 'o', '\u00f8': 'o',
  '\u014d': 'o',
  '\u00f9': 'u', '\u00fa': 'u', '\u00fb': 'u', '\u00fc': 'u', '\u016b': 'u',
  '\u00f1': 'n', '\u00e7': 'c', '\u00fd': 'y', '\u00ff': 'y',
  '0': 'o', '1': 'l', '5': 's', '8': 'b', '3': 'e',
};

export const ASCII_MULTI: Array<[string, string]> = [
  ['rn', 'm'],
  ['vv', 'w'],
  ['cl', 'd'],
  ['ii', 'u'],
  ['l1', 'll'],
];

function skeletonLabel(label: string): string {
  let folded = Array.from(label)
    .map((ch) => CONFUSABLES[ch] ?? ch)
    .join('')
    .normalize('NFKC');
  for (const [src, dst] of ASCII_MULTI) {
    folded = folded.split(src).join(dst);
  }
  return folded.toLowerCase();
}

export function skeleton(domain: string): string {
  const norm = normalize(domain);
  if (!norm) return norm;
  return norm
    .split('.')
    .filter(Boolean)
    .map((lbl) => skeletonLabel(fromAsciiLabel(lbl)))
    .join('.');
}
