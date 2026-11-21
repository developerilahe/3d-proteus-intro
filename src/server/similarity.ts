export function damerauLevenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const la = a.length;
  const lb = b.length;
  if (la === 0) return lb;
  if (lb === 0) return la;

  let dPrev2 = new Array<number>(lb + 1).fill(0);
  let dPrev = Array.from({ length: lb + 1 }, (_, idx) => idx);

  for (let i = 1; i <= la; i++) {
    const dCur = new Array<number>(lb + 1).fill(0);
    dCur[0] = i;
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let val = Math.min(dCur[j - 1] + 1, dPrev[j] + 1, dPrev[j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        val = Math.min(val, dPrev2[j - 2] + 1);
      }
      dCur[j] = val;
    }
    dPrev2 = dPrev;
    dPrev = dCur;
  }
  return dPrev[lb];
}

export function similarityRatio(a: string, b: string): number {
  if (!a && !b) return 1.0;
  const dist = damerauLevenshtein(a, b);
  return 1.0 - dist / Math.max(a.length, b.length);
}
