/**
 * Damerau–Levenshtein distance (optimal string alignment: insertions, deletions, substitutions
 * and transpositions of adjacent characters, each substring edited once) over code points.
 * Labels are at most 63 characters, so the O(n·m) table is small.
 */
export function damerauLevenshtein(a: string, b: string): number {
  const s = [...a];
  const t = [...b];
  const n = s.length;
  const m = t.length;
  if (n === 0) return m;
  if (m === 0) return n;
  const d: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = 0; i <= n; i += 1) (d[i] as number[])[0] = i;
  for (let j = 0; j <= m; j += 1) (d[0] as number[])[j] = j;
  for (let i = 1; i <= n; i += 1) {
    const row = d[i] as number[];
    const prev = d[i - 1] as number[];
    for (let j = 1; j <= m; j += 1) {
      const cost = s[i - 1] === t[j - 1] ? 0 : 1;
      let value = Math.min(
        (prev[j] as number) + 1,
        (row[j - 1] as number) + 1,
        (prev[j - 1] as number) + cost,
      );
      if (i > 1 && j > 1 && s[i - 1] === t[j - 2] && s[i - 2] === t[j - 1]) {
        value = Math.min(value, ((d[i - 2] as number[])[j - 2] as number) + 1);
      }
      row[j] = value;
    }
  }
  return (d[n] as number[])[m] as number;
}
