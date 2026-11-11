/**
 * A small seeded PRNG (mulberry32) for the synthetic dataset generator and the property tests.
 * Never used by the scorer (which has no randomness).
 */
export class Prng {
  private state: number;

  constructor(seed: number) {
    this.state = seed >>> 0;
  }

  /** Uniform in [0, 1). */
  next(): number {
    this.state = (this.state + 0x6d2b79f5) >>> 0;
    let t = this.state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  /** Integer in [min, max]. */
  int(min: number, max: number): number {
    return min + Math.floor(this.next() * (max - min + 1));
  }

  chance(p: number): boolean {
    return this.next() < p;
  }

  pick<T>(values: readonly T[]): T {
    if (values.length === 0) throw new Error('pick from an empty list');
    return values[this.int(0, values.length - 1)]!;
  }

  /** `count` distinct values of `values` (fewer when the list is shorter). */
  sample<T>(values: readonly T[], count: number): T[] {
    const copy = [...values];
    const out: T[] = [];
    while (out.length < count && copy.length > 0) {
      out.push(copy.splice(this.int(0, copy.length - 1), 1)[0]!);
    }
    return out;
  }

  shuffle<T>(values: readonly T[]): T[] {
    return this.sample(values, values.length);
  }
}
