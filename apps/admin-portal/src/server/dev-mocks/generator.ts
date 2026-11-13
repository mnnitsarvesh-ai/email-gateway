import 'server-only';

export { DEV_MOCK_MARKER } from './types';

/**
 * Deterministic synthetic data for dev fixture mode (design P9). Everything is invented:
 * `*.example.test` domains, `example.com` addresses, ids derived from a seed. Never real data.
 */
export class SeededRandom {
  private state: number;

  constructor(seed: number | string) {
    this.state = typeof seed === 'number' ? seed >>> 0 : hashString(seed);
    if (this.state === 0) this.state = 0x9e3779b9;
  }

  /** mulberry32 */
  next(): number {
    this.state = (this.state + 0x6d2b79f5) >>> 0;
    let t = this.state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  int(min: number, max: number): number {
    return min + Math.floor(this.next() * (max - min + 1));
  }

  pick<T>(items: readonly T[]): T {
    const item = items[Math.floor(this.next() * items.length)];
    if (item === undefined) throw new Error('pick from an empty list');
    return item;
  }

  bool(probability = 0.5): boolean {
    return this.next() < probability;
  }

  /** RFC 4122 shaped (version 7 nibble) id, deterministic for the seed. */
  uuid(): string {
    const hex = Array.from({ length: 32 }, () => this.int(0, 15).toString(16)).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-7${hex.slice(13, 16)}-${(
      8 + this.int(0, 3)
    ).toString(16)}${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
  }

  /** A timestamp `daysBack` days before `anchor` at most, ISO 8601 with milliseconds. */
  recentIso(anchor: number, daysBack: number): string {
    return new Date(anchor - Math.floor(this.next() * daysBack * 86_400_000)).toISOString();
  }
}

export function hashString(value: string): number {
  let hash = 2166136261;
  for (let i = 0; i < value.length; i += 1) {
    hash ^= value.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

/** Stable id for a name (same input → same id across restarts). */
export function stableUuid(name: string): string {
  return new SeededRandom(name).uuid();
}

const FIRST = ['alex', 'sam', 'jordan', 'priya', 'chen', 'maria', 'omar', 'lena', 'ravi', 'noor'];
const LAST = ['lee', 'patel', 'garcia', 'nguyen', 'kim', 'silva', 'novak', 'haddad', 'berg', 'rao'];

export function syntheticPerson(random: SeededRandom): { email: string; displayName: string } {
  const first = random.pick(FIRST);
  const last = random.pick(LAST);
  return {
    email: `${first}.${last}${random.int(1, 99)}@example.com`,
    displayName: `${first[0]?.toUpperCase()}${first.slice(1)} ${last[0]?.toUpperCase()}${last.slice(1)}`,
  };
}

export function syntheticDomain(random: SeededRandom): string {
  return `${random.pick(['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot'])}${random.int(1, 9)}.example.test`;
}

/** Stable "now" so fixture data does not drift during a dev session (rounded to the hour). */
export function fixtureAnchor(): number {
  const now = Date.now();
  return now - (now % 3_600_000);
}

/**
 * Cursor pagination over an in-memory list: opaque base64url offset cursors, `limit` 1–100,
 * returning `{ [listKey]: page, nextCursor }` like the api (no totals).
 */
export function paginate<T>(
  items: readonly T[],
  query: URLSearchParams,
  listKey: 'data' | 'items' = 'data',
): Record<string, unknown> {
  const limit = Math.min(100, Math.max(1, Number(query.get('limit') ?? '25') || 25));
  const cursor = query.get('cursor');
  let offset = 0;
  if (cursor) {
    const decoded = Number.parseInt(Buffer.from(cursor, 'base64url').toString('utf8'), 10);
    offset = Number.isFinite(decoded) && decoded >= 0 ? decoded : 0;
  }
  const page = items.slice(offset, offset + limit);
  const next =
    offset + limit < items.length
      ? Buffer.from(String(offset + limit)).toString('base64url')
      : null;
  return { [listKey]: page, nextCursor: next };
}
