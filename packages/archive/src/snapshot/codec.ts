/**
 * The tagged JSON codec of scan snapshots (A5, §4.2 `archive-scan/1`): Prisma rows contain
 * `BigInt` ids and `Date` timestamps, which plain JSON loses. Encoding maps
 *
 *     BigInt → {"$b":"<decimal>"}      Date → {"$d":"<ISO 8601>"}
 *
 * and passes plain JSON (strings, finite numbers, booleans, null, arrays, plain objects)
 * unchanged; `undefined` object properties are dropped (as JSON does). Anything else is refused
 * with `SnapshotCodecError`: Buffers and typed arrays, Prisma `Decimal`s and every other class
 * instance, functions, symbols, `undefined` inside arrays, non-finite numbers, invalid dates,
 * cycles, and plain objects that would be mistaken for a tag (a single `$b` or `$d` key).
 * Decoding is the exact inverse and refuses malformed tags. Errors name the path, never a value.
 */

export class SnapshotCodecError extends Error {
  constructor(readonly path: string) {
    super(`Snapshot value at ${path || '(root)'} cannot be encoded or decoded`);
    this.name = 'SnapshotCodecError';
  }
}

export type TaggedJson =
  null | boolean | number | string | TaggedJson[] | { [key: string]: TaggedJson };

const DECIMAL = /^-?(?:0|[1-9][0-9]*)$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function isPlainObject(value: object): boolean {
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function looksLikeTag(record: Record<string, unknown>): boolean {
  const keys = Object.keys(record).filter((k) => record[k] !== undefined);
  return keys.length === 1 && (keys[0] === '$b' || keys[0] === '$d');
}

function enc(value: unknown, path: string, seen: Set<object>): TaggedJson {
  if (value === null) return null;
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return value;
    case 'number':
      if (!Number.isFinite(value)) throw new SnapshotCodecError(path);
      return value;
    case 'bigint':
      return { $b: value.toString() };
    case 'object':
      break;
    default:
      throw new SnapshotCodecError(path);
  }
  const obj = value;
  if (obj instanceof Date) {
    if (Number.isNaN(obj.getTime())) throw new SnapshotCodecError(path);
    const iso = obj.toISOString();
    if (!ISO.test(iso)) throw new SnapshotCodecError(path);
    return { $d: iso };
  }
  if (seen.has(obj)) throw new SnapshotCodecError(path);
  seen.add(obj);
  try {
    if (Array.isArray(obj)) {
      return obj.map((item: unknown, i) => {
        if (item === undefined) throw new SnapshotCodecError(`${path}[${i}]`);
        return enc(item, `${path}[${i}]`, seen);
      });
    }
    if (!isPlainObject(obj)) throw new SnapshotCodecError(path);
    const record = obj as Record<string, unknown>;
    if (looksLikeTag(record)) throw new SnapshotCodecError(path);
    const out: Record<string, TaggedJson> = {};
    for (const key of Object.keys(record)) {
      if (record[key] === undefined) continue;
      out[key] = enc(record[key], path ? `${path}.${key}` : key, seen);
    }
    return out;
  } finally {
    seen.delete(obj);
  }
}

function dec(value: unknown, path: string): unknown {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new SnapshotCodecError(path);
    return value;
  }
  if (typeof value !== 'object') throw new SnapshotCodecError(path);
  if (Array.isArray(value)) return value.map((item, i) => dec(item, `${path}[${i}]`));
  if (!isPlainObject(value)) throw new SnapshotCodecError(path);
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length === 1 && keys[0] === '$b') {
    const v = record.$b;
    if (typeof v !== 'string' || !DECIMAL.test(v)) throw new SnapshotCodecError(path);
    return BigInt(v);
  }
  if (keys.length === 1 && keys[0] === '$d') {
    const v = record.$d;
    if (typeof v !== 'string' || !ISO.test(v)) throw new SnapshotCodecError(path);
    const d = new Date(v);
    if (Number.isNaN(d.getTime()) || d.toISOString() !== v) throw new SnapshotCodecError(path);
    return d;
  }
  const out: Record<string, unknown> = {};
  for (const key of keys) out[key] = dec(record[key], path ? `${path}.${key}` : key);
  return out;
}

/** Encodes a value (rows, row lists, a rows object) into tagged JSON. */
export function encodeTagged(value: unknown): TaggedJson {
  return enc(value, '', new Set());
}

/** Decodes tagged JSON (BigInt and Date restored). */
export function decodeTagged(value: unknown): unknown {
  return dec(value, '');
}

/** Encodes rows into the UTF-8 JSON text of tagged JSON. */
export function encodeRows(rows: unknown): string {
  return JSON.stringify(encodeTagged(rows));
}

/** Parses and decodes tagged JSON text; throws `SnapshotCodecError` on invalid JSON or tags. */
export function decodeRows<T = unknown>(text: string | Buffer): T {
  let parsed: unknown;
  try {
    parsed = JSON.parse(typeof text === 'string' ? text : text.toString('utf8'));
  } catch {
    throw new SnapshotCodecError('');
  }
  return dec(parsed, '') as T;
}
