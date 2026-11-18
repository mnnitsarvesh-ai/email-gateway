import { createHash } from 'node:crypto';

/**
 * Canonical JSON: object keys sorted by UTF-16 code unit order, no whitespace, `undefined`
 * properties omitted. Only JSON values are accepted (finite numbers, strings, booleans, null,
 * arrays and plain objects); anything else (BigInt, Date, Buffer, functions, `undefined` inside
 * arrays, non-finite numbers, cycles) throws a `TypeError` without echoing the value. Used for
 * hashes (`settings_sha256`, `criteria_sha256`, filter hashes) and the export manifest bytes.
 */
export function canonicalJson(value: unknown): string {
  return write(value, new Set());
}

function isPlainObject(value: object): boolean {
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function write(value: unknown, seen: Set<object>): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new TypeError('canonical JSON: non-finite number');
      return JSON.stringify(value);
    case 'object':
      break;
    default:
      throw new TypeError(`canonical JSON: unsupported ${typeof value}`);
  }
  const obj = value;
  if (seen.has(obj)) throw new TypeError('canonical JSON: cycle');
  seen.add(obj);
  try {
    if (Array.isArray(obj)) {
      return `[${obj
        .map((item: unknown) => {
          if (item === undefined) throw new TypeError('canonical JSON: undefined in an array');
          return write(item, seen);
        })
        .join(',')}]`;
    }
    if (!isPlainObject(obj)) throw new TypeError('canonical JSON: not a plain object');
    const record = obj as Record<string, unknown>;
    const keys = Object.keys(record)
      .filter((k) => record[k] !== undefined)
      .sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${write(record[k], seen)}`).join(',')}}`;
  } finally {
    seen.delete(obj);
  }
}

/** UTF-8 bytes of the canonical JSON. */
export function canonicalJsonBytes(value: unknown): Buffer {
  return Buffer.from(canonicalJson(value), 'utf8');
}

/** SHA-256 (lower-case hex) of bytes or of a UTF-8 string. */
export function sha256Hex(data: Buffer | Uint8Array | string): string {
  return createHash('sha256')
    .update(typeof data === 'string' ? Buffer.from(data, 'utf8') : data)
    .digest('hex');
}

/** SHA-256 of the canonical JSON of a document. */
export function canonicalSha256(value: unknown): string {
  return sha256Hex(canonicalJsonBytes(value));
}
