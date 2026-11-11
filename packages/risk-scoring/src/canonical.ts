import { createHash } from 'node:crypto';

/**
 * Canonical JSON (step 5.1 R11): object keys sorted (UTF-16 code unit order), no whitespace,
 * arrays in their given order. Refuses values JSON cannot represent exactly: non-finite numbers,
 * `bigint`, `undefined` (also as an object property or array element), functions and symbols.
 * The scorer hashes the canonical input (`inputSha256`) and the canonical effective profile
 * (`profile_sha256`).
 */
export function canonicalJson(value: unknown): string {
  return encode(value, '$');
}

function encode(value: unknown, path: string): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value))
        throw new TypeError(`canonicalJson: non-finite number at ${path}`);
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) {
        return `[${value.map((item, i) => encode(item, `${path}[${i}]`)).join(',')}]`;
      }
      const proto = Object.getPrototypeOf(value) as unknown;
      if (proto !== Object.prototype && proto !== null) {
        throw new TypeError(`canonicalJson: not a plain object at ${path}`);
      }
      const record = value as Record<string, unknown>;
      const keys = Object.keys(record).sort();
      const parts: string[] = [];
      for (const key of keys) {
        parts.push(`${JSON.stringify(key)}:${encode(record[key], `${path}.${key}`)}`);
      }
      return `{${parts.join(',')}}`;
    }
    default:
      throw new TypeError(`canonicalJson: unsupported ${typeof value} at ${path}`);
  }
}

/** Lower-case hex SHA-256 of the UTF-8 encoding of `text`. */
export function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}
