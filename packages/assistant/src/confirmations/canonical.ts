import { createHash } from 'node:crypto';

/**
 * Canonical JSON (step AI-2 D3): object keys sorted (code-point order) at every depth,
 * `undefined` members dropped (array holes and `undefined` items become `null`), `bigint` as
 * decimal strings, `Date` as ISO strings, non-finite numbers refused. The same algorithm as
 * `packages/provider-integrations/src/impact/impact-token.ts`; the assistant keeps its own copy so
 * it depends on no other workspace package. One hardening: an own `__proto__` member (possible in
 * parsed JSON) is serialized like any other member instead of being swallowed.
 */
export function canonicalJson(value: unknown): string {
  const walk = (v: unknown): unknown => {
    if (v === null) return null;
    if (typeof v === 'bigint') return v.toString();
    if (v instanceof Date) return v.toISOString();
    if (typeof v === 'number') {
      if (!Number.isFinite(v)) throw new TypeError('canonicalJson: non-finite number');
      return v;
    }
    if (typeof v === 'string' || typeof v === 'boolean') return v;
    if (Array.isArray(v)) return v.map((item) => (item === undefined ? null : walk(item)));
    if (typeof v === 'object') {
      // A null-prototype object keeps an own `__proto__` member (e.g. from JSON.parse) as data.
      const out = Object.create(null) as Record<string, unknown>;
      for (const key of Object.keys(v).sort()) {
        const member = (v as Record<string, unknown>)[key];
        if (member !== undefined && typeof member !== 'function') out[key] = walk(member);
      }
      return out;
    }
    throw new TypeError(`canonicalJson: unsupported value of type ${typeof v}`);
  };
  return JSON.stringify(walk(value));
}

/** SHA-256 of a UTF-8 string, lower-case hex (64 characters). */
export function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}
