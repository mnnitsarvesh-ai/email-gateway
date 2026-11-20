/**
 * Text sanitizing and credential-key scrubbing for everything that leaves an API response towards
 * the model or a stored card (design D8).
 */

/** Strings are capped at this many characters (code points) in envelopes and cards. */
export const STRING_MAX_CHARS = 300;

// C0 controls except \t (09) and \n (0A); DEL and C1 controls (7F-9F).
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g;
// Bidi embeddings/overrides (202A-202E) and isolates (2066-2069), plus the invisible
// left-to-right / right-to-left marks (200E, 200F).
const BIDI = /[\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;
// Zero-width space, non-joiner, joiner, word joiner, BOM / zero-width no-break space.
const ZERO_WIDTH = /[\u200B-\u200D\u2060\uFEFF]/g;

/** Removes control, bidi and zero-width characters and caps the length (code points, `…`). */
export function sanitizeText(value: string, max = STRING_MAX_CHARS): string {
  const cleaned = value.replace(CONTROL, '').replace(BIDI, '').replace(ZERO_WIDTH, '');
  if (cleaned.length <= max) return cleaned;
  const points = Array.from(cleaned);
  if (points.length <= max) return cleaned;
  return `${points.slice(0, Math.max(0, max - 1)).join('')}…`;
}

/**
 * The audit credential-key pattern (`apps/api/src/audit/audit.service.ts`
 * `SENSITIVE_METADATA_KEY`) and its safe list (`SAFE_METADATA_KEYS`), identical so the assistant
 * drops exactly what the audit log drops.
 */
export const SENSITIVE_KEY = /password|secret|token|code|key$/i;
export const SAFE_KEYS: ReadonlySet<string> = new Set([
  'statusCode',
  'planCode',
  'featureKey',
  'limitKey',
  'roleKey',
  'permissionKey',
]);

export function isCredentialKey(key: string): boolean {
  return SENSITIVE_KEY.test(key) && !SAFE_KEYS.has(key);
}

/**
 * A JSON-safe deep copy with credential keys dropped at any depth and every string sanitized.
 * Used for cards (no `untrusted_text` wrapping; the portal renders text, never HTML).
 */
export function scrubValue(value: unknown, depth = 0, maxDepth = 12): unknown {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return sanitizeText(value);
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'bigint') return value.toString(10);
  if (depth >= maxDepth) return null;
  if (Array.isArray(value)) return value.map((item) => scrubValue(item, depth + 1, maxDepth));
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (isCredentialKey(key) || item === undefined || typeof item === 'function') continue;
      out[sanitizeText(key, 64)] = scrubValue(item, depth + 1, maxDepth);
    }
    return out;
  }
  return null;
}
