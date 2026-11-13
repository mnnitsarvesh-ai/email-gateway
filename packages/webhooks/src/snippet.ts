/** Longest stored response snippet (characters; `webhook_delivery_attempts.response_snippet`). */
export const RESPONSE_SNIPPET_MAX_CHARS = 512;

const REDACTED = '[redacted]';
/** C0 and C1 control characters, DEL and the Unicode line/paragraph separators. */
// eslint-disable-next-line no-control-regex -- matching control characters is the point
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;
/** Applied in order; each replaces the whole match. */
const REDACTIONS: readonly RegExp[] = [
  /whsec_[A-Za-z0-9_-]+/g,
  /Bearer\s+\S+/gi,
  /(?:api[_-]?key|token|secret|password)\s*[:=]\s*\S+/gi,
  /[A-Za-z0-9+/=_-]{32,}/g,
];

/**
 * The stored snippet of an endpoint's response (W2, §9): the UTF-8 decoded body (lossy), control
 * characters replaced by spaces, secrets, bearer tokens, `key=value` credentials and runs of ≥ 32
 * base64/hex characters replaced by `[redacted]`, then cut to 512 characters (code points).
 * Redaction runs before the cut, so a secret straddling the limit is never partially kept.
 * `null` for an empty body. The result is untrusted text: returned as a JSON string, never HTML.
 */
export function responseSnippet(bytes: Buffer | Uint8Array | null | undefined): string | null {
  if (!bytes || bytes.length === 0) return null;
  let text = new TextDecoder('utf-8', { fatal: false }).decode(bytes).replace(CONTROL, ' ');
  for (const pattern of REDACTIONS) text = text.replace(pattern, REDACTED);
  const chars = Array.from(text);
  return chars.length > RESPONSE_SNIPPET_MAX_CHARS
    ? chars.slice(0, RESPONSE_SNIPPET_MAX_CHARS).join('')
    : text;
}
