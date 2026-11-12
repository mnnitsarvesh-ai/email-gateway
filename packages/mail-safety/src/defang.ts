import { sanitizeDisplayText } from '@email-gateway/quarantine';
import { normalizeUrl } from '@email-gateway/url-security';

/**
 * Defanged display of a URL (step 5.3 Q11): never clickable, never fetched, never rewritten.
 * `http(s)://` becomes `hxxp(s)://`, every `.` of the host becomes `[.]`, userinfo is dropped (it
 * is the classic disguise `bank.example@evil.test`), the whole display is sanitized and cut to
 * 256 characters. Other schemes are shown as `<scheme>:[removed]` (no target).
 */

export const DEFANGED_URL_MAX_CHARS = 256;

export interface DefangedUrl {
  displayUrl: string;
  /** Defanged ASCII host, or null when the input is not an http(s) URL. */
  host: string | null;
  /** SHA-256 of the normalized identity form (`message_urls.url_sha256`), null when invalid. */
  identitySha256: string | null;
}

const defangHost = (host: string): string => host.replace(/\./g, '[.]');

const cut = (text: string): string =>
  sanitizeDisplayText(text, { maxChars: DEFANGED_URL_MAX_CHARS }).text;

/** Defangs free text that looks like a URL but does not parse (scheme and dots). */
function defangText(raw: string): string {
  return cut(raw.replace(/\bhttp(s?):\/\//gi, 'hxxp$1://').replace(/\./g, '[.]'));
}

export function defangUrl(url: string): DefangedUrl {
  const raw = url.trim();
  const scheme = /^([a-zA-Z][a-zA-Z0-9+.-]{0,31}):/.exec(raw)?.[1]?.toLowerCase() ?? null;
  if (scheme !== null && scheme !== 'http' && scheme !== 'https') {
    return { displayUrl: `${scheme}:[removed]`, host: null, identitySha256: null };
  }
  const candidate = scheme === null && /^www\./i.test(raw) ? `http://${raw}` : raw;
  const normalized = normalizeUrl(candidate);
  if (!normalized.ok) return { displayUrl: defangText(raw), host: null, identitySha256: null };
  const u = normalized.url;
  const host = u.hostKind === 'ipv6' ? `[${u.host}]` : u.host;
  // `identity` has no userinfo and no fragment; show the path and query after the host.
  const rest = u.identity
    .slice(u.identity.indexOf('//') + 2)
    .replace(/^[^/?#]*/, '')
    .replace(/\bhttp(s?):\/\//gi, 'hxxp$1://');
  const port = u.port === null ? '' : `:${u.port}`;
  return {
    displayUrl: cut(`hxxp${u.scheme === 'https' ? 's' : ''}://${defangHost(host)}${port}${rest}`),
    host: defangHost(host),
    identitySha256: u.sha256,
  };
}
