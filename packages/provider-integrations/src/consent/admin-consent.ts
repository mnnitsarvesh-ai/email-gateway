import { createHash, randomBytes } from 'node:crypto';
import { MICROSOFT_CLIENT_ID } from '../types';

/** The Graph resource the mail-flow admin consent covers (D3.1). */
export const GRAPH_DEFAULT_SCOPE = 'https://graph.microsoft.com/.default';

const STATE = /^[A-Za-z0-9_-]{43}$/;

export class ConsentUrlError extends Error {
  override readonly name = 'ConsentUrlError';
}

/**
 * The Microsoft admin-consent URL (D3.1):
 * `{loginUrl}/organizations/v2.0/adminconsent?client_id&scope&redirect_uri&state`. Every value
 * comes from configuration except `state` (32 random bytes, base64url, from
 * `createConsentState`).
 */
export function buildAdminConsentUrl(input: {
  loginUrl: string;
  clientId: string;
  redirectUri: string;
  state: string;
  scope?: string;
  /** Allow `http:` (`PROVIDER_ALLOW_HTTP_ENDPOINTS`, local/ci). */
  allowHttp?: boolean;
}): string {
  const login = parseUrl(input.loginUrl, input.allowHttp, 'loginUrl');
  const redirect = parseUrl(input.redirectUri, input.allowHttp, 'redirectUri');
  if (!MICROSOFT_CLIENT_ID.test(input.clientId))
    throw new ConsentUrlError('clientId must be a GUID');
  if (!STATE.test(input.state))
    throw new ConsentUrlError('state must be 32 random bytes (base64url)');
  const url = new URL(login.href);
  url.pathname = `${login.pathname.replace(/\/+$/, '')}/organizations/v2.0/adminconsent`;
  url.search = '';
  url.searchParams.set('client_id', input.clientId);
  url.searchParams.set('scope', input.scope ?? GRAPH_DEFAULT_SCOPE);
  url.searchParams.set('redirect_uri', redirect.href);
  url.searchParams.set('state', input.state);
  return url.href;
}

function parseUrl(value: string, allowHttp: boolean | undefined, name: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ConsentUrlError(`${name} must be an absolute URL`);
  }
  if (url.protocol !== 'https:' && !(allowHttp && url.protocol === 'http:')) {
    throw new ConsentUrlError(`${name} must use https`);
  }
  if (url.username || url.password || url.hash)
    throw new ConsentUrlError(`${name} is not acceptable`);
  return url;
}

/** A fresh consent state (returned once in the URL) and its stored SHA-256 (D3.1). */
export function createConsentState(): { state: string; sha256: string } {
  const state = randomBytes(32).toString('base64url');
  return { state, sha256: hashConsentState(state) };
}

/** Lower-case hex SHA-256 of a state (the only stored form; D3, D17). */
export function hashConsentState(state: string): string {
  return createHash('sha256').update(state, 'utf8').digest('hex');
}

export const isConsentStateShape = (state: unknown): state is string =>
  typeof state === 'string' && STATE.test(state);

/** At most 256 characters of a provider error description, control characters removed (D3.3). */
export function sanitizeProviderErrorDescription(text: unknown): string | null {
  if (typeof text !== 'string') return null;
  const clean = [...text]
    .map((c) => (c.charCodeAt(0) < 0x20 || c.charCodeAt(0) === 0x7f ? ' ' : c))
    .join('')
    .replace(/\s+/g, ' ')
    .trim();
  return clean ? clean.slice(0, 256) : null;
}
