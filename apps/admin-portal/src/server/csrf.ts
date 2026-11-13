import 'server-only';
import type { ServerConfig } from '@/server/config';
import { timingSafeEqualString } from '@/server/session/seal';

/** Methods that never change state (P6). */
export function isSafeMethod(method: string): boolean {
  return method === 'GET' || method === 'HEAD';
}

/**
 * First line of P6: a state-changing request must come from the portal's own origin. `Origin`
 * must equal the origin of `PORTAL_PUBLIC_URL`; without `Origin`, `Sec-Fetch-Site: same-origin`
 * is accepted; neither → refused.
 */
export function isSameOriginRequest(
  method: string,
  headers: Headers,
  config: Pick<ServerConfig, 'PORTAL_PUBLIC_URL'>,
): boolean {
  if (isSafeMethod(method)) return true;
  const origin = headers.get('origin');
  if (origin !== null) return origin === config.PORTAL_PUBLIC_URL;
  return headers.get('sec-fetch-site') === 'same-origin';
}

/** Second line of P6: double submit of the CSRF cookie value in `X-CSRF-Token` (constant time). */
export function hasValidCsrfToken(headers: Headers, expected: string): boolean {
  const given = headers.get('x-csrf-token');
  if (!given || !expected) return false;
  return timingSafeEqualString(given, expected);
}
