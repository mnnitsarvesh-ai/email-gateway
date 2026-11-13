import 'server-only';
import { isIP } from 'node:net';

/**
 * Browser address for the trusted forwarder header `X-EG-Client-IP` (design P5, ADR-0060).
 *
 * Verified empirically against `next start` 15.5 (WP2, design §13): Next's server sets
 * `X-Forwarded-For` to the socket peer **only when the request has none** (`??=`; it never
 * appends), and it does so before middleware and route handlers run. Therefore the address is
 * `entries[length - max(hops, 1)]`:
 * - `PORTAL_TRUST_PROXY_HOPS = H ≥ 1` (behind H proxies that each append their peer, e.g. the
 *   ingress): the entry the outermost trusted proxy appended, `entries[length - H]`.
 * - `H = 0` (nothing in front of the portal; local and CI only, enforced by the config): the last
 *   entry, which is the socket peer Next filled in. A client that talks to the portal directly
 *   and sends its own `X-Forwarded-For` can choose this value, which is why H = 0 is refused
 *   outside `APP_ENV=local|ci`.
 * Returns `null` when no valid address exists; the caller then omits the header.
 */
export function normalizeIp(raw: string): string | null {
  let value = raw.trim();
  if (value.startsWith('[') && value.includes(']')) value = value.slice(1, value.indexOf(']'));
  if (value.length === 0 || value.length > 45) return null;
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(value);
  if (mapped?.[1]) value = mapped[1];
  return isIP(value) === 0 ? null : value;
}

export function clientIpFromHeaders(headers: Headers, hops: number): string | null {
  const raw = headers.get('x-forwarded-for');
  if (!raw) return null;
  const entries = raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  const index = entries.length - Math.max(hops, 1);
  if (index < 0) return null;
  return normalizeIp(entries[index] ?? '');
}
