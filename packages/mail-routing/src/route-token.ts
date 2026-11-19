import { createHmac } from 'node:crypto';

/**
 * Microsoft 365 internal-routing route token (step 8.2 D9, ADR-0081; contracts §33).
 *
 * The delivery-worker prepends `X-EG-Route-Token: <token>` (after `X-Gateway-Trace`) to internal
 * deliveries to a domain linked to a Microsoft 365 connection with internal routing on and
 * outbound `active`. The customer's transport rule that routes internal mail through the gateway
 * excepts messages carrying the current token, and a second rule removes the header before
 * mailboxes. The token is a routing marker, not a security credential (the provider-relay proof
 * of ADR-0078 is the control), but it is still masked for readers without `integration:manage`.
 */

/** Header name, exactly as the delivery-worker writes it and the generated rules match it. */
export const ROUTE_TOKEN_HEADER = 'X-EG-Route-Token';

/** Length of a route token (characters of lower-case RFC 4648 base32, no padding). */
export const ROUTE_TOKEN_LENGTH = 32;

/** A route token: 32 lower-case base32 characters. */
export const ROUTE_TOKEN_PATTERN = /^[a-z2-7]{32}$/;

const KEY_HEX = /^[0-9a-f]{64}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

/** Lower-case RFC 4648 base32 without padding. */
export function base32Lower(bytes: Uint8Array): string {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out += BASE32_ALPHABET[(buffer << (5 - bits)) & 31];
  return out;
}

/**
 * `base32(HMAC-SHA256(PROVIDER_ROUTE_TOKEN_KEY, "route-token:v1:" + connectionPublicId + ":" +
 * version))[0..32]`. The key is the 64-hex-character `PROVIDER_ROUTE_TOKEN_KEY` (decoded to its
 * 32 bytes); the connection public id is the lower-case UUID of `provider_connections.public_id`
 * and the version is `route_token_version` (1-65535). Throws on any other input: a malformed
 * key or id is a configuration or programming error, never a token.
 */
export function deriveRouteToken(
  keyHex: string,
  connectionPublicId: string,
  version: number,
): string {
  if (!KEY_HEX.test(keyHex)) throw new Error('route token key must be 64 hex characters');
  if (!UUID.test(connectionPublicId)) {
    throw new Error('connectionPublicId must be a lower-case UUID');
  }
  if (!Number.isInteger(version) || version < 1 || version > 65_535) {
    throw new Error('route token version must be an integer 1-65535');
  }
  const mac = createHmac('sha256', Buffer.from(keyHex, 'hex'))
    .update(`route-token:v1:${connectionPublicId}:${version}`, 'utf8')
    .digest();
  return base32Lower(mac).slice(0, ROUTE_TOKEN_LENGTH);
}

/** The header line (without CRLF) the delivery-worker prepends. */
export function routeTokenHeaderLine(token: string): string {
  if (!ROUTE_TOKEN_PATTERN.test(token)) throw new Error('not a route token');
  return `${ROUTE_TOKEN_HEADER}: ${token}`;
}
