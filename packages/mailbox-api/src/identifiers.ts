/**
 * Identifiers and secrets of API-mode copies (design §5 "Identifiers", D7.6, D9, D10.3, D12.4).
 * Pure functions with fixed vectors in the tests; any change is a breaking change of stored data.
 */
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

const sha256Hex = (value: string): string =>
  createHash('sha256').update(value, 'utf8').digest('hex');

/**
 * The Message-ID as the dedupe hash reads it: surrounding whitespace removed, then one pair of
 * enclosing angle brackets, then whitespace again. Null when nothing is left.
 */
export function normalizeMessageId(messageId: string | null | undefined): string | null {
  if (messageId === null || messageId === undefined) return null;
  let value = messageId.trim();
  if (value.startsWith('<') && value.endsWith('>')) value = value.slice(1, -1).trim();
  return value.length > 0 ? value : null;
}

/**
 * Dedupe hash of a copy (D7 step 6): SHA-256 hex of
 * `api-copy/1\0<organizationId>\0<Message-ID without angle brackets and surrounding whitespace>`.
 * Null without a usable Message-ID (such copies are never deduplicated).
 */
export function copyMessageIdHash(
  organizationId: bigint | number | string,
  messageId: string | null | undefined,
): string | null {
  const normalized = normalizeMessageId(messageId);
  if (normalized === null) return null;
  return sha256Hex(`api-copy/1\0${organizationId.toString()}\0${normalized}`);
}

export interface CopyRef {
  /** `api_mode_connections.public_id`. */
  connectionPublicId: string;
  /** `api_mailboxes.public_id`. */
  mailboxPublicId: string;
  /** Graph message id / Gmail message id. */
  providerMessageId: string;
}

/**
 * Ingest key of a fetched copy (`message_identities.ingest_key`, ≤ 128): `v2:mbx:` + SHA-256 hex
 * of `<connectionPublicId>|<mailboxPublicId>|<providerMessageId>`.
 */
export function ingestKeyForCopy(ref: CopyRef): string {
  return `v2:mbx:${sha256Hex(
    `${ref.connectionPublicId}|${ref.mailboxPublicId}|${ref.providerMessageId}`,
  )}`;
}

/**
 * EML object ref of a fetched copy: the first 32 hex characters of SHA-256 of
 * `mbx|<connectionPublicId>|<mailboxPublicId>|<providerMessageId>|<organizationId>`.
 */
export function objectRefForCopy(
  ref: CopyRef & { organizationId: bigint | number | string },
): string {
  return sha256Hex(
    `mbx|${ref.connectionPublicId}|${ref.mailboxPublicId}|${ref.providerMessageId}|${ref.organizationId.toString()}`,
  ).slice(0, 32);
}

/**
 * The mail-bucket key of a fetched copy (D10.3, the smtp-adapter's layout):
 * `org/<organizationId>/eml/<yyyy>/<mm>/<dd>/<objectRef>.eml` with the UTC date of `at`.
 */
export function emlObjectKeyForCopy(
  ref: CopyRef & { organizationId: bigint | number | string },
  at: Date,
): string {
  const iso = at.toISOString();
  return `org/${ref.organizationId.toString()}/eml/${iso.slice(0, 4)}/${iso.slice(5, 7)}/${iso.slice(8, 10)}/${objectRefForCopy(ref)}.eml`;
}

/**
 * D9 takes "the first 48 characters" of the base64url HMAC; a SHA-256 HMAC is 32 bytes, i.e.
 * 43 base64url characters, so the client state is the whole digest (43 characters, within
 * Graph's 128-character limit). The `slice(0, 48)` of the design is kept verbatim.
 */
export const CLIENT_STATE_LENGTH = 43;

/**
 * The Graph subscription client state of a mailbox (D9, D10.4): the first 48 characters of
 * base64url(HMAC-SHA256(secret, `api-mode-graph-client-state/1\0<mailboxPublicId>\0<version>`))
 * (= the 43-character digest). Derived in the mailbox-worker from `API_MODE_NOTIFICATION_SECRET`;
 * only its hash is stored.
 */
export function deriveClientState(
  secret: string,
  mailboxPublicId: string,
  version: number,
): string {
  if (secret.length === 0) throw new Error('client_state_secret_required');
  if (!Number.isInteger(version) || version < 0) throw new Error('client_state_version_invalid');
  return createHmac('sha256', secret)
    .update(`api-mode-graph-client-state/1\0${mailboxPublicId}\0${version}`, 'utf8')
    .digest('base64url')
    .slice(0, 48);
}

/** `api_mailboxes.client_state_hash`: SHA-256 hex of the client state value. */
export function clientStateHash(value: string): string {
  return sha256Hex(value);
}

/**
 * Constant-time check of a notification's client state against a stored hash (D12.4). False for
 * a missing value or a malformed stored hash.
 */
export function clientStateMatches(
  value: string | null | undefined,
  storedHash: string | null,
): boolean {
  if (typeof value !== 'string' || storedHash === null || !/^[0-9a-f]{64}$/.test(storedHash)) {
    return false;
  }
  return timingSafeEqual(
    Buffer.from(clientStateHash(value), 'hex'),
    Buffer.from(storedHash, 'hex'),
  );
}
