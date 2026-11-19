/**
 * Deterministic keys (step 8.4 D3, D8, D14, D15): the mail processing key shared by the live
 * consumer and the catch-up job, provider page keys, restriction subject hashes and HMAC keys of
 * values that must never be stored in clear (attempted e-mails, subject keys, recipient domains).
 */
import { createHash, createHmac } from 'node:crypto';

export { atoMailboxSha256, atoSubjectHash } from '@email-gateway/security-contracts';

const sha256 = (value: string): Buffer => createHash('sha256').update(value, 'utf8').digest();

export const sha256Hex = (value: string): string =>
  createHash('sha256').update(value, 'utf8').digest('hex');

/** RFC 9562 UUID (version nibble 8, variant 10) from the first 16 bytes of a digest. */
export function uuidFromDigest(digest: Buffer): string {
  const bytes = Buffer.from(digest.subarray(0, 16));
  bytes[6] = (bytes[6]! & 0x0f) | 0x80;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * `atoMailKey(messageId, scanId)` (D3): the `processOnce` event id of one outbound message's ATO
 * processing, identical for the live `ato.mail` consumer and the catch-up job, so a message is
 * processed once whichever path sees it first. UUID of SHA-256(`eg-ato-mail/v1\0<messageId>\0<scanId>`).
 */
export function atoMailKey(messageId: bigint | string, scanId: bigint | string): string {
  return uuidFromDigest(sha256(`eg-ato-mail/v1\0${messageId.toString()}\0${scanId.toString()}`));
}

/**
 * `providerPageKey` (D15): the `processOnce` key of one provider ingestion page, UUID of
 * SHA-256(`integrationId|stream|cursorBefore`) (an empty cursor for the first page).
 */
export function providerPageKey(
  integrationId: bigint | string,
  stream: string,
  cursorBefore: string | null,
): string {
  return uuidFromDigest(sha256(`${integrationId.toString()}|${stream}|${cursorBefore ?? ''}`));
}

/**
 * `ato_smtp_restrictions.subject_hash` (§3.2): SHA-256 of `kind|scope|connectorId|mailboxSha256|cidr`
 * with `-` for an absent part. One active restriction per subject (unique with the active marker).
 */
export function restrictionSubjectHash(input: {
  kind: 'send_block' | 'auth_block';
  scope: 'mailbox' | 'connector' | 'connector_ip';
  connectorId: bigint | string | null;
  mailboxSha256: string | null;
  cidr: string | null;
}): string {
  return sha256Hex(
    [
      input.kind,
      input.scope,
      input.connectorId === null ? '-' : input.connectorId.toString(),
      input.mailboxSha256 ?? '-',
      input.cidr ?? '-',
    ].join('|'),
  );
}

/**
 * Keyed hash of a value that must not be stored or kept in clear (D5, D8, D20): first 32 hex of
 * HMAC-SHA256(`key`, `<purpose>\0<value>`). The purpose separates domains (an account hash never
 * equals a recipient-domain hash of the same string).
 */
export function hmacKey(key: string | Buffer, purpose: string, value: string): string {
  return createHmac('sha256', key)
    .update(`${purpose}\0${value}`, 'utf8')
    .digest('hex')
    .slice(0, 32);
}

/** Signal dedupe key: SHA-256 of `ato-sig/1|<code>|<accountId>|<subject>|<bucket>`. */
export function signalDedupeKey(
  code: string,
  accountId: bigint | string,
  subject: string,
  bucket: number | string,
): string {
  return sha256Hex(`ato-sig/1|${code}|${accountId.toString()}|${subject}|${bucket.toString()}`);
}
