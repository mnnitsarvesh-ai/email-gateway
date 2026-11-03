import { createHash } from 'node:crypto';

export type IngestDirection = 'inbound' | 'outbound';

export const sha256Hex = (value: string): string =>
  createHash('sha256').update(value, 'utf8').digest('hex');

/** Identifies one Postfix queue file as seen by one LMTP listener. */
export interface QueueFileRef {
  /** The LMTP client's LHLO name (Postfix `myhostname`). */
  mtaId: string;
  /** XFORWARD IDENT (Postfix long queue id). */
  queueId: string;
  direction: IngestDirection;
}

/**
 * Ingest key (D7, fits `message_identities.ingest_key` VARCHAR(128)): `v2:` + hex SHA-256 of
 * `{mtaId}|{queueId}|{direction}|{contentSha256}|{recipientSetSha256}`, per organization.
 *
 * `recipientSetSha256` = hex SHA-256 of that organization's accepted recipient addresses,
 * lower-cased, de-duplicated, sorted and joined with LF (an SMTP address never contains one).
 * A redelivery after a lost `250` carries the same queue file and the same recipients, so it
 * has the same key and is answered as a duplicate. A retry of only some recipients (one RCPT
 * tempfailed while another of the same organization was stored) has a different recipient set,
 * so it is stored as its own message instead of being answered 250 and lost (review finding,
 * §12.7). `v1:` keys (without the recipient set) were written before that fix.
 */
export function ingestKey(
  ref: QueueFileRef,
  contentSha256: string,
  recipients: readonly string[],
): string {
  const set = [...new Set(recipients.map((address) => address.toLowerCase()))].sort();
  const recipientSet = sha256Hex(set.join('\n'));
  return `v2:${sha256Hex(
    `${ref.mtaId}|${ref.queueId}|${ref.direction}|${contentSha256}|${recipientSet}`,
  )}`;
}

/** D8 objectRef: first 32 hex characters of SHA-256(`{mtaId}|{queueId}|{direction}|{orgId}`). */
export function objectRef(ref: QueueFileRef, organizationId: bigint): string {
  return sha256Hex(
    `${ref.mtaId}|${ref.queueId}|${ref.direction}|${organizationId.toString()}`,
  ).slice(0, 32);
}

/**
 * D8 S3 key: `org/{organizationId}/eml/{yyyy}/{mm}/{dd}/{objectRef}.eml`, with the UTC date of
 * the ingestion attempt. Deterministic per queue file, organization and day, so a same-day retry
 * overwrites its own object instead of orphaning one.
 */
export function emlObjectKey(ref: QueueFileRef, organizationId: bigint, attemptAt: Date): string {
  const iso = attemptAt.toISOString();
  const [yyyy, mm, dd] = [iso.slice(0, 4), iso.slice(5, 7), iso.slice(8, 10)];
  return `org/${organizationId.toString()}/eml/${yyyy}/${mm}/${dd}/${objectRef(ref, organizationId)}.eml`;
}
