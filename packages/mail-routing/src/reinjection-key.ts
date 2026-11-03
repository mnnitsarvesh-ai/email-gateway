import { createHash } from 'node:crypto';

/** Reinjection idempotency key and token (step 2.3 R7, R8). */

const sha256Hex = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TOKEN = /^dw1-([0-9a-f]{32})$/i;
const HEX64 = /^[0-9a-f]{64}$/;
const DECIMAL_ID = /^[1-9][0-9]{0,19}$/;

/**
 * Hex SHA-256 of the addresses, lower-cased, de-duplicated, sorted and joined with LF (an SMTP
 * address never contains one): the same convention as the step 2.2 ingest key.
 */
export function recipientSetSha256(addresses: readonly string[]): string {
  const set = [...new Set(addresses.map((address) => address.toLowerCase()))].sort();
  return sha256Hex(set.join('\n'));
}

export interface ReinjectionKeyInput {
  messageId: bigint | string;
  deliverySeq: number;
  listener: 'reinject_inbound' | 'reinject_outbound';
  recipientSetSha256: string;
}

/** Hex SHA-256(`v1|{messageId}|{deliverySeq}|{listener}|{recipientSetSha256}`). */
export function reinjectionIdempotencyKey(input: ReinjectionKeyInput): string {
  const messageId = input.messageId.toString();
  if (!DECIMAL_ID.test(messageId)) throw new Error('messageId must be a decimal id');
  if (!Number.isInteger(input.deliverySeq) || input.deliverySeq < 0 || input.deliverySeq > 65_535) {
    throw new Error('deliverySeq must be an integer 0-65535');
  }
  if (input.listener !== 'reinject_inbound' && input.listener !== 'reinject_outbound') {
    throw new Error('listener must be reinject_inbound or reinject_outbound');
  }
  if (!HEX64.test(input.recipientSetSha256)) {
    throw new Error('recipientSetSha256 must be 64 lower-case hex characters');
  }
  return sha256Hex(
    `v1|${messageId}|${input.deliverySeq}|${input.listener}|${input.recipientSetSha256}`,
  );
}

/**
 * The reinjection token (`XFORWARD IDENT`, `MAIL … ENVID`): `dw1-` + the reinjection's
 * `public_id` without dashes, lower case (36 characters).
 */
export function reinjectionToken(publicId: string): string {
  if (!UUID.test(publicId)) throw new Error('publicId must be a UUID');
  return `dw1-${publicId.toLowerCase().replaceAll('-', '')}`;
}

/** The `public_id` (lower-case UUID) of a reinjection token, or null for anything else. */
export function parseReinjectionToken(token: string): string | null {
  if (typeof token !== 'string') return null;
  const match = TOKEN.exec(token);
  if (!match) return null;
  const hex = match[1]!.toLowerCase();
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
