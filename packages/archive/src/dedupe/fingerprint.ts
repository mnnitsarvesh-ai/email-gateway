import { createHash } from 'node:crypto';
import { canonicalJson } from '../documents/canonical';
import { decimalIdOrNull, type NumericId } from '../ids';
import { bareMessageId } from '../intake/envelope';
import {
  headerValues,
  parseAddressList,
  parseHeaderFields,
  parseRfc5322Date,
} from '../intake/rfc5322';

/**
 * Cross-source dedupe keys (step 8.6 D7, ADR-0088), pure:
 *
 * - `archive-dedupe/1` key: `messageIdHash = sha256("archive-dedupe/1\0<organizationId>\0<Message-ID
 *   without angle brackets and surrounding whitespace>")`; no Message-ID → no dedupe;
 * - `archive-fingerprint/1`: SHA-256 of the canonical JSON (sorted keys, no whitespace) of
 *   `{ date: <Date as epoch seconds>, from: <header From addr-spec, lower-case>, to: [sorted
 *   unique lower-case To + Cc addr-specs], attachments: [sorted SHA-256 of attachment parts] }`.
 *   Body text is excluded on purpose (the gateway changes bodies at delivery). An unusable
 *   Message-ID, Date or From, or an attachment without a valid hash, gives no fingerprint (the
 *   copies stay separate: fail-safe, stored twice).
 */

export const ARCHIVE_DEDUPE_KEY_LABEL = 'archive-dedupe/1';

/** The dedupe key of a message in an organization; null without a usable Message-ID. */
export function dedupeMessageIdHash(
  organizationId: NumericId,
  messageId: string | null | undefined,
): string | null {
  const org = decimalIdOrNull(organizationId);
  if (org === null) throw new RangeError('organizationId must be a decimal id');
  const id = bareMessageId(messageId);
  if (id === null || id.length > 998) return null;
  return createHash('sha256')
    .update(`${ARCHIVE_DEDUPE_KEY_LABEL}\0${org}\0${id}`, 'utf8')
    .digest('hex');
}

export interface HeaderFingerprintInput {
  /** The header block of the stored EML (bounded range GET, ≤ `INGEST_HEADER_MAX_BYTES`). */
  headerBlock: Buffer | string;
  /** `email_attachments.sha256` of every attachment part of the parse. */
  attachmentSha256s: readonly (string | null)[];
}

export interface HeaderFingerprintCanonical {
  date: number;
  from: string;
  to: string[];
  attachments: string[];
}

export interface HeaderFingerprint {
  /** SHA-256 (hex) of the canonical JSON. */
  fingerprint: string;
  /** The Message-ID without angle brackets (the input of `dedupeMessageIdHash`). */
  messageId: string;
  canonical: HeaderFingerprintCanonical;
}

const SHA256 = /^[0-9a-fA-F]{64}$/;

export function headerFingerprint(input: HeaderFingerprintInput): HeaderFingerprint | null {
  const fields = parseHeaderFields(input.headerBlock);
  const messageId = bareMessageId(headerValues(fields, 'Message-ID')[0]);
  if (messageId === null || messageId.length > 998) return null;
  const dateValue = headerValues(fields, 'Date')[0];
  const date = parseRfc5322Date(dateValue);
  if (date === null) return null;
  const fromValue = headerValues(fields, 'From')[0];
  const from = fromValue === undefined ? undefined : parseAddressList(fromValue)[0];
  if (from === undefined) return null;
  const to = [
    ...new Set(
      [...headerValues(fields, 'To'), ...headerValues(fields, 'Cc')]
        .flatMap(parseAddressList)
        .map((a) => a.toLowerCase()),
    ),
  ].sort();
  const attachments: string[] = [];
  for (const h of input.attachmentSha256s) {
    if (typeof h !== 'string' || !SHA256.test(h)) return null;
    attachments.push(h.toLowerCase());
  }
  attachments.sort();
  const canonical: HeaderFingerprintCanonical = { date, from: from.toLowerCase(), to, attachments };
  return {
    fingerprint: createHash('sha256').update(canonicalJson(canonical), 'utf8').digest('hex'),
    messageId,
    canonical,
  };
}
