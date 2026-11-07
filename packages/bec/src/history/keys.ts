import { createHmac } from 'node:crypto';
import { isIP } from 'node:net';
import { registrableDomainOf } from '@email-gateway/url-security';
import type { Alignment } from '../identity/alignment';
import { normalizeExtraDomains } from '../identity/freemail';
import { parseEnvelopeAddress, parseMailboxList } from '../identity/mailbox';
import type { BecDirection, BecHeaders } from '../rules/types';

/**
 * Historical communication context helpers (B12, ADR-0035): keyed hashes only. Nothing here
 * reads or writes a database; the email-worker reads the rows by these hashes and writes the
 * update list built by `buildHistoryUpdates` in the finalize transaction of round 0.
 *
 * key_hash = HMAC-SHA256(BEC_CONTEXT_HMAC_KEY, "eg-bec-ctx/v1\0" ‖ organizationId ‖ "\0" ‖
 *            scope ‖ "\0" ‖ canonical key), lower-case hex (64).
 */

export const HISTORY_KEY_PREFIX = 'eg-bec-ctx/v1\0';
export type HistoryScope = 'sender' | 'pair';
export const HISTORY_MAX_ROWS_PER_MESSAGE = 51;
export const HISTORY_FINGERPRINT_HEX = 16;

const hmac = (key: string | Buffer, message: string): string =>
  createHmac('sha256', key).update(message, 'utf8').digest('hex');

export function contextKeyHash(
  key: string | Buffer,
  organizationId: string | bigint,
  scope: HistoryScope | 'infra',
  canonical: string,
): string {
  if ((typeof key === 'string' ? Buffer.byteLength(key) : key.length) === 0) {
    throw new Error('BEC_CONTEXT_HMAC_KEY is empty');
  }
  return hmac(key, `${HISTORY_KEY_PREFIX}${String(organizationId)}\0${scope}\0${canonical}`);
}

/** Lower-cased, trimmed address (the canonical sender key). */
export const canonicalAddress = (address: string): string => address.trim().toLowerCase();

/** Direction-insensitive canonical pair: the two lower-cased addresses sorted, joined by NUL. */
export function canonicalPair(a: string, b: string): string {
  const x = canonicalAddress(a);
  const y = canonicalAddress(b);
  return x <= y ? `${x}\0${y}` : `${y}\0${x}`;
}

/** /24 for IPv4, /48 for IPv6 (null for anything else). */
export function ipNetwork(ip: string | null): string | null {
  if (!ip) return null;
  const value = ip.trim().replace(/^\[|\]$/g, '');
  const version = isIP(value);
  if (version === 4) return `${value.split('.').slice(0, 3).join('.')}.0/24`;
  if (version === 6) {
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(value);
    if (mapped) return ipNetwork(mapped[1]!);
    const [head = '', tail = ''] = value.toLowerCase().split('::');
    const headParts = head ? head.split(':') : [];
    const tailParts = tail ? tail.split(':') : [];
    const groups = value.includes('::')
      ? [
          ...headParts,
          ...Array<string>(8 - headParts.length - tailParts.length).fill('0'),
          ...tailParts,
        ]
      : headParts;
    return `${groups
      .slice(0, 3)
      .map((g) => (parseInt(g || '0', 16) || 0).toString(16))
      .join(':')}::/48`;
  }
  return null;
}

/**
 * Infrastructure fingerprint (plaintext, never stored): the DKIM-aligned signing registrable
 * domain, else the SPF-pass domain, else the client IP network. From the trusted envelope and
 * the auth row only.
 */
export function infrastructureFingerprint(
  alignment: Pick<Alignment, 'dkimAlignedDomain' | 'spfPassDomain'> | null,
  clientIp: string | null,
): string | null {
  if (alignment?.dkimAlignedDomain) return `dkim:${alignment.dkimAlignedDomain}`;
  if (alignment?.spfPassDomain) return `spf:${alignment.spfPassDomain}`;
  const network = ipNetwork(clientIp);
  return network ? `net:${network}` : null;
}

/** First 16 hex of the keyed hash of a fingerprint (the `infra[].fp` value). */
export function fingerprintHash(
  key: string | Buffer,
  organizationId: string | bigint,
  fingerprint: string,
): string {
  return contextKeyHash(key, organizationId, 'infra', fingerprint).slice(
    0,
    HISTORY_FINGERPRINT_HEX,
  );
}

export interface HistoryUpdate {
  scope: HistoryScope;
  keyHash: string;
  /** Inbound messages counted by this update (sender rows and inbound pairs). */
  inbound: 0 | 1;
  outbound: 0 | 1;
  receivedAt: Date;
  /** Sender scope only: the fingerprint hash to add/refresh in `infra`. */
  fingerprintHash: string | null;
}

export interface HistoryReadKeys {
  sender: string | null;
  /** One per checked recipient, in recipient order (≤ maxRecipients). */
  pairs: string[];
}

export interface HistoryMessageInput {
  organizationId: string | bigint;
  direction: BecDirection;
  headers: BecHeaders;
  envelopeFrom: string | null;
  recipients: readonly string[];
  receivedAt: Date;
  tenantDomains: readonly string[];
  /** BEC_HISTORY_MAX_RECIPIENTS (50). */
  maxRecipients: number;
  fingerprint: string | null;
  /**
   * Inbound only: the message may make its sender "known" (B12, review round 1). The caller sets
   * it when the message authenticated as its From (DMARC-style alignment, `authenticatedAsFrom`)
   * and the final verdict is `clean` or `unknown`. When false, no inbound row (sender, its
   * infrastructure fingerprint, or pairs) is counted: spoofed or flagged warm-up messages never
   * disable first contact (H1/H2/H5) or new infrastructure (H4) for a later attack. Outbound and
   * internal updates do not depend on it (the sender is the tenant's own user).
   */
  inboundEligible: boolean;
}

const fromAddressOf = (headers: BecHeaders): string | null => {
  for (const [name, values] of Object.entries(headers)) {
    if (name.toLowerCase() !== 'from') continue;
    const mailbox = parseMailboxList(values[0] ?? null).mailboxes.find((m) => m.address);
    if (mailbox?.address) return canonicalAddress(mailbox.address);
  }
  return null;
};

const recipientsOf = (recipients: readonly string[], max: number): string[] => {
  const out: string[] = [];
  for (const raw of recipients) {
    const parsed = parseEnvelopeAddress(raw);
    if (!parsed?.address) continue;
    const address = canonicalAddress(parsed.address);
    if (!out.includes(address)) out.push(address);
    if (out.length >= max) break;
  }
  return out;
};

/** Hashes the scan-time reads need (sender row and the (From, recipient) pair rows). */
export function historyReadKeys(
  key: string | Buffer,
  input: Omit<HistoryMessageInput, 'inboundEligible'>,
): HistoryReadKeys {
  const from = fromAddressOf(input.headers);
  if (!from) return { sender: null, pairs: [] };
  return {
    sender: contextKeyHash(key, input.organizationId, 'sender', from),
    pairs: recipientsOf(input.recipients, input.maxRecipients)
      .filter((r) => r !== from)
      .map((r) => contextKeyHash(key, input.organizationId, 'pair', canonicalPair(from, r))),
  };
}

/**
 * The history update list of one message (round 0 only; B12): inbound → the sender row plus
 * one pair row per recipient (inbound_count), only when `inboundEligible`; outbound / internal → pair rows of the internal
 * sender with each external recipient (outbound_count). ≤ 51 rows, sorted by (scope, key) so
 * concurrent upserts lock rows in the same order.
 */
export function buildHistoryUpdates(
  key: string | Buffer,
  input: HistoryMessageInput,
): HistoryUpdate[] {
  const from =
    fromAddressOf(input.headers) ??
    (input.envelopeFrom
      ? (parseEnvelopeAddress(input.envelopeFrom)?.address?.toLowerCase() ?? null)
      : null);
  if (!from) return [];
  const updates: HistoryUpdate[] = [];
  const recipients = recipientsOf(input.recipients, input.maxRecipients).filter((r) => r !== from);
  const fpHash = input.fingerprint
    ? fingerprintHash(key, input.organizationId, input.fingerprint)
    : null;
  if (input.direction === 'inbound') {
    if (!input.inboundEligible) return [];
    updates.push({
      scope: 'sender',
      keyHash: contextKeyHash(key, input.organizationId, 'sender', from),
      inbound: 1,
      outbound: 0,
      receivedAt: input.receivedAt,
      fingerprintHash: fpHash,
    });
    for (const recipient of recipients) {
      updates.push({
        scope: 'pair',
        keyHash: contextKeyHash(key, input.organizationId, 'pair', canonicalPair(from, recipient)),
        inbound: 1,
        outbound: 0,
        receivedAt: input.receivedAt,
        fingerprintHash: null,
      });
    }
  } else {
    const tenant = normalizeExtraDomains(input.tenantDomains);
    for (const recipient of recipients) {
      const domain = recipient.slice(recipient.lastIndexOf('@') + 1);
      const registrable = registrableDomainOf(domain);
      if (registrable !== null && tenant.has(registrable)) continue; // internal recipient
      updates.push({
        scope: 'pair',
        keyHash: contextKeyHash(key, input.organizationId, 'pair', canonicalPair(from, recipient)),
        inbound: 0,
        outbound: 1,
        receivedAt: input.receivedAt,
        fingerprintHash: null,
      });
    }
  }
  const unique = new Map<string, HistoryUpdate>();
  for (const u of updates) unique.set(`${u.scope}\0${u.keyHash}`, u);
  return [...unique.values()]
    .sort((a, b) =>
      a.scope < b.scope
        ? -1
        : a.scope > b.scope
          ? 1
          : a.keyHash < b.keyHash
            ? -1
            : a.keyHash > b.keyHash
              ? 1
              : 0,
    )
    .slice(0, HISTORY_MAX_ROWS_PER_MESSAGE);
}
