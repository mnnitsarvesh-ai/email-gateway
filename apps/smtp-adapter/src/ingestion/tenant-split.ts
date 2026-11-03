import { normalizeDomainName } from '@email-gateway/database';
import { countGatewayPasses } from '@email-gateway/common';
import type { RoutedDirection } from '@email-gateway/mail-routing';
import { FROM_MISMATCH, LMTP_OK, LMTP_TEMPFAIL, LOOP, type SmtpReply } from '../shared/replies';
import type { IngestDirection } from './ingestion-keys';

/** An accepted LMTP recipient with its owning organization (D7 step 1). */
export interface IngestRecipient {
  /** As given, domain lower-cased (`email_recipients.address`). */
  address: string;
  /** Lower-cased domain part (logs at info level never show more than this). */
  domain: string;
  organizationId: bigint;
  /** Inbound: the recipient domain; outbound: the sender domain. */
  domainId: bigint;
  /**
   * Routed direction (step 2.3 R1, classifyRecipient): always `inbound` on the inbound
   * listener; on the outbound listener `internal` when the recipient domain is an active domain
   * of the sender's organization, else `outbound`.
   */
  direction: RoutedDirection;
}

/** The recipients of one organization of a message, in RCPT order. */
export interface OrganizationGroup {
  organizationId: bigint;
  /** `email_messages.domain_id`: the first recipient's domain of this organization (D7 step 6). */
  domainId: bigint;
  /** Positions in the transaction's RCPT list. */
  indexes: number[];
  recipients: IngestRecipient[];
}

/** Splits recipients by organization, in order of each organization's first recipient. */
export function groupByOrganization(recipients: readonly IngestRecipient[]): OrganizationGroup[] {
  const groups = new Map<bigint, OrganizationGroup>();
  recipients.forEach((recipient, index) => {
    let group = groups.get(recipient.organizationId);
    if (!group) {
      group = {
        organizationId: recipient.organizationId,
        domainId: recipient.domainId,
        indexes: [],
        recipients: [],
      };
      groups.set(recipient.organizationId, group);
    }
    group.indexes.push(index);
    group.recipients.push(recipient);
  });
  return [...groups.values()];
}

/**
 * Splits an RCPT address into the stored form (local part as given, domain lower-cased) and
 * the domain. Null when there is no `local@domain` shape or the address is too long to store.
 */
export function splitRecipient(address: string): { address: string; domain: string } | null {
  const at = address.lastIndexOf('@');
  if (at <= 0 || at === address.length - 1) return null;
  const domain = address.slice(at + 1).toLowerCase();
  const stored = `${address.slice(0, at)}@${domain}`;
  if (stored.length > 320) return null;
  return { address: stored, domain };
}

export interface LoopGuardOptions {
  secret: string;
  gatewayId: string;
  maxPasses: number;
  direction: IngestDirection;
}

/**
 * D14: the message already passed this gateway for this organization and direction at least
 * `maxPasses` times (valid, organization-bound HMAC traces only).
 */
export function isLooping(
  traces: readonly string[],
  organizationId: bigint,
  options: LoopGuardOptions,
): boolean {
  if (traces.length === 0) return false;
  const passes = countGatewayPasses(traces, {
    secret: options.secret,
    gatewayId: options.gatewayId,
    organizationId,
    direction: options.direction === 'inbound' ? 'in' : 'out',
  });
  return passes >= options.maxPasses;
}

/** Removes RFC 5322 comments (nested, outside quoted strings). */
function stripComments(value: string): string {
  let out = '';
  let depth = 0;
  let quoted = false;
  for (let i = 0; i < value.length; i += 1) {
    const char = value[i]!;
    if (char === '\\') {
      // quoted-pair: copied inside quoted strings, dropped inside comments.
      if (depth === 0) out += char + (value[i + 1] ?? '');
      i += 1;
      continue;
    }
    if (depth === 0 && char === '"') {
      quoted = !quoted;
      out += char;
      continue;
    }
    if (!quoted && char === '(') {
      depth += 1;
      continue;
    }
    if (!quoted && char === ')' && depth > 0) {
      depth -= 1;
      continue;
    }
    if (depth === 0) out += char;
  }
  return out;
}

/**
 * The addresses of an RFC 5322 address-list header value (`From` may be a mailbox-list):
 * comments removed, quoted display names and `<…>` respected, groups (`name: a, b;`) expanded.
 */
export function parseAddressList(value: string): string[] {
  const text = stripComments(value);
  const items: string[] = [];
  let current = '';
  let quoted = false;
  let angle = false;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i]!;
    if (char === '\\' && quoted) {
      current += char + (text[i + 1] ?? '');
      i += 1;
      continue;
    }
    if (char === '"' && !angle) quoted = !quoted;
    else if (!quoted && char === '<') angle = true;
    else if (!quoted && char === '>') angle = false;
    if (!quoted && !angle && (char === ',' || char === ';')) {
      items.push(current);
      current = '';
      continue;
    }
    if (!quoted && !angle && char === ':') {
      // Group display name: drop it, keep the members.
      current = '';
      continue;
    }
    current += char;
  }
  items.push(current);
  const addresses: string[] = [];
  for (const item of items) {
    const trimmed = item.trim();
    if (trimmed.length === 0) continue;
    const angleMatch = /<([^<>]*)>/.exec(trimmed);
    const address = (angleMatch ? angleMatch[1]! : trimmed).trim();
    if (address.length > 0) addresses.push(address);
  }
  return addresses;
}

const asciiDomain = (domain: string): string | null => {
  try {
    return normalizeDomainName(domain, { allowTestNames: true }).ascii;
  } catch {
    return null;
  }
};

/** The domain of an address (after the last `@`), ASCII-normalized; null if none. */
export function addressDomain(address: string): string | null {
  const at = address.lastIndexOf('@');
  if (at <= 0 || at === address.length - 1) return null;
  return asciiDomain(address.slice(at + 1));
}

/**
 * D7 step 5 (outbound): exactly one `From` header carrying exactly one address whose domain
 * equals the envelope sender domain (IDN- and case-normalized).
 */
export function fromMatchesSender(fromValues: readonly string[], envelopeFrom: string): boolean {
  if (fromValues.length !== 1) return false;
  const senderDomain = addressDomain(envelopeFrom);
  if (senderDomain === null) return false;
  const addresses = parseAddressList(fromValues[0]!);
  if (addresses.length !== 1) return false;
  return addressDomain(addresses[0]!) === senderDomain;
}

/** Final outcome of one organization of a message. */
export type OrganizationOutcome = 'stored' | 'duplicate' | 'tempfail' | 'loop' | 'from_mismatch';

const REPLY_BY_OUTCOME: Record<OrganizationOutcome, SmtpReply> = {
  stored: LMTP_OK,
  duplicate: LMTP_OK,
  tempfail: LMTP_TEMPFAIL,
  loop: LOOP,
  from_mismatch: FROM_MISMATCH,
};

/** D7 step 7: one reply per recipient in RCPT order, from its organization's outcome. */
export function repliesFor(
  recipientCount: number,
  groups: readonly OrganizationGroup[],
  outcomes: ReadonlyMap<bigint, OrganizationOutcome>,
): SmtpReply[] {
  const replies: SmtpReply[] = Array.from({ length: recipientCount }, () => LMTP_TEMPFAIL);
  for (const group of groups) {
    const reply = REPLY_BY_OUTCOME[outcomes.get(group.organizationId) ?? 'tempfail'];
    for (const index of group.indexes) replies[index] = reply;
  }
  return replies;
}
