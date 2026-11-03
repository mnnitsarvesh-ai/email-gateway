import { simpleParser } from 'mailparser';
import { truncateCodePoints } from '../ingestion/header-scanner';

/** One per-recipient group of a `message/delivery-status` part (RFC 3464 §2.3). */
export interface DsnRecipient {
  /** Lower-cased address of `Final-Recipient` (address type stripped). */
  finalRecipient: string;
  originalRecipient: string | null;
  /** Lower-cased: failed, delayed, delivered, relayed, expanded. */
  action: string;
  /** `Status` when it is a valid enhanced status code, else null. */
  status: string | null;
  /** `Remote-MTA` name (type stripped). */
  remoteMta: string | null;
  /** Unfolded `Diagnostic-Code` value as reported (`smtp; 550 5.1.1 …`). */
  diagnosticCode: string | null;
  /** The SMTP reply code inside an `smtp`-type diagnostic, else null. */
  smtpCode: number | null;
}

/** A Postfix postmaster-copy DSN (step 2.2 D13). */
export interface DsnNotice {
  reportingMta: string | null;
  /** `X-Postfix-Queue-ID`. */
  queueId: string | null;
  /** `X-Postfix-Sender` address (type stripped, lower-cased domain kept as given); '' for <>. */
  sender: string | null;
  /** `Arrival-Date`, else the notice's `Date` (deterministic for dedupe). Null if neither. */
  occurredAt: Date | null;
  recipients: DsnRecipient[];
  /**
   * `X-Gateway-Trace` values of the undelivered message's headers (the `text/rfc822-headers`
   * or `message/rfc822` part). The bounce handler records a notice only when one of them is a
   * valid outbound trace of the sender's organization, i.e. the gateway itself reinjected the
   * message for delivery (D13, D14; review findings, §12.7).
   */
  originalTraces: string[];
}

const STATUS = /^[245]\.\d{1,3}\.\d{1,3}$/;
const MAX_DIAGNOSTIC = 1024;

/** Splits an RFC 3464 body into groups of unfolded fields (lower-cased names). */
export function parseDeliveryStatusGroups(text: string): Map<string, string>[] {
  const groups: Map<string, string>[] = [];
  let group = new Map<string, string>();
  let lastName: string | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (line.trim().length === 0) {
      if (group.size > 0) groups.push(group);
      group = new Map();
      lastName = null;
      continue;
    }
    if ((line[0] === ' ' || line[0] === '\t') && lastName !== null) {
      group.set(lastName, `${group.get(lastName) ?? ''} ${line.trim()}`);
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0) {
      lastName = null;
      continue;
    }
    lastName = line.slice(0, colon).trim().toLowerCase();
    // The first occurrence wins (RFC 3464 fields are single-valued).
    if (!group.has(lastName)) group.set(lastName, line.slice(colon + 1).trim());
    else lastName = null;
  }
  if (group.size > 0) groups.push(group);
  return groups;
}

/** `rfc822; user@example.com` → `user@example.com` (the value after the type, unwrapped). */
export function typedValue(value: string | undefined): string | null {
  if (value === undefined) return null;
  const semicolon = value.indexOf(';');
  const raw = (semicolon === -1 ? value : value.slice(semicolon + 1)).trim();
  const unwrapped = raw.startsWith('<') && raw.endsWith('>') ? raw.slice(1, -1).trim() : raw;
  return unwrapped;
}

/** Parses an RFC 5322 / RFC 3464 date (comments allowed); null when unusable. */
export function parseDsnDate(value: string | undefined): Date | null {
  if (value === undefined) return null;
  const withoutComments = value
    .replace(/\([^()]*\)/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  const ms = Date.parse(withoutComments);
  return Number.isFinite(ms) ? new Date(ms) : null;
}

function smtpCodeOf(diagnostic: string | null): number | null {
  if (diagnostic === null) return null;
  const semicolon = diagnostic.indexOf(';');
  if (semicolon === -1) return null;
  if (diagnostic.slice(0, semicolon).trim().toLowerCase() !== 'smtp') return null;
  const match = /^([245]\d\d)(?:[\s-]|$)/.exec(diagnostic.slice(semicolon + 1).trim());
  return match ? Number(match[1]) : null;
}

function recipientOf(group: Map<string, string>): DsnRecipient | null {
  const final = typedValue(group.get('final-recipient'));
  const action = group.get('action')?.trim().toLowerCase();
  if (!final || !action) return null;
  const finalRecipient = final.toLowerCase();
  if (!finalRecipient.includes('@') || finalRecipient.length > 320) return null;
  const status = group.get('status')?.trim().split(/\s/)[0] ?? '';
  const diagnostic = group.get('diagnostic-code') ?? null;
  return {
    finalRecipient,
    originalRecipient: typedValue(group.get('original-recipient')),
    action,
    status: STATUS.test(status) ? status : null,
    remoteMta: typedValue(group.get('remote-mta')),
    diagnosticCode: diagnostic === null ? null : truncateCodePoints(diagnostic, MAX_DIAGNOSTIC),
    smtpCode: smtpCodeOf(diagnostic),
  };
}

/** Parses the text of a `message/delivery-status` part. Null when it has no per-message part. */
export function parseDeliveryStatus(text: string, noticeDate: Date | null): DsnNotice | null {
  const groups = parseDeliveryStatusGroups(text);
  const perMessage = groups[0];
  if (!perMessage || perMessage.has('final-recipient')) return null;
  const recipients: DsnRecipient[] = [];
  for (const group of groups.slice(1)) {
    const recipient = recipientOf(group);
    if (recipient) recipients.push(recipient);
  }
  const queueId = perMessage.get('x-postfix-queue-id')?.trim() ?? '';
  return {
    reportingMta: typedValue(perMessage.get('reporting-mta')),
    queueId: queueId.length > 0 ? queueId : null,
    sender: typedValue(perMessage.get('x-postfix-sender')),
    occurredAt: parseDsnDate(perMessage.get('arrival-date')) ?? noticeDate,
    recipients,
    originalTraces: [],
  };
}

const TRACE_HEADER = 'x-gateway-trace';
/** Bounds the work on a hostile header block (the notice itself is capped at 2 MiB). */
const MAX_TRACES = 32;

/**
 * The unfolded values of every `X-Gateway-Trace` field of a header block (text up to the first
 * empty line). Lines without a colon end the current field.
 */
export function headerTraces(text: string): string[] {
  const traces: string[] = [];
  let current: string | null = null;
  const flush = () => {
    if (current !== null && traces.length < MAX_TRACES) traces.push(current.trim());
    current = null;
  };
  for (const line of text.split(/\r?\n/)) {
    if (line.length === 0) break;
    if (line[0] === ' ' || line[0] === '\t') {
      if (current !== null) current += ` ${line.trim()}`;
      continue;
    }
    flush();
    const colon = line.indexOf(':');
    if (colon > 0 && line.slice(0, colon).trim().toLowerCase() === TRACE_HEADER) {
      current = line.slice(colon + 1);
    }
  }
  flush();
  return traces;
}

/**
 * Parses a postmaster copy (multipart/report) with mailparser and returns the DSN of its
 * top-level `message/delivery-status` part; null when the notice has none (unparseable).
 */
export async function parseDsnNotice(raw: Buffer): Promise<DsnNotice | null> {
  const parsed = await simpleParser(raw, {
    keepDeliveryStatus: true,
    skipHtmlToText: true,
    skipTextToHtml: true,
    skipImageLinks: true,
  });
  const part = parsed.attachments.find(
    (attachment) => attachment.contentType.toLowerCase() === 'message/delivery-status',
  );
  if (!part) return null;
  const notice = parseDeliveryStatus(part.content.toString('utf8'), parsed.date ?? null);
  if (!notice) return null;
  const original = parsed.attachments.find((attachment) =>
    ['text/rfc822-headers', 'message/rfc822'].includes(attachment.contentType.toLowerCase()),
  );
  return original
    ? { ...notice, originalTraces: headerTraces(original.content.toString('utf8')) }
    : notice;
}
