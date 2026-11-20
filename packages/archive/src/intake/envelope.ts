import type { IntakeRecipientField, IntakeSourceKind } from '../vocabulary';
import {
  JOURNAL_ENVELOPE_MAX_RECIPIENTS,
  type JournalEnvelope,
  type JournalEnvelopeRecipient,
} from './documents';
import { headerValues, normalizeAddrSpec, parseAddressList, parseHeaderFields } from './rfc5322';

/**
 * The journal envelope (step 8.6 D2.6, `journal-envelope/1`): the text/plain part of an Exchange
 * journal report, or, for copy kinds, the recipients a copy carries in its headers.
 *
 * Report lines (Exchange Online and Exchange Server 2007 and later; the `Recipient:` form is the
 * older Exchange 2003 format):
 *
 * ```text
 * Sender: alice@example.com
 * On-Behalf-Of: assistant@example.com
 * Subject: Quarterly report          (ignored: the subject comes from the embedded message)
 * Message-Id: <id@example.com>
 * To: bob@example.org
 * Cc: carol@example.com
 * Bcc: dave@example.com
 * To: erin@example.com, Expanded: team@example.com
 * To: frank@example.com, Forwarded: grace@example.com
 * Recipient: heidi@example.com
 * ```
 *
 * Continuation lines (starting with whitespace) are unfolded, CRLF and LF are both accepted,
 * unknown lines are ignored, invalid addresses are skipped, domains are lower-cased, a recipient
 * listed twice is kept once (first occurrence), and recipients beyond `maxRecipients` are dropped
 * with `truncated: true`. The caller bounds the size of the text (`JOURNAL_INTAKE_ENVELOPE_MAX_BYTES`
 * through the unwrapper).
 */

export interface ParseJournalEnvelopeOptions {
  /** `JOURNAL_INTAKE_MAX_RECIPIENTS` (default and upper bound 10 000). */
  maxRecipients?: number;
  /**
   * The Message-ID of the embedded message (header scanner). When both are present and differ,
   * `envelopeMismatch` is set (recorded, not refused).
   */
  embeddedMessageId?: string | null;
}

const FIELD_OF_LINE: Record<string, IntakeRecipientField> = {
  to: 'to',
  cc: 'cc',
  bcc: 'bcc',
  recipient: 'recipient',
};

/** A Message-ID without angle brackets and surrounding whitespace; null when empty. */
export function bareMessageId(value: string | null | undefined): string | null {
  if (typeof value !== 'string') return null;
  const v = value
    .trim()
    .replace(/^<(.*)>$/s, '$1')
    .trim();
  return v === '' ? null : v;
}

function capOf(max: number | undefined): number {
  if (max === undefined) return JOURNAL_ENVELOPE_MAX_RECIPIENTS;
  if (!Number.isInteger(max) || max < 1) throw new RangeError('maxRecipients must be ≥ 1');
  return Math.min(max, JOURNAL_ENVELOPE_MAX_RECIPIENTS);
}

/** One address of an envelope value: bare, `<addr>` or `Name <addr>`; null when invalid. */
function envelopeAddress(value: string): string | null {
  const v = value.trim();
  if (v === '' || v === '<>') return null;
  const direct = normalizeAddrSpec(v.replace(/^<(.*)>$/, '$1'));
  if (direct !== null) return direct;
  return parseAddressList(v)[0] ?? null;
}

class RecipientCollector {
  readonly recipients: JournalEnvelopeRecipient[] = [];
  truncated = false;
  private readonly seen = new Set<string>();
  constructor(private readonly cap: number) {}

  add(recipient: JournalEnvelopeRecipient): void {
    const key = recipient.address.toLowerCase();
    if (this.seen.has(key)) return;
    if (this.recipients.length >= this.cap) {
      this.truncated = true;
      return;
    }
    this.seen.add(key);
    this.recipients.push(recipient);
  }
}

/** Unfolded `name: value` lines of the report text. */
function reportLines(text: string): { name: string; value: string }[] {
  const lines: { name: string; value: string }[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    if ((line.startsWith(' ') || line.startsWith('\t')) && lines.length > 0) {
      lines[lines.length - 1]!.value += ` ${line.trim()}`;
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0) {
      // A blank or free-text line ends the previous field (no continuation across it).
      lines.push({ name: '', value: '' });
      continue;
    }
    lines.push({ name: line.slice(0, colon).trim().toLowerCase(), value: line.slice(colon + 1) });
  }
  return lines.filter((l) => l.name !== '');
}

/** Parses the text/plain envelope part of a journal report into `journal-envelope/1`. */
export function parseJournalEnvelope(
  text: string,
  options: ParseJournalEnvelopeOptions = {},
): JournalEnvelope {
  const collector = new RecipientCollector(capOf(options.maxRecipients));
  let sender: string | null = null;
  let onBehalfOf: string | null = null;
  let messageId: string | null = null;
  for (const { name, value } of reportLines(text)) {
    if (name === 'sender') {
      sender ??= envelopeAddress(value);
      continue;
    }
    if (name === 'on-behalf-of') {
      onBehalfOf ??= envelopeAddress(value);
      continue;
    }
    if (name === 'message-id') {
      if (messageId === null) {
        const v = value.trim();
        messageId = v === '' ? null : v.slice(0, 998);
      }
      continue;
    }
    const field = FIELD_OF_LINE[name];
    if (field === undefined) continue;
    let last: JournalEnvelopeRecipient | null = null;
    for (const segment of value.split(',')) {
      const suffix = /^\s*(expanded|forwarded)\s*:\s*(.*)$/i.exec(segment);
      if (suffix) {
        const address = envelopeAddress(suffix[2]!);
        if (last !== null && address !== null) {
          if (suffix[1]!.toLowerCase() === 'expanded') last.expandedFrom ??= address;
          else last.forwardedFrom ??= address;
        }
        continue;
      }
      const address = envelopeAddress(segment);
      if (address === null) {
        last = null;
        continue;
      }
      last = { address, field };
      collector.add(last);
    }
  }
  const embedded = bareMessageId(options.embeddedMessageId ?? null);
  const own = bareMessageId(messageId);
  return {
    v: 1,
    sender,
    onBehalfOf,
    messageId,
    recipients: collector.recipients,
    truncated: collector.truncated,
    envelopeMismatch: embedded !== null && own !== null && embedded !== own,
  };
}

export interface CopyEnvelopeInput {
  kind: Extract<IntakeSourceKind, 'google_workspace_copy' | 'smtp_bcc'>;
  /** The header block of the copy (bounded by the caller). */
  headerBlock: Buffer | string;
  /** The SMTP envelope sender (MAIL FROM), empty for the null sender. */
  mailFrom: string | null;
  maxRecipients?: number;
}

/**
 * The envelope of a copy (D2.6): Google Workspace copies → the `X-Gm-Original-To` values when
 * present (field `envelope`), else the To/Cc header addresses (field `header`); generic SMTP BCC
 * copies → the To/Cc header addresses (field `header`). BCC recipients of a copy are unknown by
 * nature (documented in the guides).
 */
export function buildCopyEnvelope(input: CopyEnvelopeInput): JournalEnvelope {
  const collector = new RecipientCollector(capOf(input.maxRecipients));
  const fields = parseHeaderFields(input.headerBlock);
  const original =
    input.kind === 'google_workspace_copy'
      ? headerValues(fields, 'X-Gm-Original-To').flatMap(parseAddressList)
      : [];
  if (original.length > 0) {
    for (const address of original) collector.add({ address, field: 'envelope' });
  } else {
    for (const name of ['To', 'Cc']) {
      for (const address of headerValues(fields, name).flatMap(parseAddressList)) {
        collector.add({ address, field: 'header' });
      }
    }
  }
  return {
    v: 1,
    sender: input.mailFrom === null ? null : envelopeAddress(input.mailFrom),
    onBehalfOf: null,
    messageId: null,
    recipients: collector.recipients,
    truncated: collector.truncated,
    envelopeMismatch: false,
  };
}
