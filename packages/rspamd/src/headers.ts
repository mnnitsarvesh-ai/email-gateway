import { isIP } from 'node:net';
import { RspamdRequestError } from './errors';

/**
 * The trusted envelope of one message (docs/plan/steps/09-rspamd.md S9, §2.0 invariant 7): what
 * smtp-adapter recorded from Postfix XFORWARD and the SMTP transaction, never header values.
 */
export interface RspamdEnvelope {
  direction: 'inbound' | 'outbound' | 'internal';
  /** Tenant of the message; becomes `User: org-<id>` for outbound and internal mail. */
  organizationId: bigint | number | string;
  clientIp: string | null;
  clientHelo: string | null;
  /** Verified client host name (XFORWARD NAME; Postfix's `unknown` is passed through). */
  clientName: string | null;
  /** Envelope sender; the empty string is the null sender (`<>`). */
  envelopeFrom: string;
  /** Envelope recipients in RCPT order. */
  recipients: readonly string[];
  /** Postfix queue id of the inbound MX. */
  queueId: string | null;
}

/** At most this many `Rcpt` headers are sent; the rest are omitted and flagged (S9). */
export const RSPAMD_MAX_RCPT_HEADERS = 100;
/** Settings ids configured in infrastructure/rspamd/local.d/settings.conf. */
export const RSPAMD_SETTINGS_IDS = { inbound: 'eg_inbound', outbound: 'eg_outbound' } as const;

const MAX_HOST_LENGTH = 255;
const MAX_ADDRESS_LENGTH = 320;
const LOG_TAG_PATTERN = /^[A-Za-z0-9_.:-]{1,64}$/;
const SETTINGS_ID_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;
const QUEUE_ID_PATTERN = /^[A-Za-z0-9]{1,64}$/;
const ORGANIZATION_ID_PATTERN = /^[1-9][0-9]{0,19}$/;

export interface RequestHeaderOptions {
  /** Rspamd log tag; ids only (`m<messageId>r<round>`). */
  logTag: string;
  /** Overrides the settings id derived from the direction. */
  settingsId?: string;
}

export interface BuiltRequestHeaders {
  /** Header name/value pairs in send order (`Rcpt` repeats). Values are wire-ready. */
  headers: Array<[string, string]>;
  /** More than RSPAMD_MAX_RCPT_HEADERS recipients: the rest were not sent. */
  rcptTruncated: boolean;
  /** Envelope fields left out because their value was absent or unsafe (names only). */
  omitted: string[];
}

/** True when the value has no C0 control character (CR, LF, NUL, …) and no DEL. */
function hasNoControl(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
}

function safeValue(value: string | null, maxLength: number): string | null {
  if (value === null) return null;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > maxLength || !hasNoControl(trimmed)) return null;
  return trimmed;
}

/**
 * HTTP header values are sent as bytes: UTF-8 text (SMTPUTF8 addresses, IDN HELO names) is
 * encoded as UTF-8 and carried in a latin1 string, so the bytes on the wire are UTF-8.
 */
function wire(value: string): string {
  // eslint-disable-next-line no-control-regex
  return /^[\x00-\x7f]*$/.test(value) ? value : Buffer.from(value, 'utf8').toString('latin1');
}

/** A mailbox `local@domain` without spaces, brackets or control characters. */
function isMailbox(value: string): boolean {
  if (value.length > MAX_ADDRESS_LENGTH || !hasNoControl(value) || /[\s<>]/.test(value)) {
    return false;
  }
  const at = value.lastIndexOf('@');
  return at > 0 && at < value.length - 1;
}

/**
 * Builds the `/checkv2` request headers of S9 from the trusted envelope: `IP`, `Helo`,
 * `Hostname`, `From` (`<>` for the null sender), up to 100 `Rcpt`, `Queue-Id`, `User` (outbound
 * and internal only: `org-<id>`, because smtp-adapter authenticated the submitter), `Settings-Id`
 * and `Log-Tag`. Optional values that are unsafe (CR/LF, control characters, too long) are left
 * out and listed in `omitted`; an unusable sender, log tag or settings id throws
 * RspamdRequestError (never retried).
 */
export function buildRequestHeaders(
  envelope: RspamdEnvelope,
  options: RequestHeaderOptions,
): BuiltRequestHeaders {
  const headers: Array<[string, string]> = [];
  const omitted: string[] = [];

  if (!LOG_TAG_PATTERN.test(options.logTag)) {
    throw new RspamdRequestError('checkv2', 'Log-Tag', 'expected 1-64 characters [A-Za-z0-9_.:-]');
  }
  const settingsId =
    options.settingsId ??
    (envelope.direction === 'inbound' ? RSPAMD_SETTINGS_IDS.inbound : RSPAMD_SETTINGS_IDS.outbound);
  if (!SETTINGS_ID_PATTERN.test(settingsId)) {
    throw new RspamdRequestError('checkv2', 'Settings-Id', 'expected [a-z][a-z0-9_]{0,63}');
  }

  const ip = envelope.clientIp === null ? null : envelope.clientIp.trim();
  if (ip !== null && isIP(ip) !== 0) headers.push(['IP', ip]);
  else omitted.push('IP');

  const helo = safeValue(envelope.clientHelo, MAX_HOST_LENGTH);
  if (helo !== null) headers.push(['Helo', wire(helo)]);
  else omitted.push('Helo');

  const hostname = safeValue(envelope.clientName, MAX_HOST_LENGTH);
  if (hostname !== null) headers.push(['Hostname', wire(hostname)]);
  else omitted.push('Hostname');

  const from = envelope.envelopeFrom.trim();
  if (from === '' || from === '<>') {
    headers.push(['From', '<>']);
  } else if (isMailbox(from)) {
    headers.push(['From', wire(from)]);
  } else {
    throw new RspamdRequestError('checkv2', 'From', 'the envelope sender is not a mailbox');
  }

  let sent = 0;
  let rcptTruncated = false;
  let rcptInvalid = false;
  for (const recipient of envelope.recipients) {
    const rcpt = recipient.trim();
    // fetch joins repeated headers with ", " (Rspamd 3.12 splits them again), so a recipient
    // with a comma (quoted local part) cannot be sent unambiguously.
    if (!isMailbox(rcpt) || rcpt.includes(',')) {
      rcptInvalid = true;
      continue;
    }
    if (sent >= RSPAMD_MAX_RCPT_HEADERS) {
      rcptTruncated = true;
      break;
    }
    headers.push(['Rcpt', wire(rcpt)]);
    sent += 1;
  }
  if (rcptInvalid) omitted.push('Rcpt');

  const queueId = envelope.queueId === null ? null : envelope.queueId.trim();
  if (queueId !== null && QUEUE_ID_PATTERN.test(queueId)) headers.push(['Queue-Id', queueId]);
  else omitted.push('Queue-Id');

  if (envelope.direction !== 'inbound') {
    const org = String(envelope.organizationId);
    if (!ORGANIZATION_ID_PATTERN.test(org)) {
      throw new RspamdRequestError('checkv2', 'User', 'the organization id is not a positive id');
    }
    headers.push(['User', `org-${org}`]);
  }

  headers.push(['Settings-Id', settingsId]);
  headers.push(['Log-Tag', options.logTag]);
  return { headers, rcptTruncated, omitted };
}
