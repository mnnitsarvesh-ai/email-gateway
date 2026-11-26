/**
 * Bounded header-block parsing of copies (design D7.8, D9, D10.3): the header metadata of a
 * fetched copy (`email_messages` columns, the same rules as the smtp-adapter's header scanner:
 * raw unfolded values, encoded-words kept as-is) and the date of the topmost `Received:` header
 * (the provider delivery time of a journal copy, for the intake lag).
 *
 * Only the first `maxBytes` of the input up to the first empty line are read; a header block cut
 * by the limit keeps only its complete lines. No MIME parsing.
 */

export const DEFAULT_HEADER_MAX_BYTES = 256 * 1024;
const MAX_MESSAGE_ID_CHARS = 998;
const MAX_SUBJECT_CHARS = 998;
const MAX_ADDRESS_CHARS = 320;
const MAX_FIELDS = 2000;
const MAX_RECIPIENTS = 500;

export interface CopyHeaders {
  /** First `Message-ID`, unfolded and trimmed (angle brackets kept), ≤ 998 characters. */
  messageId: string | null;
  /** First `From`: the addr-spec (lower-case domain), ≤ 320 characters. */
  from: string | null;
  /** First `Date`, parsed (RFC 5322 incl. obsolete forms), or null. */
  date: Date | null;
  /** First `Subject`, unfolded raw value (encoded-words as-is), ≤ 998 characters. */
  subject: string | null;
  /** addr-specs of every `To` header (de-duplicated, ≤ 500). */
  to: string[];
  /** addr-specs of every `Cc` header (de-duplicated, ≤ 500). */
  cc: string[];
  /** Date after the last `;` of the topmost `Received:` header, or null. */
  topReceivedAt: Date | null;
  /** The empty line ending the header block was seen within the limit. */
  complete: boolean;
}

function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  let out = '';
  for (const char of value) {
    if (out.length + char.length > max) break;
    out += char;
  }
  return out;
}

/** The header block (text) within `maxBytes`, without a trailing partial line when cut. */
function headerText(
  input: Uint8Array | string,
  maxBytes: number,
): { text: string; complete: boolean } {
  const bytes = typeof input === 'string' ? Buffer.from(input, 'utf8') : Buffer.from(input);
  const limited = bytes.subarray(0, maxBytes);
  const text = limited.toString('utf8');
  const end = /\r?\n\r?\n/.exec(text);
  if (text.startsWith('\n') || text.startsWith('\r\n')) return { text: '', complete: true };
  if (end) return { text: text.slice(0, end.index + 1), complete: true };
  if (bytes.length <= maxBytes) return { text, complete: false };
  const lastLf = text.lastIndexOf('\n');
  return { text: lastLf < 0 ? '' : text.slice(0, lastLf + 1), complete: false };
}

/** Unfolded fields (lower-case names, trimmed values), in order. */
export function parseHeaderFields(text: string): { name: string; value: string }[] {
  const fields: { name: string; value: string }[] = [];
  let current: { name: string; value: string } | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (line.length === 0) break;
    if (line[0] === ' ' || line[0] === '\t') {
      if (current) current.value += line;
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0 || /\s/.test(line.slice(0, colon))) {
      current = null;
      continue;
    }
    if (fields.length >= MAX_FIELDS) break;
    current = { name: line.slice(0, colon).toLowerCase(), value: line.slice(colon + 1) };
    fields.push(current);
  }
  return fields.map(({ name, value }) => ({ name, value: value.trim() }));
}

/** Removes RFC 5322 comments `( … )` (nested, with quoted-pairs) outside quoted strings. */
function stripComments(value: string): string {
  let out = '';
  let depth = 0;
  let quoted = false;
  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i] as string;
    if (ch === '\\' && (quoted || depth > 0)) {
      if (depth === 0) out += ch + (value[i + 1] ?? '');
      i += 1;
      continue;
    }
    if (depth === 0 && ch === '"') quoted = !quoted;
    if (!quoted && ch === '(') {
      depth += 1;
      continue;
    }
    if (!quoted && ch === ')' && depth > 0) {
      depth -= 1;
      if (depth === 0) out += ' ';
      continue;
    }
    if (depth === 0) out += ch;
  }
  return out;
}

/** Normalizes an addr-spec: trimmed, the domain lower-cased; null unless `local@domain`. */
export function normalizeAddrSpec(value: string): string | null {
  let address = value.trim().replace(/^<|>$/g, '').trim();
  // Obsolete route syntax `<@relay:user@domain>`.
  const route = /^@[^:]*:(.+)$/.exec(address);
  if (route) address = (route[1] as string).trim();
  const at = address.lastIndexOf('@');
  if (at <= 0 || at === address.length - 1) return null;
  const local = address.slice(0, at);
  const domain = address.slice(at + 1).toLowerCase();
  if (/[\s<>,;]/.test(domain) || /[\s<>]/.test(local.replace(/^".*"$/, 'q'))) return null;
  return truncate(`${local}@${domain}`, MAX_ADDRESS_CHARS);
}

/** Splits an address list on commas outside quotes, angle brackets and group colons. */
function splitAddressList(value: string): string[] {
  const parts: string[] = [];
  let current = '';
  let quoted = false;
  let angle = false;
  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i] as string;
    if (ch === '\\' && quoted) {
      current += ch + (value[i + 1] ?? '');
      i += 1;
      continue;
    }
    if (ch === '"') quoted = !quoted;
    else if (!quoted && ch === '<') angle = true;
    else if (!quoted && ch === '>') angle = false;
    if (!quoted && !angle && (ch === ',' || ch === ';')) {
      parts.push(current);
      current = '';
      continue;
    }
    if (!quoted && !angle && ch === ':') {
      // Group syntax `name: a, b;` — drop the display name of the group.
      current = '';
      continue;
    }
    current += ch;
  }
  parts.push(current);
  return parts.map((p) => p.trim()).filter((p) => p.length > 0);
}

/** The addr-spec of one mailbox (`Name <a@b>` or `a@b`). */
function mailboxAddress(value: string): string | null {
  const angle = /<([^<>]*)>/.exec(value);
  if (angle) return normalizeAddrSpec(angle[1] as string);
  const bare = value.replace(/"(?:[^"\\]|\\.)*"/g, ' ').trim();
  const token = bare.split(/\s+/).find((t) => t.includes('@'));
  return token ? normalizeAddrSpec(token) : null;
}

/** addr-specs of an address-list header value. */
export function parseAddressList(value: string): string[] {
  return splitAddressList(stripComments(value))
    .map(mailboxAddress)
    .filter((a): a is string => a !== null);
}

const MONTHS: Readonly<Record<string, number>> = {
  jan: 0,
  feb: 1,
  mar: 2,
  apr: 3,
  may: 4,
  jun: 5,
  jul: 6,
  aug: 7,
  sep: 8,
  oct: 9,
  nov: 10,
  dec: 11,
};

/** Obsolete zone names (RFC 5322 §4.3); military letters are treated as -0000 (unknown). */
const ZONES: Readonly<Record<string, number>> = {
  ut: 0,
  utc: 0,
  gmt: 0,
  z: 0,
  est: -300,
  edt: -240,
  cst: -360,
  cdt: -300,
  mst: -420,
  mdt: -360,
  pst: -480,
  pdt: -420,
};

/**
 * Parses an RFC 5322 date-time (`[day ","] d month yyyy hh:mm[:ss] zone`), with comments, the
 * obsolete two- and three-digit years and named zones. Returns null when it is not a valid date.
 */
export function parseRfc5322Date(value: string): Date | null {
  const text = stripComments(value).replace(/\s+/g, ' ').trim();
  const match =
    /^(?:[A-Za-z]{3},?\s*)?(\d{1,2})\s+([A-Za-z]{3})[A-Za-z]*\s+(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?\s*([+-]\d{4}|[A-Za-z]{1,5})?$/.exec(
      text,
    );
  if (!match) return null;
  const day = Number(match[1]);
  const month = MONTHS[(match[2] as string).toLowerCase()];
  let year = Number(match[3]);
  if ((match[3] as string).length === 2) year += year < 50 ? 2000 : 1900;
  else if ((match[3] as string).length === 3) year += 1900;
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = match[6] === undefined ? 0 : Number(match[6]);
  if (month === undefined || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60) {
    return null;
  }
  let offsetMinutes = 0;
  const zone = match[7];
  if (zone !== undefined) {
    if (/^[+-]\d{4}$/.test(zone)) {
      const sign = zone[0] === '-' ? -1 : 1;
      const hours = Number(zone.slice(1, 3));
      const minutes = Number(zone.slice(3, 5));
      if (hours > 23 || minutes > 59) return null;
      offsetMinutes = sign * (hours * 60 + minutes);
    } else {
      const named = ZONES[zone.toLowerCase()];
      if (named === undefined && zone.length !== 1) return null;
      offsetMinutes = named ?? 0;
    }
  }
  const utc =
    Date.UTC(year, month, day, hour, minute, Math.min(second, 59)) - offsetMinutes * 60_000;
  const date = new Date(utc);
  // Reject impossible days (31 Feb) that Date.UTC would roll over.
  const check = new Date(Date.UTC(year, month, day));
  if (check.getUTCMonth() !== month || Number.isNaN(date.getTime())) return null;
  return date;
}

/** The date of a `Received:` value: the text after its last `;`. */
export function receivedHeaderDate(value: string): Date | null {
  const semicolon = value.lastIndexOf(';');
  return semicolon < 0 ? null : parseRfc5322Date(value.slice(semicolon + 1));
}

/** Header metadata of a copy from its first bytes (D9 `extractCopyHeaders`). */
export function extractCopyHeaders(
  headerBytes: Uint8Array | string,
  options: { maxBytes?: number } = {},
): CopyHeaders {
  const { text, complete } = headerText(headerBytes, options.maxBytes ?? DEFAULT_HEADER_MAX_BYTES);
  const result: CopyHeaders = {
    messageId: null,
    from: null,
    date: null,
    subject: null,
    to: [],
    cc: [],
    topReceivedAt: null,
    complete,
  };
  let sawReceived = false;
  let sawDate = false;
  const to = new Set<string>();
  const cc = new Set<string>();
  for (const { name, value } of parseHeaderFields(text)) {
    switch (name) {
      case 'message-id':
        if (result.messageId === null && value.length > 0) {
          result.messageId = truncate(value, MAX_MESSAGE_ID_CHARS);
        }
        break;
      case 'from':
        if (result.from === null) result.from = parseAddressList(value)[0] ?? null;
        break;
      case 'date':
        if (!sawDate) {
          sawDate = true;
          result.date = parseRfc5322Date(value);
        }
        break;
      case 'subject':
        result.subject ??= truncate(value, MAX_SUBJECT_CHARS);
        break;
      case 'to':
        for (const a of parseAddressList(value)) if (to.size < MAX_RECIPIENTS) to.add(a);
        break;
      case 'cc':
        for (const a of parseAddressList(value)) if (cc.size < MAX_RECIPIENTS) cc.add(a);
        break;
      case 'received':
        if (!sawReceived) {
          sawReceived = true;
          result.topReceivedAt = receivedHeaderDate(value);
        }
        break;
      default:
        break;
    }
  }
  result.to = [...to];
  result.cc = [...cc];
  return result;
}
