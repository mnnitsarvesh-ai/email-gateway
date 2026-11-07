import { normalizeDomainInput } from '@email-gateway/url-security';

/**
 * Bounded RFC 5322 `mailbox-list` / `address-list` parser (docs/plan/steps/12-phishing-bec.md
 * B5) over the stored, already decoded header value (`email_headers`, ≤ 2 048 code points).
 * One linear pass: a tokenizer (quoted strings with escapes, comments nested ≤ 4 and dropped,
 * angle addresses, specials) followed by a linear grouping of the tokens into mailboxes.
 * Groups `name: a, b;` are flattened; obsolete routes `<@a,@b:x@y>` are dropped. nodemailer's
 * address parser is deliberately not used (step 3.1).
 */

export const MAX_MAILBOX_INPUT_CODE_POINTS = 2048;
export const MAX_MAILBOXES = 20;
export const MAX_DISPLAY_NAME_CODE_POINTS = 128;
export const MAX_COMMENT_DEPTH = 4;

export type MailboxFlag = 'parse_error' | 'multiple' | 'display_name_truncated' | 'idn';

export interface ParsedMailbox {
  /** Trimmed, NFKC, ≤ 128 code points; null when absent. */
  displayName: string | null;
  /** `localPart@domain` with the domain as an A-label (lower case); null when unparseable. */
  address: string | null;
  localPart: string | null;
  /** A-label, lower case (url-security `normalizeDomainInput`); null when invalid. */
  domain: string | null;
  flags: MailboxFlag[];
}

export interface MailboxListResult {
  mailboxes: ParsedMailbox[];
  /** List-level flags: `parse_error` (syntax, bounds), `multiple` (more than one mailbox). */
  flags: MailboxFlag[];
  /** Input longer than the bound, or more than MAX_MAILBOXES mailboxes (the rest dropped). */
  truncated: boolean;
}

type Token =
  | { kind: 'atom'; text: string }
  | { kind: 'quoted'; text: string }
  | { kind: 'angle'; text: string }
  | { kind: 'special'; char: ',' | ':' | ';' | '@' | '.' }
  | { kind: 'space' };

interface TokenizeResult {
  tokens: Token[];
  error: boolean;
}

const SPECIALS = new Set([',', ':', ';', '@', '.']);
const isWs = (c: string): boolean => c === ' ' || c === '\t' || c === '\r' || c === '\n';

/** Single pass over the code points; every branch consumes at least one character. */
function tokenize(chars: readonly string[]): TokenizeResult {
  const tokens: Token[] = [];
  let error = false;
  let i = 0;
  let atom = '';
  const flushAtom = (): void => {
    if (atom) tokens.push({ kind: 'atom', text: atom });
    atom = '';
  };
  while (i < chars.length) {
    const c = chars[i]!;
    if (c === '"') {
      flushAtom();
      let text = '';
      i += 1;
      let closed = false;
      while (i < chars.length) {
        const q = chars[i]!;
        if (q === '\\' && i + 1 < chars.length) {
          text += chars[i + 1]!;
          i += 2;
          continue;
        }
        if (q === '"') {
          closed = true;
          i += 1;
          break;
        }
        text += q;
        i += 1;
      }
      if (!closed) error = true;
      tokens.push({ kind: 'quoted', text });
      continue;
    }
    if (c === '(') {
      flushAtom();
      let depth = 0;
      while (i < chars.length) {
        const q = chars[i]!;
        if (q === '\\' && i + 1 < chars.length) {
          i += 2;
          continue;
        }
        if (q === '(') {
          depth += 1;
          if (depth > MAX_COMMENT_DEPTH) error = true;
        } else if (q === ')') {
          depth -= 1;
          if (depth === 0) {
            i += 1;
            break;
          }
        }
        i += 1;
      }
      if (depth !== 0) error = true;
      tokens.push({ kind: 'space' });
      continue;
    }
    if (c === '<') {
      flushAtom();
      let text = '';
      i += 1;
      let closed = false;
      while (i < chars.length) {
        const q = chars[i]!;
        if (q === '>') {
          closed = true;
          i += 1;
          break;
        }
        if (q === '"') {
          // quoted local part inside an angle address: keep it verbatim (bounded by the input)
          text += q;
          i += 1;
          while (i < chars.length && chars[i] !== '"') {
            if (chars[i] === '\\' && i + 1 < chars.length) {
              text += chars[i]! + chars[i + 1]!;
              i += 2;
              continue;
            }
            text += chars[i]!;
            i += 1;
          }
          if (i < chars.length) {
            text += '"';
            i += 1;
          }
          continue;
        }
        if (q === '<') error = true;
        text += q;
        i += 1;
      }
      if (!closed) error = true;
      tokens.push({ kind: 'angle', text });
      continue;
    }
    if (c === ')' || c === '>') {
      error = true;
      i += 1;
      continue;
    }
    if (isWs(c)) {
      flushAtom();
      if (tokens.at(-1)?.kind !== 'space') tokens.push({ kind: 'space' });
      i += 1;
      continue;
    }
    if (SPECIALS.has(c)) {
      flushAtom();
      tokens.push({ kind: 'special', char: c as ',' | ':' | ';' | '@' | '.' });
      i += 1;
      continue;
    }
    atom += c;
    i += 1;
  }
  flushAtom();
  return { tokens, error };
}

/** Splits `local@domain` (last `@`, quoted local parts allowed). */
export function parseAddrSpec(raw: string): {
  address: string | null;
  localPart: string | null;
  domain: string | null;
  idn: boolean;
} {
  let text = raw.trim();
  // obsolete route: "@a,@b:local@domain"
  if (text.startsWith('@')) {
    const colon = text.indexOf(':');
    text = colon >= 0 ? text.slice(colon + 1).trim() : '';
  }
  const at = text.lastIndexOf('@');
  if (at <= 0 || at === text.length - 1) {
    return { address: null, localPart: null, domain: null, idn: false };
  }
  let localPart = text.slice(0, at);
  if (localPart.length >= 2 && localPart.startsWith('"') && localPart.endsWith('"')) {
    localPart = localPart.slice(1, -1).replace(/\\(.)/g, '$1');
  }
  if (!localPart || /[\s<>()[\],;:]/.test(localPart) || localPart.length > 64) {
    return { address: null, localPart: null, domain: null, idn: false };
  }
  const rawDomain = text.slice(at + 1);
  const normalized = normalizeDomainInput(rawDomain);
  if (!normalized.ok) return { address: null, localPart, domain: null, idn: false };
  const domain = normalized.domain;
  const idn =
    domain.split('.').some((label) => label.startsWith('xn--')) || /[^\x20-\x7e]/.test(rawDomain);
  return { address: `${localPart}@${domain}`, localPart, domain, idn };
}

const truncateCodePoints = (value: string, max: number): { text: string; truncated: boolean } => {
  const chars = [...value];
  return chars.length > max
    ? { text: chars.slice(0, max).join(''), truncated: true }
    : { text: value, truncated: false };
};

function buildMailbox(phrase: string[], addrSpec: string | null, error: boolean): ParsedMailbox {
  const flags = new Set<MailboxFlag>();
  if (error) flags.add('parse_error');
  let displayName: string | null = null;
  const joined = phrase.join('').replace(/\s+/g, ' ').trim().normalize('NFKC');
  if (joined) {
    const t = truncateCodePoints(joined, MAX_DISPLAY_NAME_CODE_POINTS);
    displayName = t.text;
    if (t.truncated) flags.add('display_name_truncated');
  }
  if (addrSpec === null) {
    flags.add('parse_error');
    return { displayName, address: null, localPart: null, domain: null, flags: [...flags].sort() };
  }
  const spec = parseAddrSpec(addrSpec);
  if (!spec.address) flags.add('parse_error');
  if (spec.idn) flags.add('idn');
  return {
    displayName,
    address: spec.address,
    localPart: spec.localPart,
    domain: spec.domain,
    flags: [...flags].sort(),
  };
}

/**
 * Parses a mailbox-list / address-list. Never throws; syntax problems are flags. The grouping
 * pass is linear in the token count: each token is visited once.
 */
export function parseMailboxList(value: string | null | undefined): MailboxListResult {
  const listFlags = new Set<MailboxFlag>();
  if (value === null || value === undefined) return { mailboxes: [], flags: [], truncated: false };
  let chars = [...value];
  let truncated = false;
  if (chars.length > MAX_MAILBOX_INPUT_CODE_POINTS) {
    chars = chars.slice(0, MAX_MAILBOX_INPUT_CODE_POINTS);
    truncated = true;
    listFlags.add('parse_error');
  }
  const { tokens, error } = tokenize(chars);
  if (error) listFlags.add('parse_error');

  const mailboxes: ParsedMailbox[] = [];
  // Current mailbox state: the phrase (display name candidates) and the bare addr-spec text.
  let phrase: string[] = [];
  let bare = '';
  let angle: string | null = null;
  let entryError = false;
  let sawContent = false;

  const finish = (): void => {
    if (!sawContent) return;
    if (mailboxes.length >= MAX_MAILBOXES) {
      truncated = true;
      listFlags.add('parse_error');
    } else if (angle !== null) {
      mailboxes.push(buildMailbox(phrase, angle, entryError));
    } else {
      // bare addr-spec; "Name addr@x" without angle brackets: the last word holding an `@` is
      // the address, the words before it the display name (flagged parse_error).
      const words = bare.split(' ').filter(Boolean);
      const at = words.findLastIndex((w) => w.includes('@'));
      if (words.length <= 1 || at < 0) {
        mailboxes.push(buildMailbox([], words[0]?.includes('@') ? words[0] : null, entryError));
      } else {
        mailboxes.push(
          buildMailbox([words.filter((_, k) => k !== at).join(' ')], words[at]!, true),
        );
      }
    }
    phrase = [];
    bare = '';
    angle = null;
    entryError = false;
    sawContent = false;
  };

  for (const token of tokens) {
    switch (token.kind) {
      case 'space':
        if (angle === null) {
          phrase.push(' ');
          bare += ' ';
        }
        break;
      case 'atom':
        sawContent = true;
        if (angle !== null) entryError = true;
        phrase.push(token.text);
        bare = (bare.endsWith('@ ') || bare.endsWith('. ') ? bare.slice(0, -1) : bare) + token.text;
        break;
      case 'quoted':
        sawContent = true;
        if (angle !== null) entryError = true;
        phrase.push(token.text);
        bare += `"${token.text.replace(/(["\\])/g, '\\$1')}"`;
        break;
      case 'angle':
        sawContent = true;
        if (angle !== null) entryError = true;
        angle = token.text;
        break;
      case 'special':
        if (token.char === ',') {
          finish();
        } else if (token.char === ':') {
          // group start: the phrase so far is the group name, dropped
          if (angle === null && !bare.includes('@')) {
            phrase = [];
            bare = '';
            sawContent = false;
          } else {
            sawContent = true;
            bare += ':';
            phrase.push(':');
          }
        } else if (token.char === ';') {
          finish();
        } else {
          sawContent = true;
          // `a @ b.c` / `a . b`: specials glue the neighbouring words of an addr-spec
          bare = bare.replace(/ +$/, '') + token.char;
          phrase.push(token.char);
        }
        break;
    }
  }
  finish();
  if (mailboxes.length > 1) listFlags.add('multiple');
  if (mailboxes.some((m) => m.flags.includes('parse_error'))) listFlags.add('parse_error');
  return { mailboxes, flags: [...listFlags].sort(), truncated };
}

/** A single addr-spec such as the SMTP envelope sender (`MAIL FROM`); `<>`/empty → null. */
export function parseEnvelopeAddress(value: string | null | undefined): ParsedMailbox | null {
  if (value === null || value === undefined) return null;
  const text = value
    .trim()
    .replace(/^<(.*)>$/, '$1')
    .trim();
  if (!text) return null;
  const spec = parseAddrSpec(text);
  return {
    displayName: null,
    address: spec.address,
    localPart: spec.localPart,
    domain: spec.domain,
    flags: spec.address ? (spec.idn ? ['idn'] : []) : ['parse_error'],
  };
}

/** Lower-cased comparison form of an address (mail systems are case-insensitive in practice). */
export const comparableAddress = (address: string | null): string | null =>
  address === null ? null : address.toLowerCase();
