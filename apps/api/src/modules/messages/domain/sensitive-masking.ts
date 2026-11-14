/**
 * Sensitive message metadata masking (step 7.2 §2 E5, E7, E9, §3.4, ADR-0062): pure functions the
 * api services apply to every read of the message surface, whatever the caller's permissions,
 * so the masks hold for API keys, the portal and every future client. Clear values leave the api
 * only through the audited `message:reveal` operations.
 *
 * - `maskAddress` masks one stored address (recipient addresses of the recipients, deliveries and
 *   quarantine routes): the first code point of the local part, `***`, then `@` and the domain as
 *   stored (`finance.team@acme.example` → `f***@acme.example`).
 * - `maskAddressesInText` masks the local part of every address-shaped substring of free text
 *   (SMTP replies, delivery event details, Rspamd symbol options); these strings are never
 *   revealed.
 * - `classifyHeader` is the header safe subset of §2 E7: sender-side identifiers and
 *   authentication facts in clear, To/Cc/Subject and every unknown name masked (fail closed).
 */

/** The mask that replaces a local part (or a whole value without `@`). */
export const MASK = '***';

/** The first code point of a string (never half of a surrogate pair), or `''`. */
const firstCodePoint = (value: string): string => {
  const cp = value.codePointAt(0);
  return cp === undefined ? '' : String.fromCodePoint(cp);
};

/**
 * One address masked (§3.4): `''` → `''`; no `@` → first code point + `***`; `local@domain` →
 * first code point of `local` (none when the local part is empty) + `***@` + `domain` as stored.
 * The last `@` separates the domain, so a quoted local part containing `@` never leaks its tail.
 */
export function maskAddress(value: string): string {
  if (value === '') return '';
  const at = value.lastIndexOf('@');
  if (at === -1) return `${firstCodePoint(value)}${MASK}`;
  return `${firstCodePoint(value.slice(0, at))}${MASK}@${value.slice(at + 1)}`;
}

/**
 * An address-shaped substring of free text (§3.4, Unicode flag): a dot-atom local part of letters,
 * digits and the RFC 5322 atext symbols, or a quoted local part (step 7.2 WP2 deviation 1:
 * quoted local parts are masked too), then `@` and a domain of at least two labels. Labels are
 * ASCII letters, digits and hyphens or (deviation 1) Unicode letters and digits, so U-label IDN
 * domains (SMTPUTF8 replies) are matched as well as A-labels; `user@localhost` (one label) is not
 * an address here. A dot-atom match starts only at the start of a run of local-part characters
 * (the lookbehind; same matches, linear instead of quadratic scanning of long runs). Inputs are
 * bounded by the columns (≤ 2 048 code points).
 */
const ADDRESS_IN_TEXT =
  /(?:"[^"\\\r\n]{0,64}"|(?<![\p{L}\p{N}._%+\-!#$&'*/=?^`{|}~])[\p{L}\p{N}._%+\-!#$&'*/=?^`{|}~]+)@[\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)+/gu;

/** Every address-shaped substring with its local part masked; other text unchanged. */
export function maskAddressesInText(text: string): string {
  return text.replace(ADDRESS_IN_TEXT, (match) => maskAddress(match));
}

/** `maskAddressesInText` for nullable columns. */
export const maskAddressesInNullableText = (text: string | null): string | null =>
  text === null ? null : maskAddressesInText(text);

/** Header values withheld on every read (revealed only through `POST /messages/{id}/reveal`). */
export const MASKED_HEADER_NAMES = ['To', 'Cc', 'Subject'] as const;

/**
 * The header safe subset (§2 E7): sender-side identifiers and authentication facts, in clear for
 * `message:read`. Together with MASKED_HEADER_NAMES this is the step 3.1 stored allow-list
 * (`STORED_HEADER_NAMES` of `@email-gateway/mime-parser`).
 */
export const SAFE_HEADER_NAMES = [
  'From',
  'Sender',
  'Reply-To',
  'Return-Path',
  'Date',
  'Message-ID',
  'In-Reply-To',
  'References',
  'Authentication-Results',
] as const;

/**
 * The headers the gateway stores (step 3.1 M7), in the parser's canonical order: a mirror of
 * `STORED_HEADER_NAMES` of `@email-gateway/mime-parser` (the unit test compares both). Exactly
 * SAFE_HEADER_NAMES plus MASKED_HEADER_NAMES.
 */
export const STORED_HEADER_NAMES = [
  'From',
  'Sender',
  'Reply-To',
  'To',
  'Cc',
  'Subject',
  'Message-ID',
  'Date',
  'In-Reply-To',
  'References',
  'Return-Path',
  'Authentication-Results',
] as const;

export type HeaderClass = 'safe' | 'masked';

const SAFE = new Set<string>(SAFE_HEADER_NAMES.map((name) => name.toLowerCase()));
const MASKED = new Map<string, string>(
  MASKED_HEADER_NAMES.map((name) => [name.toLowerCase(), name]),
);

/**
 * `safe` for a name of the safe subset (case-insensitive, surrounding white space ignored);
 * `masked` for To, Cc, Subject and **every other name** (fail closed: a name outside the 3.1
 * allow-list, a misspelling, an empty name).
 */
export function classifyHeader(name: string): HeaderClass {
  return SAFE.has(name.trim().toLowerCase()) ? 'safe' : 'masked';
}

/** True for the stored rows the reveal returns (To, Cc, Subject; case-insensitive). */
export const isRevealableHeader = (name: string): boolean => MASKED.has(name.trim().toLowerCase());
