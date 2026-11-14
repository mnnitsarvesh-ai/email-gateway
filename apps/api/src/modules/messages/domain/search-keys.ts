/**
 * The TypeScript side of the step 7.2 message search keys (docs/plan/steps/21-email-explorer-details.md
 * §2 E1, §3.1, ADR-0061). MySQL computes the keys as VIRTUAL generated columns (migration
 * `email_explorer_search`); the explorer applies the same normalization to the value a user
 * searches for, so `normalizeX(value)` must equal what MySQL stores for a row whose column holds
 * `value`. Every function mirrors its SQL expression exactly and is parity-tested against MySQL
 * (integration/messages-search-keys.test.ts):
 *
 *   subject_key    IF(subject IS NULL, NULL, LEFT(REGEXP_REPLACE(REGEXP_REPLACE(REGEXP_REPLACE(
 *                    subject, '^(?:[[:space:]]*+(?:re|fw|fwd|aw|wg|sv|vs|antw|tr|rif|enc|odp)
 *                    [[:space:]]*+(?:\[[0-9]+\][[:space:]]*+)?:)+', '', 1, 1, 'i'),
 *                    '[[:space:]]+', ' '), '^ | $', ''), 128))
 *   sender_domain  IF(LOCATE('@', envelope_from) = 0, NULL,
 *                    LEFT(SUBSTRING_INDEX(envelope_from, '@', -1), 253))
 *   message_id_key IF(internet_message_id IS NULL, NULL,
 *                    LEFT(TRIM(TRAILING '>' FROM TRIM(LEADING '<' FROM TRIM(internet_message_id))), 255))
 *   address_domain IF(LOCATE('@', address) = 0, NULL, LEFT(SUBSTRING_INDEX(address, '@', -1), 253))
 *
 * Details that matter for parity:
 * - ICU's `[[:space:]]` is the Unicode `White_Space` property (25 code points, measured on MySQL
 *   8.4.13): the explicit class below, never JavaScript's `\s` (which adds U+FEFF and lacks
 *   U+0085).
 * - `LEFT(…, n)` counts code points (utf8mb4 characters), never UTF-16 units.
 * - MySQL `TRIM(x)` removes spaces (U+0020) only; `TRIM(LEADING '<' …)` removes every leading `<`.
 * - Case and accents are not normalized here: the columns' collation (`utf8mb4_unicode_ci`)
 *   ignores them when MySQL compares.
 * The JavaScript pattern has no possessive quantifiers; it has no two adjacent unbounded
 * repetitions either, so it is linear like the SQL one.
 */

/** Unicode `White_Space` = ICU `[[:space:]]` (and JavaScript `\p{White_Space}`). */
export const WHITE_SPACE_CLASS =
  '\\u0009-\\u000D\\u0020\\u0085\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000';

const WS = `[${WHITE_SPACE_CLASS}]`;

/** Leading reply/forward markers of the subject key (§2 E1), repeated. */
export const REPLY_MARKER_WORDS = [
  're',
  'fw',
  'fwd',
  'aw',
  'wg',
  'sv',
  'vs',
  'antw',
  'tr',
  'rif',
  'enc',
  'odp',
] as const;

const REPLY_MARKERS = new RegExp(
  `^(?:${WS}*(?:${REPLY_MARKER_WORDS.join('|')})${WS}*(?:\\[[0-9]+\\]${WS}*)?:)+`,
  'iu',
);
const WHITE_SPACE_RUNS = new RegExp(`${WS}+`, 'gu');
const EDGE_SPACE = /^ | $/gu;

/** Lengths of the generated columns (code points). */
export const SUBJECT_KEY_LENGTH = 128;
export const DOMAIN_KEY_LENGTH = 253;
export const MESSAGE_ID_KEY_LENGTH = 255;

/** The first `n` code points of `value` (MySQL `LEFT` on a utf8mb4 string). */
export function firstCodePoints(value: string, n: number): string {
  let out = '';
  let count = 0;
  for (const ch of value) {
    if (count === n) break;
    out += ch;
    count += 1;
  }
  return out;
}

/** Number of code points of `value` (MySQL `CHAR_LENGTH`). */
export function codePointLength(value: string): number {
  return Array.from(value).length;
}

/**
 * `subject_key` of a subject: leading reply/forward markers removed (`Re:`, `Fwd:`, `AW:`,
 * `RE[3]:`, … repeated), every White_Space run collapsed to one space, one leading and one
 * trailing space removed, the first 128 code points. May be empty (a subject of markers only).
 */
export function normalizeSubjectKey(subject: string): string {
  const stripped = subject.replace(REPLY_MARKERS, '');
  const collapsed = stripped.replace(WHITE_SPACE_RUNS, ' ').replace(EDGE_SPACE, '');
  return firstCodePoints(collapsed, SUBJECT_KEY_LENGTH);
}

/**
 * The normalized form of a subject prefix (`subjectPrefix`): the subject key normalization
 * without the truncation (the caller bounds the length, §2 E2: 3–128 code points).
 */
export function normalizeSubjectPrefix(prefix: string): string {
  return prefix.replace(REPLY_MARKERS, '').replace(WHITE_SPACE_RUNS, ' ').replace(EDGE_SPACE, '');
}

/** `message_id_key` of a Message-ID: spaces trimmed, every leading `<` and trailing `>` removed, 255. */
export function normalizeMessageIdKey(messageId: string): string {
  const trimmed = messageId.replace(/^ +| +$/gu, '');
  const unbracketed = trimmed.replace(/^<+/u, '').replace(/>+$/u, '');
  return firstCodePoints(unbracketed, MESSAGE_ID_KEY_LENGTH);
}

/**
 * `sender_domain` / `address_domain` of an address: the part after its last `@` (253 code
 * points), or null when it has no `@` (the null sender). `x@` gives `''`, like SUBSTRING_INDEX.
 */
export function domainOf(address: string): string | null {
  const at = address.lastIndexOf('@');
  if (at < 0) return null;
  return firstCodePoints(address.slice(at + 1), DOMAIN_KEY_LENGTH);
}

/** The `ESCAPE` character of every `LIKE` of the search (code constant, §3.2). */
export const LIKE_ESCAPE = '!';

/** A literal for `LIKE … ESCAPE '!'`: `!`, `%` and `_` escaped (never a wildcard from input). */
export function escapeLike(literal: string): string {
  return literal.replace(/[!%_]/gu, (c) => `${LIKE_ESCAPE}${c}`);
}

/** The `LIKE` pattern of a normalized subject prefix: the escaped prefix, then `%`. */
export const subjectPrefixPattern = (normalizedPrefix: string): string =>
  `${escapeLike(normalizedPrefix)}%`;
