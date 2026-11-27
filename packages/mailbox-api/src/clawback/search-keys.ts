/**
 * Parity copy of the step 7.2 message search keys (design note 37 C4.4).
 *
 * SOURCE: apps/api/src/modules/messages/domain/search-keys.ts (`normalizeSubjectKey`,
 * `normalizeMessageIdKey`, `WHITE_SPACE_CLASS`, `REPLY_MARKER_WORDS`, `firstCodePoints`). The
 * mailbox-worker cannot import the api, so this file repeats those functions exactly; the unit
 * test carries the api's table vectors verbatim. Change both files together, never one alone.
 *
 * MySQL computes `email_messages.subject_key` / `message_id_key` as generated columns:
 *
 *   subject_key    LEFT(REGEXP_REPLACE(REGEXP_REPLACE(REGEXP_REPLACE(subject,
 *                    '^(?:[[:space:]]*+(?:re|fw|fwd|aw|wg|sv|vs|antw|tr|rif|enc|odp)
 *                    [[:space:]]*+(?:\[[0-9]+\][[:space:]]*+)?:)+', '', 1, 1, 'i'),
 *                    '[[:space:]]+', ' '), '^ | $', ''), 128)
 *   message_id_key LEFT(TRIM(TRAILING '>' FROM TRIM(LEADING '<' FROM TRIM(internet_message_id))), 255)
 *
 * ICU `[[:space:]]` is Unicode `White_Space` (25 code points; never JavaScript `\s`), `LEFT`
 * counts code points, MySQL `TRIM(x)` removes U+0020 only.
 */

/** Unicode `White_Space` = ICU `[[:space:]]` (the api's `WHITE_SPACE_CLASS`). */
export const SEARCH_KEY_WHITE_SPACE_CLASS =
  '\\u0009-\\u000D\\u0020\\u0085\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000';

const WS = `[${SEARCH_KEY_WHITE_SPACE_CLASS}]`;

/** Leading reply/forward markers of the subject key (the api's `REPLY_MARKER_WORDS`). */
export const SUBJECT_KEY_REPLY_MARKER_WORDS = [
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
  `^(?:${WS}*(?:${SUBJECT_KEY_REPLY_MARKER_WORDS.join('|')})${WS}*(?:\\[[0-9]+\\]${WS}*)?:)+`,
  'iu',
);
const WHITE_SPACE_RUNS = new RegExp(`${WS}+`, 'gu');
const EDGE_SPACE = /^ | $/gu;

/** Lengths of the generated columns (code points). */
export const SEARCH_SUBJECT_KEY_LENGTH = 128;
export const SEARCH_MESSAGE_ID_KEY_LENGTH = 255;

/** The first `n` code points of `value` (MySQL `LEFT` on a utf8mb4 string). */
function firstCodePoints(value: string, n: number): string {
  let out = '';
  let count = 0;
  for (const ch of value) {
    if (count === n) break;
    out += ch;
    count += 1;
  }
  return out;
}

/**
 * `subject_key` of a subject (= the api's `normalizeSubjectKey`): leading reply/forward markers
 * removed (repeated), every White_Space run collapsed to one space, one leading and one trailing
 * space removed, the first 128 code points. May be empty.
 */
export function subjectKeyOf(subject: string): string {
  const stripped = subject.replace(REPLY_MARKERS, '');
  const collapsed = stripped.replace(WHITE_SPACE_RUNS, ' ').replace(EDGE_SPACE, '');
  return firstCodePoints(collapsed, SEARCH_SUBJECT_KEY_LENGTH);
}

/**
 * `message_id_key` of a Message-ID (= the api's `normalizeMessageIdKey`): spaces trimmed, every
 * leading `<` and trailing `>` removed, the first 255 code points.
 */
export function messageIdKeyOf(messageId: string): string {
  const trimmed = messageId.replace(/^ +| +$/gu, '');
  const unbracketed = trimmed.replace(/^<+/u, '').replace(/>+$/u, '');
  return firstCodePoints(unbracketed, SEARCH_MESSAGE_ID_KEY_LENGTH);
}
