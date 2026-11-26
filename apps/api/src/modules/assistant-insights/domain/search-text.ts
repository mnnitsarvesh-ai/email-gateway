import { LIKE_ESCAPE, SNIPPET_MAX_CHARS } from '../insights.constants';

/**
 * Pure text helpers of the owner's content search (step AI-6 D4): the escaped `LIKE` pattern, the
 * folding that mirrors the case- and accent-insensitive collation for locating the match, and the
 * sanitized snippet cut around the first match.
 */

/**
 * `%q%` for `LIKE … ESCAPE '!'`: the escape character itself, `%` and `_` are escaped so every
 * character of the query matches literally. The pattern is always a bound parameter.
 */
export function likeContainsPattern(query: string): string {
  const escaped = query.replace(/[!%_]/g, (ch) => `${LIKE_ESCAPE}${ch}`);
  return `%${escaped}%`;
}

// C0 and C1 controls (incl. tab and line breaks, which a one-line snippet turns into spaces
// first) and DEL.
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001F\u007F-\u009F]/g;
// The same without tab (09) and line feed (0A): multi-line user text keeps its lines.
// eslint-disable-next-line no-control-regex
const CONTROL_KEEP_LINES = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g;
// Bidi marks, embeddings, overrides and isolates.
const BIDI = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;
// Zero-width space, non-joiner, joiner, word joiner, BOM / zero-width no-break space, soft hyphen.
const ZERO_WIDTH = /[\u00AD\u200B-\u200D\u2060\uFEFF]/g;
// Lone surrogates never render; they are dropped with the invisible characters.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

/**
 * One line of displayable text: bidi and zero-width characters and lone surrogates are removed,
 * whitespace runs (incl. tabs and line breaks) become one space, then the remaining control
 * characters are removed; trimmed.
 */
export function sanitizeLine(value: string): string {
  return (
    value
      // Invisible characters first: `\s` also matches U+FEFF.
      .replace(BIDI, '')
      .replace(ZERO_WIDTH, '')
      .replace(LONE_SURROGATE, '')
      .replace(/\s+/g, ' ')
      .replace(CONTROL, '')
      .replace(/ {2,}/g, ' ')
      .trim()
  );
}

/**
 * User-written text kept as written (line breaks and tabs stay), with control, bidi and
 * zero-width characters removed; trimmed. Used for feedback comments.
 */
export function sanitizeUserText(value: string): string {
  return value
    .replace(/\r\n?/g, '\n')
    .replace(CONTROL_KEEP_LINES, '')
    .replace(BIDI, '')
    .replace(ZERO_WIDTH, '')
    .replace(LONE_SURROGATE, '')
    .trim();
}

/** Case- and accent-folded form of one code point (NFD without combining marks, lower case). */
function foldPoint(point: string): string {
  return point.normalize('NFD').replace(/\p{M}/gu, '').toLowerCase();
}

/**
 * The index (in code points of `text`) of the first occurrence of `query` under case and accent
 * folding, or -1. Mirrors `utf8mb4_0900_ai_ci` closely enough to place the snippet; when the
 * database matched but this does not (rare collation differences), the snippet starts at the
 * beginning of the text.
 */
export function foldedIndexOf(points: readonly string[], query: string): number {
  const folded: string[] = [];
  const origin: number[] = [];
  points.forEach((point, index) => {
    for (const ch of Array.from(foldPoint(point))) {
      folded.push(ch);
      origin.push(index);
    }
  });
  const needle = Array.from(
    Array.from(query)
      .map((p) => foldPoint(p))
      .join(''),
  );
  if (needle.length === 0 || needle.length > folded.length) return -1;
  outer: for (let i = 0; i + needle.length <= folded.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (folded[i + j] !== needle[j]) continue outer;
    }
    return origin[i]!;
  }
  return -1;
}

/**
 * The search snippet (D4): the sanitized one-line text, at most `max` code points (incl. the
 * ellipses), cut around the first match of `query` so the match is visible with context on both
 * sides; without a match the beginning of the text.
 */
export function snippetOf(text: string, query: string, max = SNIPPET_MAX_CHARS): string {
  const points = Array.from(sanitizeLine(text));
  if (points.length <= max) return points.join('');
  const queryPoints = Array.from(sanitizeLine(query));
  const at = foldedIndexOf(points, queryPoints.join(''));
  if (at < 0) return `${points.slice(0, max - 1).join('')}…`;
  const matchLength = Math.min(queryPoints.length, max - 2);
  // Room left for context once the match and both ellipses are placed.
  const context = Math.max(0, max - 2 - matchLength);
  let start = Math.max(0, at - Math.floor(context / 2));
  // No leading ellipsis needed when the window starts at the beginning.
  if (start === 0) return `${points.slice(0, max - 1).join('')}…`;
  let end = start + (max - 2);
  if (end >= points.length) {
    // The window reaches the end: only a leading ellipsis.
    start = points.length - (max - 1);
    return `…${points.slice(start).join('')}`;
  }
  end = Math.min(end, points.length);
  return `…${points.slice(start, end).join('')}…`;
}
