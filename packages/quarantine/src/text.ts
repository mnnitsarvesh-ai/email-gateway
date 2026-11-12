/**
 * Display-text sanitization (step 5.3 Q9, Q11, Q20): what the subject in search results and
 * digests, file names and preview text go through. Unicode NFC; C0/C1 controls removed (except
 * `\n`/`\t` when `multiline`); bidi embeddings, overrides and isolates (U+202A–U+202E,
 * U+2066–U+2069, U+200E/U+200F, U+061C) and zero-width/invisible characters (U+200B–U+200D,
 * U+2060–U+2064, U+FEFF, U+180E, U+00AD) removed; cut to `maxChars` code points.
 */

// eslint-disable-next-line no-control-regex -- removing control characters is the point
const CONTROLS_SINGLE_LINE = /[\u0000-\u001f\u007f-\u009f]/g;
// eslint-disable-next-line no-control-regex -- removing control characters is the point
const CONTROLS_MULTILINE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;
const BIDI = /[\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]/g;
const INVISIBLE = /[\u200b-\u200d\u2060-\u2064\ufeff\u180e\u00ad]/g;

export interface SanitizedText {
  text: string;
  truncated: boolean;
}

export function sanitizeDisplayText(
  input: string,
  options: { maxChars: number; multiline?: boolean },
): SanitizedText {
  let text = input.normalize('NFC');
  text = text.replace(/\r\n?/g, '\n');
  text = text.replace(
    options.multiline === true ? CONTROLS_MULTILINE : CONTROLS_SINGLE_LINE,
    (c) => (options.multiline !== true && (c === '\n' || c === '\t') ? ' ' : ''),
  );
  text = text.replace(BIDI, '').replace(INVISIBLE, '');
  if (options.multiline !== true) text = text.replace(/\s+/g, ' ').trim();
  const points = [...text];
  if (points.length <= options.maxChars) return { text, truncated: false };
  return { text: points.slice(0, options.maxChars).join(''), truncated: true };
}

/** A subject for search results (≤ 256) and digests (≤ 78): single line, sanitized. */
export const sanitizeSubject = (subject: string | null, maxChars = 256): string | null =>
  subject === null ? null : sanitizeDisplayText(subject, { maxChars }).text;
