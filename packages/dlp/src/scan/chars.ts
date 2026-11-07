/**
 * Character classes and linear scanning primitives of the built-in detectors (step 4.5 D5):
 * every scanner walks the text once, never with a regular expression over message text;
 * anchored regular expressions are applied only to single tokens of at most
 * `MAX_TOKEN_LENGTH` code units.
 */

export const MAX_TOKEN_LENGTH = 128;

export const isDigitCode = (c: number): boolean => c >= 48 && c <= 57;
export const isUpperCode = (c: number): boolean => c >= 65 && c <= 90;
export const isLowerCode = (c: number): boolean => c >= 97 && c <= 122;
export const isAlnumCode = (c: number): boolean =>
  isDigitCode(c) || isUpperCode(c) || isLowerCode(c);

/** A letter or digit of any script (used for "not part of a longer run" checks). */
export const isWordAt = (text: string, index: number): boolean => {
  if (index < 0 || index >= text.length) return false;
  const c = text.charCodeAt(index);
  if (c < 128) return isAlnumCode(c);
  return /[\p{L}\p{N}]/u.test(text[index]!);
};

export type CharClass = (c: number) => boolean;

/** `[A-Za-z0-9]` tokens. */
export const ALNUM: CharClass = isAlnumCode;
/** `[A-Za-z0-9_-]` tokens (API tokens). */
export const TOKEN_CHARS: CharClass = (c) => isAlnumCode(c) || c === 95 || c === 45;
/** `[A-Za-z0-9/+]` tokens (AWS secret access keys). */
export const BASE64_CHARS: CharClass = (c) => isAlnumCode(c) || c === 47 || c === 43;
/** `[A-Za-z0-9_.-]` tokens (JWT). */
export const JWT_CHARS: CharClass = (c) => isAlnumCode(c) || c === 95 || c === 45 || c === 46;

export interface Token {
  start: number;
  end: number;
}

/**
 * Calls `visit` for every maximal token of `cls` that starts in [from, to). A token may extend
 * past `to` (the chunk overlap); tokens longer than `maxLength` are skipped without a call.
 * Linear: every position is examined a bounded number of times.
 */
export function forEachToken(
  text: string,
  from: number,
  to: number,
  cls: CharClass,
  visit: (start: number, end: number) => void,
  maxLength: number = MAX_TOKEN_LENGTH,
): void {
  const end = Math.min(to, text.length);
  let i = Math.max(0, from);
  // A token that started before `from` belongs to the previous chunk.
  while (i < end && i > 0 && cls(text.charCodeAt(i - 1)) && cls(text.charCodeAt(i))) i += 1;
  while (i < end) {
    if (!cls(text.charCodeAt(i))) {
      i += 1;
      continue;
    }
    const start = i;
    while (i < text.length && cls(text.charCodeAt(i)) && i - start <= maxLength) i += 1;
    if (i - start > maxLength) {
      while (i < text.length && cls(text.charCodeAt(i))) i += 1;
      continue;
    }
    visit(start, i);
  }
}

/** A digit run with optional single separators (space or `-`) between digit groups. */
export interface DigitRun {
  start: number;
  end: number;
  digits: string;
  groups: number[];
  /** '' (no separator), ' ', '-', or 'mixed'. */
  separator: '' | ' ' | '-' | 'mixed';
  /** The run is directly preceded by `+`. */
  plus: boolean;
}

export const MAX_DIGIT_RUN = 64;

/**
 * Calls `visit` for every maximal digit run that starts in [from, to): digits, where a single
 * space or `-` may separate digit groups. The run is bounded by characters that are not word
 * characters (letters or digits of any script), so a run inside a longer alphanumeric token is
 * never reported. Runs of more than `MAX_DIGIT_RUN` digits are skipped.
 */
export function forEachDigitRun(
  text: string,
  from: number,
  to: number,
  visit: (run: DigitRun) => void,
): void {
  const end = Math.min(to, text.length);
  let i = Math.max(0, from);
  const isSep = (c: number) => c === 32 || c === 45;
  // Skip a run that started before `from`.
  if (i > 0) {
    while (i < end) {
      const prev = text.charCodeAt(i - 1);
      const c = text.charCodeAt(i);
      const continues =
        (isDigitCode(prev) &&
          (isDigitCode(c) || (isSep(c) && isDigitCode(text.charCodeAt(i + 1))))) ||
        (isSep(prev) && isDigitCode(c) && i >= 2 && isDigitCode(text.charCodeAt(i - 2)));
      if (!continues) break;
      i += 1;
    }
  }
  while (i < end) {
    const c = text.charCodeAt(i);
    if (!isDigitCode(c) || isWordAt(text, i - 1)) {
      i += 1;
      continue;
    }
    const start = i;
    const groups: number[] = [];
    let separator: DigitRun['separator'] = '';
    let digits = '';
    let group = 0;
    let tooLong = false;
    while (i < text.length) {
      const d = text.charCodeAt(i);
      if (isDigitCode(d)) {
        if (digits.length < MAX_DIGIT_RUN) digits += text[i];
        else tooLong = true;
        group += 1;
        i += 1;
        continue;
      }
      if (isSep(d) && isDigitCode(text.charCodeAt(i + 1))) {
        const sep = d === 32 ? ' ' : '-';
        separator = separator === '' ? sep : separator === sep ? separator : 'mixed';
        groups.push(group);
        group = 0;
        i += 1;
        continue;
      }
      break;
    }
    groups.push(group);
    if (tooLong || isWordAt(text, i)) continue;
    visit({ start, end: i, digits, groups, separator, plus: start > 0 && text[start - 1] === '+' });
  }
}

/** Start and end (exclusive, without the line break) of the line holding `index`, bounded. */
export function lineAround(
  text: string,
  index: number,
  bound = 512,
): { start: number; end: number } {
  let start = index;
  const minStart = Math.max(0, index - bound);
  while (start > minStart && text.charCodeAt(start - 1) !== 10) start -= 1;
  let end = index;
  const maxEnd = Math.min(text.length, index + bound);
  while (end < maxEnd && text.charCodeAt(end) !== 10 && text.charCodeAt(end) !== 13) end += 1;
  return { start, end };
}
