import { skeleton } from '@email-gateway/url-security';
import { Deadline } from './deadline';

/**
 * Normalization for lexicon matching with an exact offset map (B8, `bec-text/1`):
 * NFKC (per code point) → remove `\p{Cf}` → case fold → UTS #39 skeleton for Latin tokens only
 * (a token holding a Latin letter, or whose every code point skeletons to ASCII: defeats
 * `gіft card` with a Cyrillic і; Devanagari tokens untouched) → whitespace runs collapsed to
 * one space. `start[i]`/`end[i]` give, for every UTF-16 unit `i` of the normalized text, the
 * UTF-16 range of the source code point it came from, so spans map back exactly.
 */

export const TEXT_DERIVATION_VERSION = 'bec-text/1';

export interface NormalizedText {
  text: string;
  start: number[];
  end: number[];
}

interface Piece {
  value: string;
  start: number;
  end: number;
  token: boolean;
}

const FORMAT = /^\p{Cf}$/u;
const WORD = /^[\p{L}\p{M}\p{N}]$/u;
const SPACE = /^\s$/u;
const LATIN = /\p{Script=Latin}/u;
const DEVANAGARI = /\p{Script=Devanagari}/u;
const isAscii = (value: string): boolean => {
  for (let i = 0; i < value.length; i += 1) if (value.charCodeAt(i) > 0x7f) return false;
  return true;
};

const isWordChar = (value: string): boolean => {
  for (const c of value) if (!WORD.test(c)) return false;
  return value.length > 0;
};

export function normalizeForMatching(
  source: string,
  deadline: Deadline = Deadline.none(),
): NormalizedText {
  // Phase 1: NFKC per code point, strip format characters, case fold; keep source ranges.
  const pieces: Piece[] = [];
  let offset = 0;
  for (const cp of source) {
    deadline.check();
    const start = offset;
    offset += cp.length;
    if (FORMAT.test(cp)) continue;
    const value = cp
      .normalize('NFKC')
      .replace(/\p{Cf}/gu, '')
      .toLowerCase();
    if (!value) continue;
    for (const c of value) pieces.push({ value: c, start, end: offset, token: isWordChar(c) });
  }
  // Phase 2: tokens → skeleton when Latin; other characters: whitespace collapsed.
  const out: string[] = [];
  const startMap: number[] = [];
  const endMap: number[] = [];
  const emit = (value: string, start: number, end: number): void => {
    out.push(value);
    for (let k = 0; k < value.length; k += 1) {
      startMap.push(start);
      endMap.push(end);
    }
  };
  let i = 0;
  while (i < pieces.length) {
    deadline.check();
    const piece = pieces[i]!;
    if (!piece.token) {
      if (SPACE.test(piece.value)) {
        if (out.length > 0 && out.at(-1) !== ' ') emit(' ', piece.start, piece.end);
      } else {
        emit(piece.value, piece.start, piece.end);
      }
      i += 1;
      continue;
    }
    let j = i;
    while (j < pieces.length && pieces[j]!.token) j += 1;
    const token = pieces.slice(i, j);
    const text = token.map((p) => p.value).join('');
    const skeletons = DEVANAGARI.test(text) ? null : token.map((p) => skeleton(p.value));
    const latin = skeletons !== null && (LATIN.test(text) || skeletons.every(isAscii));
    for (let k = 0; k < token.length; k += 1) {
      const p = token[k]!;
      emit(latin ? skeletons[k]! : p.value, p.start, p.end);
    }
    i = j;
  }
  // trailing collapsed space
  if (out.at(-1) === ' ') {
    out.pop();
    startMap.pop();
    endMap.pop();
  }
  return { text: out.join(''), start: startMap, end: endMap };
}

export interface WordToken {
  value: string;
  /** Offsets in the normalized text (UTF-16). */
  start: number;
  end: number;
}

/** Unicode word tokens `[\p{L}\p{M}\p{N}]+` of a normalized text, linear. */
export function wordTokens(text: string, deadline: Deadline = Deadline.none()): WordToken[] {
  const tokens: WordToken[] = [];
  let current = '';
  let start = -1;
  let offset = 0;
  for (const c of text) {
    deadline.check();
    if (WORD.test(c)) {
      if (start < 0) start = offset;
      current += c;
    } else if (start >= 0) {
      tokens.push({ value: current, start, end: offset });
      current = '';
      start = -1;
    }
    offset += c.length;
  }
  if (start >= 0) tokens.push({ value: current, start, end: offset });
  return tokens;
}

/** Maps a normalized range [start, end) back to the source range. */
export function toSourceRange(
  normalized: NormalizedText,
  start: number,
  end: number,
): { start: number; end: number } {
  return { start: normalized.start[start]!, end: normalized.end[end - 1]! };
}
