import { Deadline } from './deadline';

/**
 * Financial identifier detectors for C10 (B8): hand-written linear scanners over the source
 * text (no backtracking regular expression is applied to message text; the anchored checks
 * below run on single short tokens). Only counts are recorded.
 *
 * - IBAN: 2 letters + 2 digits + 11–30 alphanumerics (print form with single spaces allowed),
 *   ISO 13616 mod-97 = 1.
 * - SWIFT/BIC: 8 or 11 characters (`AAAA BB CC [DDD]`) with "swift" or "bic" within 5 tokens.
 * - IFSC (`[A-Z]{4}0[A-Z0-9]{6}`) with an account number (9–18 digits) within 10 tokens.
 * - Amounts with a currency (₹, Rs./Rs, INR, rupees, $, USD, €, EUR).
 */

export interface PatternCounts {
  iban: number;
  swift: number;
  ifscAccount: number;
  amount: number;
}

export const emptyPatternCounts = (): PatternCounts => ({
  iban: 0,
  swift: 0,
  ifscAccount: 0,
  amount: 0,
});

const MAX_COUNT = 64;

const isUpper = (c: number): boolean => c >= 65 && c <= 90;
const isDigit = (c: number): boolean => c >= 48 && c <= 57;
const isAlnumAscii = (c: number): boolean => isUpper(c) || isDigit(c) || (c >= 97 && c <= 122);
const isWordCode = (s: string, i: number): boolean => {
  const c = s.charCodeAt(i);
  if (Number.isNaN(c)) return false;
  if (c < 128) return isAlnumAscii(c);
  return /[\p{L}\p{N}]/u.test(s[i]!);
};

/** ISO 13616 / ISO 7064 mod 97-10 over a compact IBAN. */
export function ibanChecksumValid(compact: string): boolean {
  if (compact.length < 15 || compact.length > 34) return false;
  if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]+$/.test(compact)) return false;
  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    const value = isDigit(code) ? String(code - 48) : String(code - 55);
    for (const digit of value) remainder = (remainder * 10 + (digit.charCodeAt(0) - 48)) % 97;
  }
  return remainder === 1;
}

interface RawToken {
  value: string;
  start: number;
  end: number;
}

function rawTokens(text: string, deadline: Deadline): RawToken[] {
  const tokens: RawToken[] = [];
  let i = 0;
  while (i < text.length) {
    deadline.check();
    if (!isWordCode(text, i)) {
      i += 1;
      continue;
    }
    const start = i;
    while (i < text.length && isWordCode(text, i)) i += 1;
    tokens.push({ value: text.slice(start, i), start, end: i });
  }
  return tokens;
}

/** IBANs: scans from each token start; consumed characters are skipped (linear). */
function countIbans(text: string, deadline: Deadline): number {
  let count = 0;
  let i = 0;
  while (i + 4 <= text.length && count < MAX_COUNT) {
    deadline.check();
    const atStart = i === 0 || !isWordCode(text, i - 1);
    if (
      !atStart ||
      !isUpper(text.charCodeAt(i)) ||
      !isUpper(text.charCodeAt(i + 1)) ||
      !isDigit(text.charCodeAt(i + 2)) ||
      !isDigit(text.charCodeAt(i + 3))
    ) {
      i += 1;
      continue;
    }
    // Collect up to 34 compact characters, single spaces allowed between groups.
    let compact = '';
    const groupEnds: number[] = []; // compact lengths at each space boundary
    let j = i;
    while (j < text.length && compact.length < 34) {
      const c = text.charCodeAt(j);
      if (isUpper(c) || isDigit(c)) {
        compact += text[j]!;
        j += 1;
      } else if (c === 32 && j + 1 < text.length) {
        const n = text.charCodeAt(j + 1);
        if (!(isUpper(n) || isDigit(n))) break;
        groupEnds.push(compact.length);
        j += 1;
      } else {
        break;
      }
    }
    const endsAtBoundary = j >= text.length || !isWordCode(text, j);
    const candidates = [...(endsAtBoundary ? [compact.length] : []), ...groupEnds.reverse()];
    let found = false;
    for (const length of candidates) {
      if (ibanChecksumValid(compact.slice(0, length))) {
        count += 1;
        found = true;
        break;
      }
    }
    i = found ? j : i + 1;
  }
  return count;
}

const BIC = /^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/;
const IFSC = /^[A-Z]{4}0[A-Z0-9]{6}$/;
const ACCOUNT = /^[0-9]{9,18}$/;
const CURRENCY_WORDS = new Set(['rs', 'inr', 'usd', 'eur', 'rupees']);
const CURRENCY_SYMBOLS = new Set(['₹', '$', '€']);

function countAmounts(text: string, tokens: readonly RawToken[], deadline: Deadline): number {
  let count = 0;
  const numberAt = (pos: number): number => {
    // returns end of a number starting at pos (after optional spaces/dots), or -1
    let k = pos;
    let skipped = 0;
    while (k < text.length && (text[k] === ' ' || text[k] === '.') && skipped < 3) {
      k += 1;
      skipped += 1;
    }
    if (!isDigit(text.charCodeAt(k))) return -1;
    while (k < text.length && (isDigit(text.charCodeAt(k)) || text[k] === ',')) k += 1;
    return k;
  };
  for (let i = 0; i < text.length && count < MAX_COUNT; i += 1) {
    deadline.check();
    if (CURRENCY_SYMBOLS.has(text[i]!) && numberAt(i + 1) > 0) count += 1;
  }
  for (let t = 0; t < tokens.length && count < MAX_COUNT; t += 1) {
    deadline.check();
    const token = tokens[t]!;
    const lower = token.value.toLowerCase();
    if (CURRENCY_WORDS.has(lower)) {
      if (numberAt(token.end) > 0) {
        count += 1;
        continue;
      }
      const previous = tokens[t - 1];
      if (previous && /^[0-9][0-9]*$/.test(previous.value) && token.start - previous.end <= 1) {
        count += 1;
      }
    }
  }
  return count;
}

export function detectPatterns(text: string, deadline: Deadline = Deadline.none()): PatternCounts {
  const tokens = rawTokens(text, deadline);
  const lowerTokens = tokens.map((t) => t.value.toLowerCase());
  let swift = 0;
  let ifscAccount = 0;
  for (let t = 0; t < tokens.length; t += 1) {
    deadline.check();
    const value = tokens[t]!.value;
    if ((value.length === 8 || value.length === 11) && BIC.test(value) && swift < MAX_COUNT) {
      for (let k = Math.max(0, t - 5); k <= Math.min(tokens.length - 1, t + 5); k += 1) {
        if (k !== t && (lowerTokens[k] === 'swift' || lowerTokens[k] === 'bic')) {
          swift += 1;
          break;
        }
      }
    }
    if (value.length === 11 && IFSC.test(value) && ifscAccount < MAX_COUNT) {
      for (let k = Math.max(0, t - 10); k <= Math.min(tokens.length - 1, t + 10); k += 1) {
        if (k !== t && ACCOUNT.test(tokens[k]!.value)) {
          ifscAccount += 1;
          break;
        }
      }
    }
  }
  return {
    iban: countIbans(text, deadline),
    swift,
    ifscAccount,
    amount: countAmounts(text, tokens, deadline),
  };
}

export const addPatternCounts = (a: PatternCounts, b: PatternCounts): PatternCounts => ({
  iban: a.iban + b.iban,
  swift: a.swift + b.swift,
  ifscAccount: a.ifscAccount + b.ifscAccount,
  amount: a.amount + b.amount,
});
