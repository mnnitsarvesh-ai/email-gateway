import { forEachDigitRun, isDigitCode, type DigitRun } from '../scan/chars';
import {
  TEST_CARD_NUMBERS,
  iinBrand,
  luhnValid,
  trivialDigitRun,
  verhoeffValid,
} from '../validators';
import { enabled, type DetectorContext } from './context';

/**
 * Digit-run detectors (step 4.5 D5): PC1 payment cards, NI2 Aadhaar (gated, D17), PI2 Indian
 * mobile numbers and the account number of BA2 (with an IFSC in the window). One linear pass
 * over the maximal digit runs of the chunk.
 */

const CARD_GROUPINGS = ['4-4-4-4', '4-4-4-4-3', '4-6-5', '4-6-4'] as const;

const groupingOf = (run: DigitRun): string => run.groups.join('-');

/** The run is a card candidate shape: contiguous 13–19 digits or a brand grouping. */
const cardShape = (run: DigitRun): 'plain' | 'grouped' | null => {
  const n = run.digits.length;
  if (n < 13 || n > 19) return null;
  if (run.groups.length === 1) return 'plain';
  if (run.separator === 'mixed') return null;
  return (CARD_GROUPINGS as readonly string[]).includes(groupingOf(run)) ? 'grouped' : null;
};

/** A month/year expiry (`MM/YY` or `MM/YYYY`) inside [lo, hi). Hand-written scan. */
export function hasExpiryNear(text: string, lo: number, hi: number): boolean {
  const from = Math.max(0, lo);
  const to = Math.min(text.length, hi);
  for (let i = from; i + 4 < to + 1; i += 1) {
    if (text.charCodeAt(i + 2) !== 47) continue; // '/'
    if (!isDigitCode(text.charCodeAt(i)) || !isDigitCode(text.charCodeAt(i + 1))) continue;
    if (!isDigitCode(text.charCodeAt(i + 3)) || !isDigitCode(text.charCodeAt(i + 4))) continue;
    if (i > 0 && isDigitCode(text.charCodeAt(i - 1))) continue;
    let end = i + 5;
    if (isDigitCode(text.charCodeAt(end)) && isDigitCode(text.charCodeAt(end + 1))) end += 2;
    if (isDigitCode(text.charCodeAt(end))) continue;
    const month = Number(text.slice(i, i + 2));
    if (month >= 1 && month <= 12) return true;
  }
  return false;
}

function cardCandidate(ctx: DetectorContext, run: DigitRun): void {
  if (!enabled(ctx, 'PC1')) return;
  const shape = cardShape(run);
  if (!shape) return;
  if (!luhnValid(run.digits)) return;
  const brand = iinBrand(run.digits);
  if (!brand) return;
  // Packaged test numbers, one repeated digit and trivial runs are never candidates.
  if (TEST_CARD_NUMBERS.has(run.digits) || trivialDigitRun(run.digits)) return;
  let base = 0.45;
  if (shape === 'grouped') base += 0.1;
  if (hasExpiryNear(ctx.text, run.start - ctx.window, run.end + ctx.window)) base += 0.1;
  ctx.emit({
    detector: 'PC1',
    segment: ctx.segment,
    start: run.start,
    end: run.end,
    value: ctx.text.slice(run.start, run.end),
    compact: run.digits,
    base,
    context: ['card'],
    contextBonus: 0.3,
    requiresContext: false,
    negative: 'standard',
    codePenalty: true,
    extra: { brand },
  });
}

/** Aadhaar shape: `dddd dddd dddd`, `dddd-dddd-dddd` or 12 contiguous digits, first 2–9. */
export function aadhaarShape(
  run: Pick<DigitRun, 'digits' | 'groups' | 'separator'>,
): 'plain' | 'grouped' | null {
  if (run.digits.length !== 12) return null;
  const first = run.digits.charCodeAt(0) - 48;
  if (first < 2) return null;
  if (run.groups.length === 1) return 'plain';
  if (run.separator === 'mixed' || run.groups.join('-') !== '4-4-4') return null;
  return 'grouped';
}

function aadhaarCandidate(ctx: DetectorContext, run: DigitRun): void {
  // Gated (D17): without the recorded compliance basis NI2 does not run at all.
  if (!ctx.aadhaarEnabled) return;
  const shape = aadhaarShape(run);
  if (!shape || !verhoeffValid(run.digits)) return;
  ctx.emit({
    detector: 'NI2',
    segment: ctx.segment,
    start: run.start,
    end: run.end,
    value: ctx.text.slice(run.start, run.end),
    compact: run.digits,
    base: shape === 'grouped' ? 0.65 : 0.55,
    context: ['aadhaar'],
    contextBonus: 0.35,
    requiresContext: false,
    negative: 'standard',
    codePenalty: false,
    extra: {},
  });
}

/** The 10-digit Indian mobile number of a run (prefix `+91` / `91` / `0` removed), or null. */
export function indianMobile(
  run: Pick<DigitRun, 'digits' | 'groups' | 'plus'>,
): { number: string; plus91: boolean } | null {
  const { digits, groups } = run;
  const isMobile = (d: string, g: readonly number[]) =>
    d.length === 10 &&
    d.charCodeAt(0) >= 54 &&
    (g.length === 1 || (g.length === 2 && g[0] === 5 && g[1] === 5));
  if (!run.plus && isMobile(digits, groups)) return { number: digits, plus91: false };
  for (const prefix of run.plus ? ['91'] : ['91', '0']) {
    if (!digits.startsWith(prefix)) continue;
    const rest = digits.slice(prefix.length);
    const first = groups[0]!;
    // The prefix is its own group (`+91 98765 43210`) or part of the first one (`+919876543210`).
    const restGroups =
      first === prefix.length ? groups.slice(1) : [first - prefix.length, ...groups.slice(1)];
    if (first >= prefix.length && isMobile(rest, restGroups)) {
      return { number: rest, plus91: run.plus };
    }
  }
  return null;
}

function mobileCandidate(ctx: DetectorContext, run: DigitRun): void {
  if (!enabled(ctx, 'PI2')) return;
  const mobile = indianMobile(run);
  if (!mobile) return;
  if (trivialDigitRun(mobile.number)) return;
  const start = run.plus ? run.start - 1 : run.start;
  ctx.emit({
    detector: 'PI2',
    segment: ctx.segment,
    start,
    end: run.end,
    value: ctx.text.slice(start, run.end),
    compact: mobile.number,
    base: mobile.plus91 ? 0.6 : 0.5,
    context: ['mobile'],
    contextBonus: 0.3,
    requiresContext: false,
    negative: 'no_phone',
    codePenalty: true,
    extra: {},
  });
}

function accountCandidate(ctx: DetectorContext, run: DigitRun): void {
  if (!enabled(ctx, 'BA2') || ctx.ifsc.length === 0) return;
  if (run.groups.length !== 1 || run.digits.length < 9 || run.digits.length > 18) return;
  if (trivialDigitRun(run.digits)) return;
  const lo = run.start - ctx.window;
  const hi = run.end + ctx.window;
  const ifsc = ctx.ifsc.find((t) => t.end > lo && t.start < hi);
  if (!ifsc) return;
  ctx.emit({
    detector: 'BA2',
    segment: ctx.segment,
    start: run.start,
    end: run.end,
    value: ctx.text.slice(run.start, run.end),
    compact: run.digits,
    base: 0.5,
    context: ['bank_account'],
    contextBonus: 0.3,
    requiresContext: false,
    negative: null,
    codePenalty: false,
    extra: { ifsc: ifsc.value },
  });
}

/** PC1, NI2, PI2 and BA2 over the digit runs starting in [from, to). */
export function scanDigitRuns(ctx: DetectorContext, from: number, to: number): void {
  forEachDigitRun(ctx.text, from, to, (run) => {
    cardCandidate(ctx, run);
    aadhaarCandidate(ctx, run);
    mobileCandidate(ctx, run);
    accountCandidate(ctx, run);
  });
}
