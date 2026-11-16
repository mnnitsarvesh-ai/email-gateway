import { z } from 'zod';
import { linesOf } from './model';

/**
 * Field-level zod building blocks of the DLP and BEC forms. They do input hygiene only (an integer
 * input holds an integer, a required input is not empty, list lengths and item lengths of the
 * request schema): the API normalizes and validates every value and its answer always wins
 * (design §2 B2, B13). Values stay strings in the form (no transforms, so the react-hook-form
 * input and output types are equal); the body builders convert them.
 */

/** A string enum from a value list of `model.ts`. */
export function enumOf<T extends string>(values: readonly T[]) {
  return z.enum(values as unknown as [T, ...T[]]);
}

/** Trimmed text of `min`–`max` characters. */
export function text(min: number, max: number, required = 'Enter a value') {
  return z
    .string()
    .trim()
    .min(min, min <= 1 ? required : `Enter at least ${min} characters`)
    .max(max, `At most ${max} characters`);
}

/** Trimmed optional text (`''` when empty) of at most `max` characters. */
export function optionalText(max: number) {
  return z.string().trim().max(max, `At most ${max} characters`);
}

function wholeNumberProblem(value: string, min: number, max: number): string | null {
  if (!/^\d+$/.test(value)) return 'Enter a whole number';
  const number = Number(value);
  return number < min || number > max ? `Enter a number from ${min} to ${max}` : null;
}

/** A whole number typed into a text input, `min`–`max`. */
export function wholeNumber(min: number, max: number) {
  return z
    .string()
    .trim()
    .superRefine((value, ctx) => {
      const problem = wholeNumberProblem(value, min, max);
      if (problem) ctx.addIssue({ code: 'custom', message: problem });
    });
}

/** An optional whole number (`''` when empty). */
export function optionalWholeNumber(min: number, max: number) {
  return z
    .string()
    .trim()
    .superRefine((value, ctx) => {
      if (!value) return;
      const problem = wholeNumberProblem(value, min, max);
      if (problem) ctx.addIssue({ code: 'custom', message: problem });
    });
}

const CONFIDENCE_SHAPE = /^(0(\.\d{1,2})?|1(\.0{1,2})?|\.\d{1,2})$/;
const CONFIDENCE_MESSAGE =
  'Enter a value from 0.5 to 1 with at most two decimals (for example 0.8)';

function confidenceProblem(value: string): boolean {
  const number = Number(value);
  return !CONFIDENCE_SHAPE.test(value) || number < 0.5 || number > 1;
}

/** A confidence from 0.5 to 1 with at most two decimals (the API's rule). */
export function confidence() {
  return z
    .string()
    .trim()
    .superRefine((value, ctx) => {
      if (confidenceProblem(value)) ctx.addIssue({ code: 'custom', message: CONFIDENCE_MESSAGE });
    });
}

/** An optional confidence (`''` when empty). */
export function optionalConfidence() {
  return z
    .string()
    .trim()
    .superRefine((value, ctx) => {
      if (value && confidenceProblem(value)) {
        ctx.addIssue({ code: 'custom', message: CONFIDENCE_MESSAGE });
      }
    });
}

/** An optional number input as a number (`undefined` when empty). */
export function numberOrUndefined(value: string): number | undefined {
  return value.trim() ? Number(value.trim()) : undefined;
}

export type ItemCheck = 'address' | 'domain' | null;

const ADDRESS_SHAPE = /^[^\s@]+@[^\s@]+$/;
const DOMAIN_SHAPE = /^[^\s@/]+\.[^\s@/]+$/;

function itemProblem(value: string, check: ItemCheck): string | null {
  if (check === 'address' && !ADDRESS_SHAPE.test(value)) {
    return 'enter an address such as name@example.com';
  }
  if (check === 'domain' && !DOMAIN_SHAPE.test(value)) return 'enter a domain such as example.com';
  return null;
}

/**
 * A "one per line" list (the textarea text): empty lines are ignored, the count and each item's
 * length (and shape, for addresses and domains) are checked, a problem is named by its line.
 */
export function lineList(options: {
  max: number;
  min?: number;
  itemMin?: number;
  itemMax: number;
  check?: ItemCheck;
  /** Plural noun of the items ("domains"); `one` is the singular ("domain"). */
  noun: string;
  one?: string;
}) {
  const { max, min = 0, itemMin = 1, itemMax, check = null, noun, one = noun } = options;
  return z.string().superRefine((textValue, ctx) => {
    const entries = linesOf(textValue);
    if (entries.length < min) {
      ctx.addIssue({
        code: 'custom',
        message:
          min === 1 ? `Enter at least one ${one}` : `Enter at least ${min} ${noun} (one per line)`,
      });
      return;
    }
    if (entries.length > max) {
      ctx.addIssue({
        code: 'custom',
        message: `At most ${max} ${noun}; this list has ${entries.length}`,
      });
      return;
    }
    for (const entry of entries) {
      const problem =
        entry.value.length < itemMin || entry.value.length > itemMax
          ? `${itemMin}–${itemMax} characters`
          : itemProblem(entry.value, check);
      if (problem) {
        ctx.addIssue({ code: 'custom', message: `Line ${entry.line}: ${problem}` });
        return;
      }
    }
  });
}

/** `YYYY-MM-DD` whose end of day (UTC) is in the future; `''` allowed when `optional`. */
export function futureDay(options: { optional?: boolean; required?: string } = {}) {
  const { optional = false, required = 'Choose a date' } = options;
  return z.string().superRefine((value, ctx) => {
    const problem = futureDayProblem(value, optional, required);
    if (problem) ctx.addIssue({ code: 'custom', message: problem });
  });
}

/** The problem of a `YYYY-MM-DD` value that must end in the future (`null` when fine). */
export function futureDayProblem(
  value: string,
  optional = false,
  required = 'Choose a date',
): string | null {
  if (!value) return optional ? null : required;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value) || Number.isNaN(Date.parse(`${value}T23:59:59Z`))) {
    return 'Enter a date';
  }
  return Date.parse(`${value}T23:59:59Z`) <= Date.now() ? 'Choose a date in the future' : null;
}
