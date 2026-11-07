import { ibanChecksumValid } from '@email-gateway/bec';
import { z } from 'zod';
import { readDataFile, readDataLines } from '../data';

/**
 * Pure checksum and structure validators of `dlp-map/1` (step 4.5 D6). Every function takes the
 * compact normalized form (digits or uppercase alphanumerics without separators) and never
 * throws on malformed input (it returns false / null).
 */

const isDigits = (value: string): boolean => /^[0-9]+$/.test(value);

/** Luhn (ISO/IEC 7812-1) over a digit string. */
export function luhnValid(digits: string): boolean {
  if (digits.length < 2 || !isDigits(digits)) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

/** The Luhn check digit that completes `payload` (corpus generation). */
export function luhnCheckDigit(payload: string): number {
  for (let d = 0; d <= 9; d += 1) if (luhnValid(`${payload}${d}`)) return d;
  throw new Error('unreachable');
}

const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
] as const;
const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
] as const;
const VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9] as const;

const verhoeffState = (digits: string, offset: number): number => {
  let c = 0;
  for (let i = 0; i < digits.length; i += 1) {
    const d = digits.charCodeAt(digits.length - 1 - i) - 48;
    c = VERHOEFF_D[c]![VERHOEFF_P[(i + offset) % 8]![d]!]!;
  }
  return c;
};

/** Verhoeff (dihedral group D5) over a digit string; Aadhaar's check digit. */
export function verhoeffValid(digits: string): boolean {
  if (digits.length < 2 || !isDigits(digits)) return false;
  return verhoeffState(digits, 0) === 0;
}

/** The Verhoeff check digit that completes `payload` (corpus generation). */
export function verhoeffCheckDigit(payload: string): number {
  if (!isDigits(payload)) throw new Error('digits expected');
  return VERHOEFF_INV[verhoeffState(payload, 1)]!;
}

const ibanRegistrySchema = z.strictObject({
  version: z.number().int().min(1),
  description: z.string(),
  lengths: z.record(z.string().regex(/^[A-Z]{2}$/), z.number().int().min(15).max(34)),
});

/** ISO 13616 registry: country → total IBAN length (packaged `data/iban-registry.json`). */
export const IBAN_LENGTHS: Readonly<Record<string, number>> = Object.freeze(
  ibanRegistrySchema.parse(JSON.parse(readDataFile('iban-registry.json'))).lengths,
);

/** The country of a compact IBAN is registered and the length is its exact length. */
export function ibanLengthValid(compact: string): boolean {
  const length = IBAN_LENGTHS[compact.slice(0, 2)];
  return length !== undefined && compact.length === length;
}

/** IBAN validation of BA1 and the custom `mod97` validator: registry length + ISO 7064 mod 97-10. */
export function mod97Valid(compact: string): boolean {
  return ibanLengthValid(compact) && ibanChecksumValid(compact);
}

const GSTIN_CHARSET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';

/** The GSTIN check character (mod 36, alternating weights 1/2) of the first 14 characters. */
export function gstinCheckChar(first14: string): string | null {
  if (!/^[0-9A-Z]{14}$/.test(first14)) return null;
  let sum = 0;
  for (let i = 0; i < 14; i += 1) {
    const value = GSTIN_CHARSET.indexOf(first14[i]!);
    const product = value * (i % 2 === 0 ? 1 : 2);
    sum += Math.floor(product / 36) + (product % 36);
  }
  return GSTIN_CHARSET[(36 - (sum % 36)) % 36]!;
}

/** PAN shape (NI1): 3 letters, entity type, letter, 4 digits, letter. */
export const PAN_PATTERN = /^[A-Z]{3}[PCHABGJLFT][A-Z][0-9]{4}[A-Z]$/;

/** Indian state codes of a GSTIN: 01–38, 97 (other territory), 99 (centre jurisdiction). */
const gstinStateValid = (code: string): boolean => {
  const n = Number(code);
  return (n >= 1 && n <= 38) || n === 97 || n === 99;
};

/** GSTIN (PI4): state code, embedded PAN, entity number, `Z`, check character. */
export function gstinValid(compact: string): boolean {
  if (!/^[0-9]{2}[A-Z0-9]{10}[1-9A-Z]Z[0-9A-Z]$/.test(compact)) return false;
  if (!gstinStateValid(compact.slice(0, 2))) return false;
  if (!PAN_PATTERN.test(compact.slice(2, 12))) return false;
  return gstinCheckChar(compact.slice(0, 14)) === compact[14];
}

const MRZ_WEIGHTS = [7, 3, 1] as const;

/** ICAO 9303 check digit (weights 7-3-1; `<` = 0, A = 10 … Z = 35); null on another character. */
export function mrzCheckDigit(field: string): number | null {
  let sum = 0;
  for (let i = 0; i < field.length; i += 1) {
    const c = field.charCodeAt(i);
    let value: number;
    if (c >= 48 && c <= 57) value = c - 48;
    else if (c >= 65 && c <= 90) value = c - 55;
    else if (c === 60) value = 0;
    else return null;
    sum += value * MRZ_WEIGHTS[i % 3]!;
  }
  return sum % 10;
}

/** The check digit character at the end of an MRZ field is valid. */
export const mrzFieldValid = (field: string, check: string): boolean => {
  const digit = mrzCheckDigit(field);
  return digit !== null && check === String(digit);
};

/** IFSC (BA2): 4 bank letters, `0`, 6 branch alphanumerics. */
export const ifscValid = (value: string): boolean => /^[A-Z]{4}0[A-Z0-9]{6}$/.test(value);

/** ISO 3166-1 alpha-2 codes (packaged `data/iso3166.txt`). */
export const ISO3166_ALPHA2: ReadonlySet<string> = new Set(readDataLines('iso3166.txt'));

export const isIso3166Alpha2 = (code: string): boolean => ISO3166_ALPHA2.has(code);

// ---------------------------------------------------------------------------------------------
// IIN table (PC1)
// ---------------------------------------------------------------------------------------------

const iinSchema = z.strictObject({
  version: z.number().int().min(1),
  description: z.string(),
  brands: z
    .array(
      z.strictObject({
        brand: z.string().regex(/^[a-z]+$/),
        prefixes: z.array(z.string().regex(/^[0-9]{1,6}(-[0-9]{1,6})?$/)).min(1),
        lengths: z.array(z.number().int().min(12).max(19)).min(1),
      }),
    )
    .min(1),
});

interface IinRange {
  brand: string;
  width: number;
  low: number;
  high: number;
  lengths: readonly number[];
  order: number;
}

const IIN_RANGES: readonly IinRange[] = (() => {
  const parsed = iinSchema.parse(JSON.parse(readDataFile('iin-ranges.json')));
  const ranges: IinRange[] = [];
  parsed.brands.forEach((brand, order) => {
    for (const prefix of brand.prefixes) {
      const [low, high = low] = prefix.split('-') as [string, string?];
      if (low.length !== high.length) throw new Error(`iin ${brand.brand}: bad range ${prefix}`);
      ranges.push({
        brand: brand.brand,
        width: low.length,
        low: Number(low),
        high: Number(high),
        lengths: brand.lengths,
        order,
      });
    }
  });
  // Longest prefix first, then file order.
  return ranges.sort((a, b) => b.width - a.width || a.order - b.order);
})();

/**
 * The card brand of a digit string by the IIN table, or null when no brand claims its prefix
 * with that length (the longest matching prefix decides; a brand with the wrong length is no
 * brand).
 */
export function iinBrand(digits: string): string | null {
  if (!isDigits(digits)) return null;
  for (const range of IIN_RANGES) {
    if (digits.length < range.width) continue;
    const prefix = Number(digits.slice(0, range.width));
    if (prefix < range.low || prefix > range.high) continue;
    return range.lengths.includes(digits.length) ? range.brand : null;
  }
  return null;
}

/** Packaged test card numbers (never reported, D5 PC1). */
export const TEST_CARD_NUMBERS: ReadonlySet<string> = new Set(readDataLines('test-cards.txt'));

/** One repeated digit, or a strictly ascending / descending run (mod 10). */
export function trivialDigitRun(digits: string): boolean {
  if (digits.length < 2) return false;
  let same = true;
  let up = true;
  let down = true;
  for (let i = 1; i < digits.length; i += 1) {
    const a = digits.charCodeAt(i - 1) - 48;
    const b = digits.charCodeAt(i) - 48;
    if (a !== b) same = false;
    if ((a + 1) % 10 !== b) up = false;
    if ((a + 9) % 10 !== b) down = false;
  }
  return same || up || down;
}

/** Validators selectable by tenant patterns (D9), keyed by `DLP_PATTERN_VALIDATORS`. */
export const PATTERN_VALIDATORS: Readonly<
  Record<'none' | 'luhn' | 'verhoeff' | 'mod97' | 'gstin', (compact: string) => boolean>
> = Object.freeze({
  none: () => true,
  luhn: luhnValid,
  verhoeff: verhoeffValid,
  mod97: mod97Valid,
  gstin: gstinValid,
});

/** Compact form of a matched value: digits and uppercase alphanumerics only. */
export const compactValue = (value: string): string =>
  value.replace(/[^0-9A-Za-z]/g, '').toUpperCase();

/**
 * Applies a tenant pattern's validator to a matched value: `luhn` / `verhoeff` check the digits
 * of the match (a prefix such as `CARD-` is ignored), `mod97` / `gstin` its compact
 * uppercase alphanumeric form.
 */
export function validatePatternValue(
  validator: keyof typeof PATTERN_VALIDATORS,
  value: string,
): boolean {
  const digitsOnly = validator === 'luhn' || validator === 'verhoeff';
  return PATTERN_VALIDATORS[validator](
    digitsOnly ? value.replace(/[^0-9]/g, '') : compactValue(value),
  );
}
