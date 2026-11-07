import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Packaged data files (`data/`, package.json "files"), resolved from this module's directory so
 * the same path works from `src/` (tests) and `dist/` (runtime). The only I/O of the package
 * (step 4.5 §4): dictionaries, the IIN table, the IBAN registry, ISO 3166, test cards and the
 * custom-pattern probe corpus.
 */
export const PACKAGE_DIR = join(__dirname, '..');
export const DATA_DIR = join(PACKAGE_DIR, 'data');

export const readDataFile = (...parts: string[]): string =>
  readFileSync(join(DATA_DIR, ...parts), 'utf8');

export const sha256Hex = (value: string | Buffer): string =>
  createHash('sha256').update(value).digest('hex');

/** Non-empty lines of a packaged text file without `#` comments. */
export const readDataLines = (...parts: string[]): string[] =>
  readDataFile(...parts)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'));

/** Deterministic JSON (sorted keys) for version hashes. */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

/** Files hashed into the `data=` part of the engine version (D23). */
export const DLP_DATA_FILES = [
  'iin-ranges.json',
  'iban-registry.json',
  'iso3166.txt',
  'test-cards.txt',
  'probe-corpus.txt',
] as const;

/** Files hashed into the `dict=` part of the engine version (D8, D23). */
export const DLP_DICTIONARY_FILES = [
  'labels.json',
  'business.json',
  'financial.json',
  'context.json',
  'negative.json',
] as const;
