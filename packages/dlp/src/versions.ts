import { DLP_DATA_FILES, DLP_DICTIONARY_FILES, readDataFile, sha256Hex } from './data';

/**
 * Versions recorded with every DLP result (step 4.5 D23). This module imports nothing from
 * `@email-gateway/bec` so the extractor entry point can use it.
 */

/** Extraction rules of D4 (`dlp_scan_results.extractor_version`). */
export const DLP_EXTRACTOR_VERSION = 'dlp-extract/1';
/** The text the evidence offsets refer to: the bec normalization + the extraction rules. */
export const DLP_TEXT_DERIVATION_VERSION = 'dlp-text/1';
/** The exact pdfjs-dist version of the extractor (engine info gauge). */
export const DLP_PDFJS_VERSION = '4.10.38';

const hashFiles = (files: readonly string[], read: (name: string) => string): string =>
  sha256Hex(files.map((name) => `${name}\0${read(name)}`).join('\0')).slice(0, 8);

let cached: { dict: string; data: string } | null = null;

/** `dict=` (built-in dictionaries) and `data=` (IIN, IBAN, ISO 3166, test cards, probe) hashes. */
export function dlpDataVersions(): { dict: string; data: string } {
  cached ??= {
    dict: hashFiles(DLP_DICTIONARY_FILES, (name) => readDataFile('dictionaries', name)),
    data: hashFiles(DLP_DATA_FILES, (name) => readDataFile(name)),
  };
  return cached;
}

/** `dlp/1;dict=<8 hex>;data=<8 hex>;ext=dlp-extract/1` (≤ 96 characters). */
export function dlpEngineVersion(): string {
  const { dict, data } = dlpDataVersions();
  return `dlp/1;dict=${dict};data=${data};ext=${DLP_EXTRACTOR_VERSION}`;
}
