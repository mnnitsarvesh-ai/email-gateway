import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Packaged files (`data/`, `models/`, `prompts/`, `training/`; package.json "files"), resolved
 * from this module's directory so the same path works from `src/` (tests) and `dist/` (runtime).
 */
export const PACKAGE_DIR = join(__dirname, '..');
export const DATA_DIR = join(PACKAGE_DIR, 'data');

export const readPackageFile = (...parts: string[]): string =>
  readFileSync(join(PACKAGE_DIR, ...parts), 'utf8');

export const readDataFile = (...parts: string[]): string => readPackageFile('data', ...parts);

export const sha256Hex = (value: string | Buffer): string =>
  createHash('sha256').update(value).digest('hex');
