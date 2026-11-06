import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Packaged data files (`data/`, shipped with the package: package.json "files"). Resolved from
 * this module's directory so the same path works from `src/` (tests) and `dist/` (runtime).
 */
export const DATA_DIR = join(__dirname, '..', 'data');

export const readDataFile = (name: string): string => readFileSync(join(DATA_DIR, name), 'utf8');
