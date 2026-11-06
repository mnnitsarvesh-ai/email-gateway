import { readDataFile } from '../data';

/**
 * UTS #39 §4 skeleton over the Unicode confusables table (U7): NFD → map every code point
 * through `confusables.txt` (Unicode 16.0.0, generated into data/confusables.json by
 * scripts/generate-confusables.mjs) → NFD → lower case. Digits and hyphen are kept as
 * characters; their table mappings (`1` → `l`, `0` → `O` → `o`) apply.
 */

interface ConfusablesFile {
  source: string;
  unicodeVersion: string;
  sourceSha256: string;
  entries: number;
  map: Record<string, string>;
}

let table: { version: string; sha256: string; map: Map<string, string> } | null = null;

function load(): NonNullable<typeof table> {
  if (table) return table;
  const file = JSON.parse(readDataFile('confusables.json')) as ConfusablesFile;
  const map = new Map(Object.entries(file.map));
  if (map.size !== file.entries || map.size === 0) {
    throw new Error('data/confusables.json is inconsistent (entry count)');
  }
  table = { version: file.unicodeVersion, sha256: file.sourceSha256, map };
  return table;
}

/** Unicode version of the confusables table (part of `lookalikeVersion`). */
export function confusablesVersion(): string {
  return load().version;
}

export function skeleton(value: string): string {
  const { map } = load();
  let mapped = '';
  for (const char of value.normalize('NFD')) mapped += map.get(char) ?? char;
  return mapped.normalize('NFD').toLowerCase();
}
