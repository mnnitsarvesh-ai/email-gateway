import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * `@email-gateway/dlp/extract` runs inside the DLP extractor child (step 4.5 D4): its module
 * graph must never reach `@email-gateway/bec`, `@email-gateway/url-security`, an AI SDK or
 * `child_process`. Walks the relative imports from `extract/index.ts` and checks every bare
 * import it meets.
 */

const SRC = resolve(__dirname, '..');
const FORBIDDEN = [
  /^@email-gateway\/bec/,
  /^@email-gateway\/url-security/,
  /^@anthropic-ai\//,
  /^openai$/,
  /^(?:node:)?child_process$/,
  /^parse5/,
];
const ALLOWED_BARE = [
  /^node:(?:path|url|module|crypto|fs|zlib)$/,
  /^@email-gateway\/security-contracts$/,
  /^zod$/,
];

const importsOf = (file: string): string[] => {
  const source = readFileSync(file, 'utf8');
  const specifiers: string[] = [];
  for (const match of source.matchAll(
    /(?:import|export)\s[^'"]*?from\s+'([^']+)'|require\('([^']+)'\)|import\('([^']+)'\)/g,
  )) {
    specifiers.push((match[1] ?? match[2] ?? match[3])!);
  }
  return specifiers;
};

const resolveRelative = (from: string, specifier: string): string => {
  const base = resolve(dirname(from), specifier);
  for (const candidate of [`${base}.ts`, join(base, 'index.ts')]) {
    try {
      readFileSync(candidate);
      return candidate;
    } catch {
      // try the next candidate
    }
  }
  throw new Error(`cannot resolve ${specifier} from ${from}`);
};

describe('extractor entry point import graph', () => {
  it('reaches no bec, url-security, AI SDK or child_process module', () => {
    const seen = new Set<string>();
    const bare = new Set<string>();
    const queue = [join(SRC, 'extract', 'index.ts')];
    while (queue.length > 0) {
      const file = queue.pop()!;
      if (seen.has(file)) continue;
      seen.add(file);
      for (const specifier of importsOf(file)) {
        if (specifier.startsWith('.')) queue.push(resolveRelative(file, specifier));
        else bare.add(specifier);
      }
    }
    expect(seen.size).toBeGreaterThan(5);
    for (const specifier of bare) {
      expect(
        FORBIDDEN.some((f) => f.test(specifier)),
        specifier,
      ).toBe(false);
      expect(
        ALLOWED_BARE.some((a) => a.test(specifier)),
        `unexpected import ${specifier}`,
      ).toBe(true);
    }
    // The graph includes the data module (versions) but none of the detectors.
    expect([...seen].some((f) => f.includes(`${'detectors'}`))).toBe(false);
  });

  it('the root proxy files re-export dist/extract', () => {
    const root = resolve(SRC, '..');
    expect(readFileSync(join(root, 'extract.js'), 'utf8')).toContain("require('./dist/extract')");
    expect(readFileSync(join(root, 'extract.d.ts'), 'utf8')).toContain(
      "export * from './dist/extract'",
    );
  });
});
