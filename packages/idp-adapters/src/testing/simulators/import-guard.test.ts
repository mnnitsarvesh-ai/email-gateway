import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

// D12: the simulators run standalone from dist/testing/simulators in node:22-alpine, so their
// sources import only node:* modules and each other.
describe('simulator import guard', () => {
  it('imports only node:* modules and sibling simulator files', () => {
    const dir = __dirname;
    const files = readdirSync(dir).filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts'));
    expect(files.length).toBeGreaterThanOrEqual(7);
    for (const file of files) {
      const source = readFileSync(join(dir, file), 'utf8');
      const specifiers = [
        ...source.matchAll(/(?:import|export)\s[^'"]*?from\s+['"]([^'"]+)['"]/g),
        ...source.matchAll(/(?:require|import)\(\s*['"]([^'"]+)['"]\s*\)/g),
        ...source.matchAll(/^import\s+['"]([^'"]+)['"]/gm),
      ].map((match) => match[1] as string);
      for (const specifier of specifiers) {
        expect(
          specifier.startsWith('node:') || /^\.\/[a-z0-9-]+$/.test(specifier),
          `${file} imports ${specifier}`,
        ).toBe(true);
      }
    }
  });
});
