import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

function runtimeFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      if (name === 'testing') continue;
      out.push(...runtimeFiles(path));
    } else if (name.endsWith('.ts') && !name.endsWith('.test.ts')) {
      out.push(path);
    }
  }
  return out;
}

describe('runtime code never imports the test kit', () => {
  it('no runtime module imports ./testing', () => {
    const offenders = runtimeFiles(__dirname).filter((file) =>
      /from '(\.{1,2}\/)+testing|security-incidents\/testing'/.test(readFileSync(file, 'utf8')),
    );
    expect(offenders).toEqual([]);
  });
});
