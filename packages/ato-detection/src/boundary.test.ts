import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import * as runtime from './index';

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

describe('runtime code never imports the test kit (§4.4)', () => {
  it('no runtime module imports ./testing or a /testing entry point', () => {
    const offenders = runtimeFiles(__dirname).filter((file) =>
      /from '((\.{1,2}\/)+testing|@email-gateway\/[a-z-]+\/testing)/.test(
        readFileSync(file, 'utf8'),
      ),
    );
    expect(offenders).toEqual([]);
  });

  it('the runtime entry point exports none of the test kit', () => {
    for (const name of [
      'FakeIdentityProviderAdapter',
      'describeProviderAdapterContract',
      'writeMmdb',
      'SYNTHETIC_GEOIP',
      'InMemoryRedis',
    ]) {
      expect(Object.keys(runtime), name).not.toContain(name);
    }
  });

  it('runtime modules never import vitest', () => {
    const offenders = runtimeFiles(__dirname).filter((file) =>
      /from 'vitest'/.test(readFileSync(file, 'utf8')),
    );
    expect(offenders).toEqual([]);
  });
});

describe('the fake adapter entry point (step 8.4 WP4)', () => {
  it('`@email-gateway/ato-detection/fake-provider` loads without Vitest', () => {
    // The ato-worker registers the fake adapter at runtime in local/ci only (D15,
    // ATO_PROVIDER_FAKE_ENABLED); the /testing entry imports Vitest (contract kit), so the fake
    // adapter has its own vitest-free entry point.
    const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8')) as {
      exports: Record<string, { default: string }>;
    };
    expect(pkg.exports['./fake-provider']?.default).toBe('./dist/testing/fake-provider.js');
    const source = readFileSync(join(__dirname, 'testing', 'fake-provider.ts'), 'utf8');
    const imports = [...source.matchAll(/from '([^']+)'/g)].map((m) => m[1]);
    expect(imports.every((i) => i === 'node:crypto' || i === '../provider')).toBe(true);
  });
});
