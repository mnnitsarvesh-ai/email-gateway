// @vitest-environment node
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { DEV_MOCK_MARKER, scanForMockLayer } from '../../../scripts/assert-no-mock-layer.mjs';
import { DEV_MOCK_MARKER as MODULE_MARKER } from '@/server/dev-mocks/types';

const dirs: string[] = [];
function fakeNext(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'eg-next-'));
  dirs.push(root);
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(join(root, path, '..'), { recursive: true });
    writeFileSync(join(root, path), content);
  }
  return root;
}

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe('assert-no-mock-layer (design P9)', () => {
  it('uses the same marker as the fixture modules', () => {
    expect(DEV_MOCK_MARKER).toBe(MODULE_MARKER);
  });

  it('passes a clean build output', async () => {
    const dir = fakeNext({
      'server/app/page.js': 'console.log(1)',
      'static/chunks/a.js': 'x',
      'standalone/server.js': 'y',
    });
    expect(await scanForMockLayer(dir)).toEqual([]);
  });

  it('finds the marker in server, static and standalone output', async () => {
    const dir = fakeNext({
      'server/chunks/1.js': `const m="${DEV_MOCK_MARKER}"`,
      'static/chunks/2.js': `x${DEV_MOCK_MARKER}`,
      'standalone/apps/admin-portal/.next/server/3.js': `"${DEV_MOCK_MARKER}"`,
    });
    const hits = await scanForMockLayer(dir);
    expect(hits.map((h) => h.file).sort()).toEqual([
      'server/chunks/1.js',
      'standalone/apps/admin-portal/.next/server/3.js',
      'static/chunks/2.js',
    ]);
  });

  it('finds the module path in file contents and names, and ignores .next/cache', async () => {
    const dir = fakeNext({
      'server/app/route.js.nft.json': '{"files":["../src/server/dev-mocks/index.ts"]}',
      'standalone/src/server/dev-mocks/index.ts': 'export {}',
      'cache/webpack/x.pack': `dev-mocks ${DEV_MOCK_MARKER}`,
    });
    const hits = await scanForMockLayer(dir);
    expect(hits.some((h) => h.file === 'server/app/route.js.nft.json')).toBe(true);
    expect(hits.some((h) => h.file.startsWith('standalone/src/server/dev-mocks'))).toBe(true);
    expect(hits.some((h) => h.file.startsWith('cache'))).toBe(false);
  });
});
