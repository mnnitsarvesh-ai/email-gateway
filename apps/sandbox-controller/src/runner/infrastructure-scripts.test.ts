import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

// The zero-dependency scripts mounted into / baked into the sandbox containers (step 4.6 X5, X6)
// carry their own node:test suites; they run here so `pnpm test` covers them:
//   infrastructure/sandbox/sinkhole/sinkhole.test.mjs  (DNS/HTTP/TLS-SNI parsing, bounds, admin)
//   infrastructure/sandbox/runner/bootstrap.test.mjs   (input parsing, framing, dropped files)
const ROOT = resolve(__dirname, '../../../..');

describe('infrastructure/sandbox scripts (node:test)', () => {
  it.each([
    'infrastructure/sandbox/sinkhole/sinkhole.test.mjs',
    'infrastructure/sandbox/runner/bootstrap.test.mjs',
  ])(
    '%s passes',
    (file) => {
      const result = spawnSync(
        process.execPath,
        ['--test', '--test-reporter=tap', resolve(ROOT, file)],
        {
          cwd: ROOT,
          encoding: 'utf8',
          timeout: 60_000,
        },
      );
      expect(result.stdout).toMatch(/^# fail 0$/m);
      expect(result.status, result.stdout.slice(-2_000)).toBe(0);
    },
    90_000,
  );
});
