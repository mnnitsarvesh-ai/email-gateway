import { execFile } from 'node:child_process';
import path from 'node:path';
import { promisify } from 'node:util';
import { ESLint, type Linter } from 'eslint';
import { createConfig } from '@esg/eslint-config';
import { beforeAll, describe, expect, it } from 'vitest';

const run = promisify(execFile);
const fixturesRoot = path.join(import.meta.dirname, '..', 'fixtures');
const tscBin = path.join(import.meta.dirname, '..', 'node_modules', 'typescript', 'bin', 'tsc');

function makeEslint(config: Linter.Config[]): ESLint {
  return new ESLint({ cwd: fixturesRoot, overrideConfigFile: true, overrideConfig: config });
}

async function lint(eslint: ESLint, file: string): Promise<Linter.LintMessage[]> {
  const [result] = await eslint.lintFiles([file]);
  return result?.messages ?? [];
}

function only(messages: Linter.LintMessage[], ruleId: string): Linter.LintMessage[] {
  return messages.filter((m) => m.ruleId === ruleId);
}

describe('lint fixtures', () => {
  let eslint: ESLint;
  beforeAll(() => {
    eslint = makeEslint(createConfig({ root: fixturesRoot }));
  });

  describe('AC-5 strictness rules', () => {
    it('AC-5: explicit any is an error', async () => {
      const m = only(await lint(eslint, 'packages/x/src/explicit-any.ts'), '@typescript-eslint/no-explicit-any');
      expect(m).toHaveLength(1);
      expect(m[0]?.severity).toBe(2);
    });
    it('AC-5: object-literal type assertion is an error', async () => {
      const m = only(
        await lint(eslint, 'packages/x/src/assertion.ts'),
        '@typescript-eslint/consistent-type-assertions',
      );
      expect(m).toHaveLength(1);
      expect(m[0]?.severity).toBe(2);
    });
  });

  describe('AC-6 cross-service imports', () => {
    it.each(['services/a/src/by-name.ts', 'services/a/src/by-relative.ts'])('AC-6: %s fails the boundary rule', async (file) => {
      const m = only(await lint(eslint, file), 'no-restricted-imports');
      expect(m).toHaveLength(1);
      expect(m[0]?.message).toContain('[boundary]');
      expect(m[0]?.message).not.toContain('[control-plane]');
      expect(m[0]?.severity).toBe(2);
    });
    // KNOWN GAP (QA issue #1): a sibling-service relative import (`../../b/src/x.js`) contains no
    // services|packages|... segment, so the relative-escape regex misses it. `it.fails` documents the
    // gap and turns red the day it is fixed, prompting removal of `.fails`.
    it.fails('AC-6 (gap): sibling relative import ../../b/src/x.js should fail the boundary rule', async () => {
      const m = only(await lint(eslint, 'services/a/src/by-sibling-relative.ts'), 'no-restricted-imports');
      expect(m).toHaveLength(1);
    });
  });

  describe('AC-7 packages and e2e', () => {
    it.each([
      'packages/x/src/imports-service.ts',
      'packages/x/src/relative-escape.ts',
      'test/e2e/src/imports-service.ts',
    ])('AC-7: %s fails the boundary rule', async (file) => {
      const m = only(await lint(eslint, file), 'no-restricted-imports');
      expect(m).toHaveLength(1);
      expect(m[0]?.message).toContain('[boundary]');
      expect(m[0]?.severity).toBe(2);
    });
  });

  describe('AC-8 control plane', () => {
    const files = ['db-control-plane.ts', 'config-control-plane.ts'];
    for (const svc of ['ingest-like', 'portal']) {
      it.each(files)(`AC-8: ${svc}/%s is blocked`, async (f) => {
        const m = only(await lint(eslint, `services/${svc}/src/${f}`), 'no-restricted-imports');
        expect(m).toHaveLength(1);
        expect(m[0]?.message).toContain('[control-plane]');
        expect(m[0]?.severity).toBe(2);
      });
    }
    it.each(files)('AC-8: api/%s passes', async (f) => {
      const m = only(await lint(eslint, `services/api/src/${f}`), 'no-restricted-imports');
      expect(m).toHaveLength(0);
      // the module does not exist yet (tasks 006/007), so unrelated unresolved-type errors are expected
    });
  });

  describe('AC-10 negative control', () => {
    it('AC-10: negative control: without the boundary rule the cross-service fixture is not flagged', async () => {
      const stripped = createConfig({ root: fixturesRoot }).map((c) => {
        if (!c.rules) return c;
        const rules = Object.fromEntries(Object.entries(c.rules).filter(([name]) => name !== 'no-restricted-imports'));
        return { ...c, rules };
      });
      const m = only(await lint(makeEslint(stripped), 'services/a/src/by-name.ts'), 'no-restricted-imports');
      expect(m).toHaveLength(0);
    });
  });
});

describe('AC-4 TypeScript strictness fixtures', () => {
  async function tsc(dir: string): Promise<{ code: number; out: string }> {
    try {
      const r = await run(process.execPath, [tscBin, '-p', path.join(fixturesRoot, 'ts-strict', dir), '--noEmit']);
      return { code: 0, out: r.stdout };
    } catch (e) {
      const err = e as { code?: number; stdout?: string };
      return { code: err.code ?? 1, out: err.stdout ?? '' };
    }
  }

  it('AC-4: implicit any fails with TS7006', async () => {
    const r = await tsc('implicit-any');
    expect(r.code).not.toBe(0);
    expect(r.out).toContain('TS7006');
  });
  it('AC-4: unchecked index access fails with TS2532 or TS18048', async () => {
    const r = await tsc('unchecked-index');
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/TS(2532|18048)/);
  });
});
