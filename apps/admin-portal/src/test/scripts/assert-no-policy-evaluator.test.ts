// @vitest-environment node
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, sep } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  EVALUATOR_PACKAGES,
  NEEDLES,
  scanForPolicyEvaluator,
} from '../../../scripts/assert-no-policy-evaluator.mjs';

/**
 * The no-evaluator guards of step 7.3 (design B2, ADR-0063 decision 2): the portal never imports
 * the policy evaluator or its engines, never constructs a RegExp in the policy feature, and the
 * build-output scanner finds evaluator code wherever it would ship.
 */

const PORTAL = join(__dirname, '../../..');
const SRC = join(PORTAL, 'src');
const POLICY_DSL_SRC = join(PORTAL, '../../packages/policy-dsl/src');

function files(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...files(full));
    else if (entry.isFile()) out.push(full);
  }
  return out;
}

/** Module specifiers of import/export-from/dynamic import/require statements. */
function moduleSpecifiers(source: string): string[] {
  const out: string[] = [];
  const patterns = [
    /\bfrom\s*['"]([^'"]+)['"]/g,
    /\bimport\s*['"]([^'"]+)['"]/g,
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) out.push(match[1]!);
  }
  return out;
}

const forbidden = (specifier: string): boolean =>
  EVALUATOR_PACKAGES.some((pkg) => specifier === pkg || specifier.startsWith(`${pkg}/`)) ||
  /(^|\/)packages\/(policy-dsl|risk-scoring|dlp|bec)(\/|$)/.test(specifier);

/** Portal sources that ship: tests, test support, generated clients and dev fixtures excluded. */
function shippedSources(): string[] {
  return files(SRC).filter((file) => {
    const rel = relative(SRC, file).split(sep).join('/');
    if (!/\.(ts|tsx|mts|cts|js|jsx|mjs)$/.test(rel)) return false;
    if (/\.gen\.ts$/.test(rel) || /\.test\.tsx?$/.test(rel) || rel.endsWith('/test-data.ts'))
      return false;
    if (rel.startsWith('test/') || rel.startsWith('server/dev-mocks/')) return false;
    return true;
  });
}

describe('no policy evaluator in the portal sources (design B2 guard 2)', () => {
  it('detects imports, re-exports, dynamic imports and requires (the scan is meaningful)', () => {
    const sample = [
      "import { evaluatePolicyPerRecipient } from '@email-gateway/policy-dsl';",
      "import type { RiskLevel } from '@email-gateway/risk-scoring/levels';",
      "export * from '@email-gateway/dlp';",
      "const bec = await import('@email-gateway/bec');",
      "const { RE2JS } = require('re2js');",
      "import '../../../../packages/policy-dsl/src/index';",
      "import { x } from '@email-gateway/policy-dsl-presentation';",
      "import { y } from '@email-gateway/shared-types';",
    ].join('\n');
    expect(moduleSpecifiers(sample).filter(forbidden)).toEqual([
      '@email-gateway/policy-dsl',
      '@email-gateway/risk-scoring/levels',
      '@email-gateway/dlp',
      '../../../../packages/policy-dsl/src/index',
      '@email-gateway/bec',
      're2js',
    ]);
  });

  it('no shipped portal module imports an evaluator package', () => {
    const sources = shippedSources();
    expect(sources.length).toBeGreaterThan(100);
    expect(sources.some((f) => f.includes(`${sep}features${sep}policies${sep}builder${sep}`))).toBe(
      true,
    );
    const hits = sources.flatMap((file) =>
      moduleSpecifiers(readFileSync(file, 'utf8'))
        .filter(forbidden)
        .map((specifier) => `${relative(SRC, file)}: ${specifier}`),
    );
    expect(hits).toEqual([]);
  });

  it('no shipped portal module contains an evaluator-only needle (the build scan would refuse it)', () => {
    // Test fixtures (`test-support/`) hold api responses verbatim and are never imported by a page.
    const hits = shippedSources()
      .filter((file) => !file.includes(`${sep}test-support${sep}`))
      .flatMap((file) => {
        const text = readFileSync(file, 'utf8');
        return NEEDLES.filter((needle) => text.includes(needle)).map(
          (needle) => `${relative(SRC, file)}: ${needle}`,
        );
      });
    expect(hits).toEqual([]);
  });

  it('the policy feature never constructs a RegExp (tenant patterns are compiled by the server only)', () => {
    const needle = ['new', 'RegExp('].join(' ');
    const policyFiles = shippedSources().filter((file) =>
      relative(SRC, file).split(sep).join('/').startsWith('features/policies/'),
    );
    expect(policyFiles.length).toBeGreaterThan(10);
    expect(policyFiles.filter((file) => readFileSync(file, 'utf8').includes(needle))).toEqual([]);
  });

  it('the portal does not depend on an evaluator package', () => {
    const manifest = JSON.parse(readFileSync(join(PORTAL, 'package.json'), 'utf8')) as Record<
      string,
      Record<string, string> | undefined
    >;
    const declared = [
      'dependencies',
      'devDependencies',
      'peerDependencies',
      'optionalDependencies',
    ].flatMap((key) => Object.keys(manifest[key] ?? {}));
    expect(declared.length).toBeGreaterThan(10);
    expect(declared.filter((name) => EVALUATOR_PACKAGES.includes(name))).toEqual([]);
  });

  it('the build script runs the output scanner after the mock-layer scanner', () => {
    const manifest = JSON.parse(readFileSync(join(PORTAL, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>;
    };
    expect(manifest.scripts.build).toMatch(
      /next build && node scripts\/assert-no-mock-layer\.mjs && node scripts\/assert-no-policy-evaluator\.mjs$/,
    );
  });
});

const dirs: string[] = [];
function fakeNext(content: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'eg-next-'));
  dirs.push(root);
  for (const [path, text] of Object.entries(content)) {
    mkdirSync(join(root, path, '..'), { recursive: true });
    writeFileSync(join(root, path), text);
  }
  return root;
}

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe('assert-no-policy-evaluator (design B2 guard 3)', () => {
  it('every needle is present in the evaluator library (packages/policy-dsl/src)', () => {
    const sources = files(POLICY_DSL_SRC)
      .filter(
        (file) => file.endsWith('.ts') && !file.endsWith('.test.ts') && statSync(file).isFile(),
      )
      .map((file) => readFileSync(file, 'utf8'))
      .join('\n');
    expect(sources.length).toBeGreaterThan(10_000);
    for (const needle of NEEDLES) expect(sources, needle).toContain(needle);
  });

  it('passes a clean build output', async () => {
    const dir = fakeNext({
      'server/app/policies/page.js': 'export default function Page(){return "Policy builder"}',
      'static/chunks/app.js': 'console.log("policy-dsl/1 documents are built here")',
      'standalone/apps/admin-portal/package.json': JSON.stringify({ dependencies: { next: '15' } }),
    });
    expect(await scanForPolicyEvaluator(dir)).toEqual([]);
  });

  it('finds every needle planted in server, static and standalone output', async () => {
    for (const needle of NEEDLES) {
      const dir = fakeNext({
        'server/chunks/1.js': `const a=${JSON.stringify(needle)}`,
        'static/chunks/2.js': `x${needle}y`,
        'standalone/apps/admin-portal/.next/server/3.js': `"${needle}"`,
      });
      const hits = await scanForPolicyEvaluator(dir);
      expect(
        hits
          .filter((h) => h.needle === needle)
          .map((h) => h.file)
          .sort(),
        needle,
      ).toEqual([
        'server/chunks/1.js',
        'standalone/apps/admin-portal/.next/server/3.js',
        'static/chunks/2.js',
      ]);
    }
  });

  it('finds traced packages by file name and a portal dependency; skips .next/cache and the root manifest copy', async () => {
    const dir = fakeNext({
      'standalone/node_modules/@email-gateway/policy-dsl/dist/index.js': 'module.exports={}',
      'standalone/apps/admin-portal/package.json': JSON.stringify({
        dependencies: { re2js: '1.2.0' },
      }),
      'standalone/package.json': JSON.stringify({
        scripts: { test: 'pnpm --filter @email-gateway/policy-dsl test' },
      }),
      'cache/webpack/x.pack': 'compileSnapshot policy.floor.hard_block',
    });
    const hits = await scanForPolicyEvaluator(dir);
    expect(hits).toContainEqual({
      file: 'standalone/node_modules/@email-gateway/policy-dsl/dist/index.js',
      needle: '@email-gateway/policy-dsl',
    });
    expect(hits).toContainEqual({
      file: 'standalone/apps/admin-portal/package.json',
      needle: 're2js',
    });
    expect(hits.some((h) => h.file.startsWith('cache'))).toBe(false);
    expect(hits.some((h) => h.file === 'standalone/package.json')).toBe(false);
  });
});
