import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * The DLP extractor child (step 4.5 D4) has the inspector child's isolation guarantees and in
 * addition never reaches `@email-gateway/bec`, the url-security package, parse5 or an AI SDK:
 * its module graph (our own modules and `@email-gateway/dlp/extract`, followed through relative
 * imports into the package sources) imports no `child_process`, `worker_threads` or network
 * module, uses no fs write API and reads no environment beyond the selftest flag.
 */
const ENTRY = resolve(__dirname, 'child.ts');
const DLP_SRC = resolve(__dirname, '../../../../../../../packages/dlp/src');
const ALLOWED_PACKAGES = new Set([
  '@email-gateway/dlp/extract',
  '@email-gateway/security-contracts',
  'pdfjs-dist',
  'tar-stream',
  'yauzl',
  'zod',
  'node:crypto',
  'node:fs',
  'node:module',
  'node:path',
  'node:stream',
  'node:url',
  'node:zlib',
]);
const FORBIDDEN = [
  'child_process',
  'node:child_process',
  'worker_threads',
  'node:worker_threads',
  'node:net',
  'node:http',
  'node:https',
  'net',
  'http',
  'https',
  '@email-gateway/bec',
  '@email-gateway/url-security',
  '@anthropic-ai/sdk',
  'parse5',
  '@litko/yara-x',
];
const FS_WRITE =
  /\b(writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|mkdir|mkdirSync|mkdtemp|mkdtempSync|rm|rmSync|unlink|unlinkSync|rename|renameSync|copyFile|copyFileSync|cp|cpSync|symlink|truncate|open|openSync|chmod)\b/;

function importsOf(source: string): string[] {
  const specifiers = new Set<string>();
  for (const match of source.matchAll(
    /(?:import|export)\s+(?:type\s+)?(?:[^'"]*?\sfrom\s+)?['"]([^'"]+)['"]/g,
  )) {
    if (!/^\s*import\s+type\b/.test(match[0]) && !/^\s*export\s+type\b/.test(match[0]))
      specifiers.add(match[1]!);
  }
  for (const match of source.matchAll(/require(?:\.resolve)?\(\s*['"]([^'"]+)['"]\s*\)/g))
    specifiers.add(match[1]!);
  for (const match of source.matchAll(/import\(\s*['"]([^'"]+)['"]\s*\)/g))
    specifiers.add(match[1]!);
  return [...specifiers];
}

const resolveTs = (base: string): string =>
  existsSync(`${base}.ts`) ? `${base}.ts` : resolve(base, 'index.ts');

function graph(entry: string): { files: Map<string, string>; packages: Set<string> } {
  const files = new Map<string, string>();
  const packages = new Set<string>();
  const visit = (file: string) => {
    if (files.has(file)) return;
    const source = readFileSync(file, 'utf8');
    files.set(file, source);
    for (const specifier of importsOf(source)) {
      if (specifier.startsWith('.')) visit(resolveTs(resolve(dirname(file), specifier)));
      else if (specifier === '@email-gateway/dlp/extract') {
        packages.add(specifier);
        visit(resolve(DLP_SRC, 'extract/index.ts'));
      } else packages.add(specifier.replace(/^(@[^/]+\/[^/]+|[^@][^/]*).*$/, '$1'));
    }
  };
  visit(entry);
  return { files, packages };
}

describe('DLP extractor child module graph (step 4.5 D4)', () => {
  const { files, packages } = graph(ENTRY);

  it('reaches only the allowed packages: no child_process, no bec, no AI SDK, no network', () => {
    expect([...files.keys()].some((f) => f.includes('/packages/dlp/src/extract/'))).toBe(true);
    expect([...files.keys()].some((f) => f.endsWith('inspector/inspect.ts'))).toBe(true);
    for (const pkg of packages) expect(ALLOWED_PACKAGES, pkg).toContain(pkg);
    for (const forbidden of FORBIDDEN) expect(packages.has(forbidden), forbidden).toBe(false);
    expect(packages.has('@email-gateway/dlp')).toBe(false);
  });

  it('uses no file write API and reads no environment beyond the selftest flag', () => {
    for (const [file, source] of files) {
      const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
      const fsImports = [
        ...code.matchAll(/import\s*\{([^}]*)\}\s*from\s*['"]node:fs(?:\/promises)?['"]/g),
      ].flatMap((m) => m[1]!.split(',').map((s) => s.trim()));
      for (const name of fsImports) expect(FS_WRITE.test(name), `${file}: ${name}`).toBe(false);
      const envReads = [...code.matchAll(/process\.env\.([A-Z_]+)/g)].map((m) => m[1]);
      for (const name of envReads)
        expect(['EG_INSPECTOR_SELFTEST'], `${file}: ${String(name)}`).toContain(name);
    }
  });
});
