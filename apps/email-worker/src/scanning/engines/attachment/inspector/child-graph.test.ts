import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * The inspector child never spawns a process and never writes a file (step 4.2 A4, §2.0
 * invariants 2 and 3): its module graph (our own modules, followed through relative imports)
 * imports neither `child_process` nor `worker_threads`, uses no fs write API, and reaches only
 * the third-party packages listed here. Compiled children additionally run under Node's
 * permission model (no child process, no worker, no fs write; pool.ts).
 *
 * Third-party note (recorded by WP2): the `@litko/yara-x` loader would `require('child_process')`
 * only when neither `/usr/bin/ldd` nor `process.report` identify the libc (never on glibc), and
 * under the permission model such a spawn is refused anyway.
 */
const ENTRY = resolve(__dirname, 'child.ts');
const ALLOWED_PACKAGES = new Set([
  '@email-gateway/security-contracts',
  '@litko/yara-x',
  'tar-stream',
  'yauzl',
  'node:crypto',
  'node:fs',
  'node:path',
  'node:stream',
  'node:zlib',
]);
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
  for (const match of source.matchAll(/require\(\s*['"]([^'"]+)['"]\s*\)/g))
    specifiers.add(match[1]!);
  for (const match of source.matchAll(/import\(\s*['"]([^'"]+)['"]\s*\)/g))
    specifiers.add(match[1]!);
  return [...specifiers];
}

function graph(entry: string): { files: Map<string, string>; packages: Set<string> } {
  const files = new Map<string, string>();
  const packages = new Set<string>();
  const visit = (file: string) => {
    if (files.has(file)) return;
    const source = readFileSync(file, 'utf8');
    files.set(file, source);
    for (const specifier of importsOf(source)) {
      if (specifier.startsWith('.')) visit(resolve(dirname(file), `${specifier}.ts`));
      else packages.add(specifier.replace(/^(@[^/]+\/[^/]+|[^@][^/]*).*$/, '$1'));
    }
  };
  visit(entry);
  return { files, packages };
}

describe('inspector child module graph (step 4.2 A4)', () => {
  const { files, packages } = graph(ENTRY);

  it('reaches only the allowed packages (no child_process, no worker_threads, no network)', () => {
    expect(files.size).toBeGreaterThanOrEqual(5);
    for (const pkg of packages) expect(ALLOWED_PACKAGES, pkg).toContain(pkg);
    for (const forbidden of [
      'child_process',
      'node:child_process',
      'worker_threads',
      'node:worker_threads',
      'node:net',
      'node:http',
      'node:https',
      'net',
      'http',
    ]) {
      expect(packages.has(forbidden)).toBe(false);
    }
  });

  it('uses no file write API and reads no environment beyond its own flags', () => {
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
