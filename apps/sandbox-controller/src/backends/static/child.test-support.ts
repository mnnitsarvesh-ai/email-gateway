import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';
import { transformFileSync } from '@swc/core';

/**
 * Test support: compiles the analyzer child's module graph (this directory, without tests and
 * fixtures) to CommonJS in a temporary directory with swc, so unit tests spawn the REAL child
 * under Node's permission model from source runs (production spawns `dist/…/analyzer-child.js`).
 * The graph imports only node built-ins and relative files (asserted by analyzers.test.ts), so
 * the compiled directory is self-contained.
 */

let compiled: string | undefined;

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return sources(path);
    if (
      !entry.name.endsWith('.ts') ||
      entry.name.includes('.test') ||
      entry.name === 'static.backend.ts'
    )
      return [];
    if (entry.name === 'child-runner.ts' || entry.name === 'sampler.ts') return [];
    return [path];
  });
}

/** The compiled `analyzer-child.js` (compiled once per test process). */
export function compiledAnalyzerChild(): string {
  if (compiled) return compiled;
  // One directory per source content (reused across runs, never accumulating).
  const files = sources(__dirname).sort();
  const hash = createHash('sha256');
  for (const file of files) hash.update(file).update(readFileSync(file));
  const out = join(tmpdir(), `eg-sbx-child-${hash.digest('hex').slice(0, 16)}`);
  for (const file of files) {
    const { code } = transformFileSync(file, {
      jsc: { parser: { syntax: 'typescript' }, target: 'es2022' },
      module: { type: 'commonjs' },
      sourceMaps: false,
    });
    const target = join(out, relative(__dirname, file)).replace(/\.ts$/, '.js');
    if (existsSync(target)) continue;
    mkdirSync(dirname(target), { recursive: true });
    // Atomic: concurrent test workers never see a half-written module.
    const temporary = `${target}.${String(process.pid)}.${String(Math.random()).slice(2)}`;
    writeFileSync(temporary, code);
    renameSync(temporary, target);
  }
  compiled = join(out, 'analyzer-child.js');
  return compiled;
}
