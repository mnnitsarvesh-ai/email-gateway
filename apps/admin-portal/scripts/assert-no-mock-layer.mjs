#!/usr/bin/env node
// Fails the build when the dev fixture layer (design P9) reached the production output.
//
// Runs after `next build` (package `build` script). Scans every file under .next/ (server,
// static, standalone; .next/cache is skipped: it holds incremental-compiler caches that a
// previous `next dev` run may have filled and is never shipped) for the marker exported by
// every fixture module and for the module path `dev-mocks`.
import { readdir, readFile, stat } from 'node:fs/promises';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const DEV_MOCK_MARKER = 'eg-dev-mock-layer-7f3a9c';
export const NEEDLES = [DEV_MOCK_MARKER, 'dev-mocks'];
const SKIP_DIRS = new Set(['cache']);

async function* walk(dir, root) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (dir === root && SKIP_DIRS.has(entry.name)) continue;
      yield* walk(full, root);
    } else if (entry.isFile() || entry.isSymbolicLink()) {
      yield full;
    }
  }
}

/** Returns `{ file, needle }` for every hit (file names count too). */
export async function scanForMockLayer(nextDir) {
  const findings = [];
  for await (const file of walk(nextDir, nextDir)) {
    const rel = relative(nextDir, file);
    for (const needle of NEEDLES) {
      if (rel.includes(needle)) findings.push({ file: rel, needle });
    }
    let info;
    try {
      info = await stat(file);
    } catch {
      continue;
    }
    if (!info.isFile()) continue;
    const content = await readFile(file);
    for (const needle of NEEDLES) {
      if (content.includes(needle)) findings.push({ file: rel, needle });
    }
  }
  return findings;
}

async function main() {
  const appDir = join(dirname(fileURLToPath(import.meta.url)), '..');
  const nextDir = join(appDir, '.next');
  try {
    await stat(nextDir);
  } catch {
    console.error('assert-no-mock-layer: .next does not exist; run next build first');
    process.exit(1);
  }
  const findings = await scanForMockLayer(nextDir);
  if (findings.length > 0) {
    for (const f of findings.slice(0, 20)) {
      console.error(`assert-no-mock-layer: "${f.needle}" found in .next/${f.file}`);
    }
    console.error(
      `assert-no-mock-layer: the dev fixture layer is in the build output (${findings.length} hit(s)); it must never ship`,
    );
    process.exit(1);
  }
  console.log('assert-no-mock-layer: no dev fixture code in .next (server, static, standalone)');
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
