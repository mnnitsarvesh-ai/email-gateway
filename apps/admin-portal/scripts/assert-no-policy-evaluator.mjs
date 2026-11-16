#!/usr/bin/env node
// Fails the build when policy evaluation code reached the portal's production output (step 7.3
// design B2, ADR-0063 decision 2: the browser never evaluates policies; the api is authoritative).
//
// Runs after `next build` and assert-no-mock-layer (package `build` script). Scans every file under
// .next/ (server, static, standalone; .next/cache is skipped: incremental-compiler caches are never
// shipped) for needles that exist only in the evaluator library `packages/policy-dsl` (package
// names, the input version, evaluator entry points and reason codes the evaluator emits). File
// names count too (a traced `node_modules/@email-gateway/policy-dsl/...`). The unit test
// (src/test/scripts/assert-no-policy-evaluator.test.ts) proves every needle is present in
// packages/policy-dsl/src, so a needle can never silently stop meaning anything.
import { readdir, readFile, stat } from 'node:fs/promises';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

/** Packages the portal must never import (lint rule, source scan and this build scan). */
export const EVALUATOR_PACKAGES = [
  '@email-gateway/policy-dsl',
  '@email-gateway/risk-scoring',
  '@email-gateway/dlp',
  '@email-gateway/bec',
  're2js',
];

/** Strings that exist only in the evaluator library (each checked against its sources). */
export const NEEDLES = [
  '@email-gateway/policy-dsl',
  '@email-gateway/risk-scoring',
  're2js',
  'policy-input/1',
  'evaluatePolicyPerRecipient',
  'compileSnapshot',
  'buildPolicyInput',
  'policy.floor.hard_block',
  'policy.clamp.ai_only',
  'policy.override.applied',
];

const SKIP_DIRS = new Set(['cache']);
/**
 * Next copies the monorepo's root manifest to standalone/package.json; its scripts name every
 * workspace package (`--filter @email-gateway/...`). It is not portal code and not a dependency
 * list of the portal (that is standalone/apps/admin-portal/package.json, which is scanned).
 */
const SKIP_FILES = new Set([`standalone${sep}package.json`]);

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

/** Returns `{ file, needle }` for every hit (paths relative to `nextDir`, `/`-separated). */
export async function scanForPolicyEvaluator(nextDir) {
  const findings = [];
  for await (const file of walk(nextDir, nextDir)) {
    const rel = relative(nextDir, file);
    if (SKIP_FILES.has(rel)) continue;
    const shown = rel.split(sep).join('/');
    for (const needle of NEEDLES) {
      if (shown.includes(needle)) findings.push({ file: shown, needle });
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
      if (content.includes(needle)) findings.push({ file: shown, needle });
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
    console.error('assert-no-policy-evaluator: .next does not exist; run next build first');
    process.exit(1);
  }
  const findings = await scanForPolicyEvaluator(nextDir);
  if (findings.length > 0) {
    for (const f of findings.slice(0, 20)) {
      console.error(`assert-no-policy-evaluator: "${f.needle}" found in .next/${f.file}`);
    }
    console.error(
      `assert-no-policy-evaluator: policy evaluator code is in the build output (${findings.length} hit(s)); the portal must never evaluate policies (ADR-0063)`,
    );
    process.exit(1);
  }
  console.log(
    `assert-no-policy-evaluator: no policy evaluator code in .next (server, static, standalone; ${NEEDLES.length} needles)`,
  );
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
