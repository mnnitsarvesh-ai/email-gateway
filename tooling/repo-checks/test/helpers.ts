import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

export const repoRoot = path.resolve(import.meta.dirname, '..', '..', '..');

export function read(rel: string): string {
  return fs.readFileSync(path.join(repoRoot, rel), 'utf8');
}

export function readJson(rel: string): unknown {
  return JSON.parse(read(rel));
}

const SKIP_DIRS = new Set(['node_modules', 'dist', '.turbo', '.git', 'coverage']);

/** Recursively list files under a repo-relative dir, skipping dependency/build output. */
export function walk(rel: string): string[] {
  const abs = path.join(repoRoot, rel);
  if (!fs.existsSync(abs)) return [];
  const out: string[] = [];
  for (const entry of fs.readdirSync(abs, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const child = path.posix.join(rel, entry.name);
    if (entry.isDirectory()) out.push(...walk(child));
    else out.push(child);
  }
  return out;
}

export function which(bin: string): boolean {
  return spawnSync('which', [bin], { encoding: 'utf8' }).status === 0;
}

export function git(...args: string[]): { status: number | null; stdout: string } {
  const r = spawnSync('git', args, { cwd: repoRoot, encoding: 'utf8' });
  return { status: r.status, stdout: r.stdout };
}

/** Environment without DATABASE_URL or any dbmate settings. */
export function cleanDbEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (k === 'DATABASE_URL' || k.startsWith('DBMATE_')) continue;
    env[k] = v;
  }
  return env;
}

/**
 * Forbidden-command patterns are assembled from fragments so that this file
 * does not match its own scan (AC-13, AC-19).
 */
export const FORBIDDEN: { label: string; re: RegExp }[] = [
  { label: 'terraform apply/destroy', re: new RegExp(['\\bterra', 'form\\b[^\\n;&|]*\\b(apply|destroy)\\b'].join('')) },
  { label: 'kubectl', re: new RegExp(['\\bkube', 'ctl\\b'].join('')) },
  { label: 'git push', re: new RegExp(['\\bgit\\b[^\\n;&|]*\\bpu', 'sh\\b'].join('')) },
  { label: 'aws cli', re: new RegExp(['(^|[\\s;&|(`"\'])a', 'ws(\\s+-\\S+)*\\s+[a-z0-9-]+'].join('')) },
];

/** Files at the repo root that are scanned for forbidden commands (never .env*, which agents must not read). */
export function rootFiles(): string[] {
  return fs
    .readdirSync(repoRoot, { withFileTypes: true })
    .filter((e) => e.isFile() && !e.name.startsWith('.env') && e.name !== 'CLAUDE.md' && e.name !== 'pnpm-lock.yaml')
    .map((e) => e.name);
}
