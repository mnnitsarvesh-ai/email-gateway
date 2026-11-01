// @ts-check
// Guarded dbmate wrapper: `pnpm dbmate <command>`.
// - DATABASE_URL must come from the environment (or gitignored .env.local); there is no default.
// - Refuses unless the host is localhost, 127.0.0.1, ::1 or a compose service name (a single-label
//   host such as `mysql`), so a stray real URL cannot migrate or drop a real database.
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const FORBIDDEN_FLAGS = new Set(['--url', '-u', '--env', '-e', '--env-file']);

/** @param {string} message */
function fail(message) {
  console.error(`dbmate guard: ${message}`);
  process.exit(1);
}

const args = process.argv.slice(2);
const checkOnly = args[0] === '--check-only';
const passthrough = checkOnly ? args.slice(1) : args;

for (const a of passthrough) {
  const flag = a.split('=')[0] ?? a;
  if (FORBIDDEN_FLAGS.has(flag)) fail(`${flag} is not allowed; set DATABASE_URL in the environment instead.`);
}

const raw = process.env['DATABASE_URL'];
if (!raw) fail('DATABASE_URL is not set. Export it (or put it in gitignored .env.local); there is no default host.');

/** @type {URL} */
let url;
try {
  url = new URL(raw);
} catch {
  fail('DATABASE_URL is not a valid URL.');
  throw new Error('unreachable');
}

const host = url.hostname.replace(/^\[|\]$/g, '');
const allowed = host === 'localhost' || host === '127.0.0.1' || host === '::1' || /^[a-z][a-z0-9_-]*$/i.test(host);
if (!allowed) {
  fail(`refusing host "${host}" (allowed: localhost, 127.0.0.1, ::1, or a compose service name without dots).`);
}

if (checkOnly) {
  console.log('dbmate guard: ok');
  process.exit(0);
}

const bin = path.join(import.meta.dirname, '..', 'node_modules', '.bin', 'dbmate');
const r = spawnSync(bin, ['--migrations-dir', 'db/migrations', ...passthrough], { stdio: 'inherit' });
process.exit(r.status ?? 1);
