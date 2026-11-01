// @ts-check
// Guarded dbmate wrapper: `pnpm dbmate <command>`.
// - DATABASE_URL must be exported in the calling shell (for example `set -a; . ./.env.local; set +a`).
//   This script never reads .env files, and there is no default host.
// - Only the mysql: scheme, only local hosts or known compose service names, only allowlisted
//   query parameters, only allowlisted subcommands and flags. `drop` and `create` additionally need
//   ESG_DBMATE_ALLOW_DROP=1, so a stray URL cannot migrate or drop a real database.
import { spawnSync } from 'node:child_process';
import path from 'node:path';

/** Compose service names for the local MySQL stack. Task 003 aligns this with deploy/local/compose.yaml. */
const COMPOSE_SERVICE_HOSTS = ['mysql', 'mysql-writer', 'mysql-replica'];
const LOCAL_HOSTS = ['localhost', '127.0.0.1', '::1'];
const ALLOWED_QUERY_PARAMS = new Set(['charset', 'collation', 'parseTime', 'loc', 'timeout', 'readTimeout', 'writeTimeout', 'multiStatements']);
const SUBCOMMANDS = new Set(['new', 'up', 'migrate', 'rollback', 'status', 'dump', 'wait']);
const DESTRUCTIVE_SUBCOMMANDS = new Set(['drop', 'create']);
const ALLOWED_FLAGS = [/^--no-dump-schema$/, /^--wait$/, /^--wait-timeout=\d+[smh]?$/];

/** @param {string} message @returns {never} */
function fail(message) {
  console.error(`dbmate guard: ${message}`);
  process.exit(1);
}

const argv = process.argv.slice(2);
const checkOnly = argv[0] === '--check-only';
const args = checkOnly ? argv.slice(1) : argv;

/** @type {string | undefined} */
let subcommand;
/** @type {string[]} */
const positionals = [];
for (const a of args) {
  if (a.startsWith('-')) {
    if (!ALLOWED_FLAGS.some((re) => re.test(a))) {
      fail(`flag "${a.split('=')[0] ?? a}" is not allowed (allowed: --no-dump-schema, --wait, --wait-timeout=<n>).`);
    }
  } else if (subcommand === undefined) {
    subcommand = a;
  } else {
    positionals.push(a);
  }
}

if (subcommand === undefined) fail(`a subcommand is required (${[...SUBCOMMANDS].join(', ')}).`);
if (DESTRUCTIVE_SUBCOMMANDS.has(subcommand)) {
  if (process.env['ESG_DBMATE_ALLOW_DROP'] !== '1') fail(`"${subcommand}" needs ESG_DBMATE_ALLOW_DROP=1.`);
} else if (!SUBCOMMANDS.has(subcommand)) {
  fail(`subcommand "${subcommand}" is not allowed (allowed: ${[...SUBCOMMANDS].join(', ')}).`);
}
if (subcommand === 'new') {
  if (positionals.length !== 1 || !/^[A-Za-z0-9_]+$/.test(positionals[0] ?? '')) fail('"new" takes exactly one name (letters, digits, underscore).');
} else if (positionals.length > 0) {
  fail(`unexpected argument "${positionals[0] ?? ''}".`);
}

const raw = process.env['DATABASE_URL'];
if (!raw) fail('DATABASE_URL is not set. Export it in your shell; there is no default host.');

/** @type {URL} */
let url;
try {
  url = new URL(raw);
} catch {
  fail('DATABASE_URL is not a valid URL.');
}

if (url.protocol !== 'mysql:') fail(`DATABASE_URL scheme must be mysql: (got ${url.protocol}).`);
for (const key of url.searchParams.keys()) {
  if (!ALLOWED_QUERY_PARAMS.has(key)) fail(`DATABASE_URL query parameter "${key}" is not allowed.`);
}
const host = url.hostname.replace(/^\[|\]$/g, '');
if (![...LOCAL_HOSTS, ...COMPOSE_SERVICE_HOSTS].includes(host)) {
  fail(`refusing host "${host}" (allowed: ${[...LOCAL_HOSTS, ...COMPOSE_SERVICE_HOSTS].join(', ')}).`);
}

// dbmate auto-loads ./.env unless told otherwise; point it at an empty file so only the
// guarded process environment is used. Callers cannot pass --env-file themselves (see above).
const dbmateArgs = ['--env-file=/dev/null', '--migrations-dir', 'db/migrations', ...args];

if (checkOnly) {
  console.log(`dbmate guard: ok (dbmate ${dbmateArgs.join(' ')})`);
  process.exit(0);
}

/** @type {NodeJS.ProcessEnv} */
const env = {};
for (const [k, v] of Object.entries(process.env)) {
  if (!k.startsWith('DBMATE_')) env[k] = v;
}
const bin = path.join(import.meta.dirname, '..', 'node_modules', '.bin', 'dbmate');
const r = spawnSync(bin, dbmateArgs, { stdio: 'inherit', env });
process.exit(r.status ?? 1);
