#!/usr/bin/env node
// Host-run of the sandbox-controller (step 4.6 X1): `pnpm --filter @email-gateway/sandbox-controller dev`.
//
// The repository's ../../.env holds keys the controller refuses (database, Redis, main S3, MinIO
// root, other broker users, the artifact PRIVATE key, …). This script never loads it wholesale:
// it parses it, keeps only the controller's allow-listed keys (CONTROLLER_ENV_KEYS of
// dist/config.js — the same list the unit tests check against the refusal rules), lets explicit
// shell overrides of those keys win, rewrites Compose host names to 127.0.0.1 with the published
// ports, uses a host scratch directory and spawns `node dist/main.js` with that environment only.
// No value is printed.

import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseEnv } from 'node:util';

const appDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const main = join(appDir, 'dist', 'main.js');
if (!existsSync(main)) {
  console.error(
    'dev-env: dist/main.js missing; run `pnpm --filter @email-gateway/sandbox-controller build`',
  );
  process.exit(1);
}
const { CONTROLLER_ENV_KEYS, forbiddenKeysPresent } = require(join(appDir, 'dist', 'config.js'));

const envFile = resolve(appDir, '../../.env');
const fileEnv = existsSync(envFile) ? parseEnv(readFileSync(envFile, 'utf8')) : {};

// Published host ports of the Compose services the controller talks to.
const hostPorts = {
  rabbitmq: { 5672: fileEnv.RABBITMQ_HOST_PORT ?? '5672' },
  minio: { 9000: fileEnv.MINIO_HOST_PORT ?? '9000' },
};

/** Rewrites `scheme://[user@]rabbitmq:5672/…` style values to 127.0.0.1 and the host port. */
function toHost(value) {
  return value
    .split(',')
    .map((entry) => {
      let url;
      try {
        url = new URL(entry.trim());
      } catch {
        return entry;
      }
      const mapping = hostPorts[url.hostname];
      if (!mapping) return entry.trim();
      const port =
        url.port ||
        (url.protocol.startsWith('amqp') ? '5672' : url.protocol === 'https:' ? '443' : '80');
      url.hostname = '127.0.0.1';
      url.port = mapping[port] ?? port;
      return url.toString().replace(/\/$/, entry.trim().endsWith('/') ? '/' : '');
    })
    .join(',');
}

const env = {};
for (const key of CONTROLLER_ENV_KEYS) {
  const value = process.env[key] ?? fileEnv[key];
  if (value !== undefined && value !== '') env[key] = toHost(value);
}
env.NODE_ENV = process.env.NODE_ENV ?? 'development';
// The container path /scratch does not exist on a developer machine.
if (!env.SANDBOX_SCRATCH_DIR || env.SANDBOX_SCRATCH_DIR === '/scratch') {
  env.SANDBOX_SCRATCH_DIR = join(tmpdir(), 'eg-sandbox-controller-scratch');
}
mkdirSync(env.SANDBOX_SCRATCH_DIR, { recursive: true, mode: 0o700 });

// Defence in depth: the allow-list must never yield a refused key.
const refused = forbiddenKeysPresent(env);
if (refused.length > 0) {
  console.error(`dev-env: refusing to start with ${refused.join(', ')}`);
  process.exit(1);
}

const child = spawn(process.execPath, ['--enable-source-maps', main], {
  cwd: appDir,
  env: { PATH: process.env.PATH ?? '/usr/bin:/bin', ...env },
  stdio: 'inherit',
});
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));
child.on('exit', (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
