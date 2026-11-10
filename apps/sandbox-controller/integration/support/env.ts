import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CONTROLLER_ENV_KEYS } from '../../src/config';

/**
 * Explicit controller environments for the integration suites (step 4.6 X1: "integration tests
 * build the config from explicit env objects"). `vitest.integration.config.ts` loaded
 * `../../.env` into `process.env` for addresses and the controller's own credentials; this module
 * copies ONLY the controller's allow-listed keys, rewrites the Compose MinIO address to the
 * published host port and uses a private scratch directory. Values are never printed.
 */

export function required(key: string): string {
  const value = process.env[key];
  if (!value)
    throw new Error(`${key} is not set (run scripts/init-env.mjs and append the sandbox keys)`);
  return value;
}

export const MINIO_ENDPOINT = `http://127.0.0.1:${process.env.MINIO_HOST_PORT ?? '9000'}`;
export const VHOST = process.env.RABBITMQ_VHOST ?? 'email-gateway';

/** An amqp URL with the topology vhost (the admin URL of .env has none). */
export function vhostUrl(url: string): string {
  const parsed = new URL(url);
  if (parsed.pathname === '/' || parsed.pathname === '')
    parsed.pathname = `/${encodeURIComponent(VHOST)}`;
  return parsed.toString();
}

const scratchDirs: string[] = [];

function scratchDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'eg-sbx-int-'));
  scratchDirs.push(dir);
  return dir;
}

/** Removes every scratch root `controllerEnv` created (afterAll of each suite). */
export function removeScratchDirs(): void {
  for (const dir of scratchDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
}

/** The controller's environment for a host run against the Compose broker and MinIO. */
export function controllerEnv(overrides: Record<string, string> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const key of CONTROLLER_ENV_KEYS) {
    const value = process.env[key];
    if (value) env[key] = value;
  }
  return {
    ...env,
    NODE_ENV: 'test',
    APP_ENV: 'local',
    LOG_LEVEL: 'warn',
    SANDBOX_BACKEND: 'disabled',
    SANDBOX_ALLOW_NON_VM_EXECUTION: 'false',
    SANDBOX_S3_ENDPOINT: MINIO_ENDPOINT,
    SANDBOX_S3_FORCE_PATH_STYLE: 'true',
    SANDBOX_SCRATCH_DIR: scratchDir(),
    SANDBOX_CONTROLLER_NAME: `wp2-int-${String(process.pid)}`,
    ...overrides,
  };
}

/** A synthetic organization id of this test run (results are routed by it). */
export function testOrganization(): string {
  return String(930_000_000 + Math.floor(Math.random() * 1_000_000));
}
