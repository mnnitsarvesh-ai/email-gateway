/**
 * Environment of the portal end-to-end run (step 7.1 WP6). Reads the repository `.env` (the same
 * file the api, the portal and Docker Compose read) without overriding variables already set in
 * the shell. Values are never printed; only key names appear in error messages.
 */
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

export const PACKAGE_ROOT = resolve(__dirname, '..');
export const REPO_ROOT = resolve(PACKAGE_ROOT, '../..');

let loaded = false;

export function loadEnv(): void {
  if (loaded) return;
  loaded = true;
  const file = resolve(REPO_ROOT, '.env');
  if (existsSync(file)) process.loadEnvFile(file);
}

export function requireEnv(key: string): string {
  loadEnv();
  const value = process.env[key];
  if (value === undefined || value === '') {
    throw new Error(`${key} is not set (expected in the repository .env)`);
  }
  return value;
}

export function optionalEnv(key: string, fallback: string): string {
  loadEnv();
  const value = process.env[key];
  return value === undefined || value === '' ? fallback : value;
}

/** The portal under test. The only origin the browser may reach (see support/fixtures.ts). */
export const PORTAL_ORIGIN = 'http://localhost:3001';

/** The api the portal forwards to (host process on API_HOST_PORT, 3200 on this machine). */
export function apiOrigin(): string {
  return optionalEnv('E2E_API_ORIGIN', optionalEnv('API_INTERNAL_URL', 'http://localhost:3200'));
}
