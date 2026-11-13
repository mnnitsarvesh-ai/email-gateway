// @vitest-environment node
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * Design P10: no secrets in client bundles. Runs only when a build exists (.next/static);
 * checks server key names, the values of the local .env for those keys (never printed), and
 * token prefixes (`egr_` refresh, `egt_` single-use, `eyJ` JWT).
 */
const appDir = join(__dirname, '..');
const staticDir = join(appDir, '.next/static');
const SERVER_KEYS = [
  'PORTAL_SESSION_KEY',
  'PORTAL_SESSION_KEY_PREVIOUS',
  'API_TRUSTED_FORWARDER_TOKEN',
  'API_INTERNAL_URL',
  'AUTH_JWT_SECRET',
  'DATABASE_URL',
];

function files(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...files(full));
    else out.push(full);
  }
  return out;
}

function envValues(): Map<string, string> {
  const values = new Map<string, string>();
  const envFile = join(appDir, '../../.env');
  if (!existsSync(envFile)) return values;
  for (const line of readFileSync(envFile, 'utf8').split('\n')) {
    const match = /^([A-Z0-9_]+)=(.*)$/.exec(line);
    if (match?.[1] && match[2] && SERVER_KEYS.includes(match[1]) && match[2].length >= 12)
      values.set(match[1], match[2]);
  }
  return values;
}

describe.skipIf(!existsSync(staticDir))('build output (.next/static)', () => {
  const contents = existsSync(staticDir)
    ? files(staticDir)
        .filter((f) => /\.(js|css|html|json|txt|map)$/.test(f))
        .map((f) => ({ file: f.slice(appDir.length + 1), text: readFileSync(f, 'utf8') }))
    : [];

  it('contains no server key names', () => {
    for (const key of SERVER_KEYS) {
      expect(
        contents.filter((c) => c.text.includes(key)).map((c) => c.file),
        key,
      ).toEqual([]);
    }
  });

  it('contains no values of the server keys of the local .env', () => {
    for (const [key, value] of envValues()) {
      const hits = contents.filter((c) => c.text.includes(value)).map((c) => c.file);
      expect(hits, `value of ${key} found in client output`).toEqual([]);
    }
  });

  it('contains no token-shaped strings', () => {
    for (const prefix of [
      /egr_[A-Za-z0-9_-]{20,}/,
      /egt_[A-Za-z0-9_-]{20,}/,
      /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
    ]) {
      expect(
        contents.filter((c) => prefix.test(c.text)).map((c) => c.file),
        String(prefix),
      ).toEqual([]);
    }
  });
});
