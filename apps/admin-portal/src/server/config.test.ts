// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { PortalConfigError, loadServerConfig } from './config';
import { TEST_FORWARDER_TOKEN, TEST_KEY } from './test-helpers';

const base = {
  NODE_ENV: 'development',
  APP_ENV: 'local',
  API_INTERNAL_URL: 'http://localhost:3200',
  PORTAL_PUBLIC_URL: 'http://localhost:3001',
  PORTAL_SESSION_KEY: TEST_KEY,
};

function issues(
  env: Record<string, string | undefined>,
  readFile?: (p: string) => string,
): string[] {
  try {
    loadServerConfig(env, readFile);
    return [];
  } catch (error) {
    if (error instanceof PortalConfigError) return error.issues;
    throw error;
  }
}

describe('server config (design §3.5)', () => {
  it('applies the defaults', () => {
    expect(loadServerConfig(base)).toMatchObject({
      PORTAL_TRUST_PROXY_HOPS: 0,
      PORTAL_API_TIMEOUT_MS: 15_000,
      PORTAL_DEV_MOCKS: 'disabled',
      secure: false,
    });
  });

  it('treats empty values as unset (blank keys in .env)', () => {
    expect(
      loadServerConfig({ ...base, PORTAL_SESSION_KEY_PREVIOUS: '', PORTAL_DEV_MOCKS: '' })
        .PORTAL_DEV_MOCKS,
    ).toBe('disabled');
  });

  it('reads _FILE secrets, an explicit value wins', () => {
    const files: Record<string, string> = {
      '/run/secrets/key': `${TEST_KEY}\n`,
      '/run/secrets/fwd': TEST_FORWARDER_TOKEN,
    };
    const cfg = loadServerConfig(
      {
        ...base,
        PORTAL_SESSION_KEY: undefined,
        PORTAL_SESSION_KEY_FILE: '/run/secrets/key',
        API_TRUSTED_FORWARDER_TOKEN_FILE: '/run/secrets/fwd',
      },
      (path) => files[path] ?? '',
    );
    expect(cfg.PORTAL_SESSION_KEY).toBe(TEST_KEY);
    expect(cfg.API_TRUSTED_FORWARDER_TOKEN).toBe(TEST_FORWARDER_TOKEN);
    expect(
      issues(
        { ...base, PORTAL_SESSION_KEY: undefined, PORTAL_SESSION_KEY_FILE: '/missing' },
        () => {
          throw new Error('ENOENT');
        },
      ),
    ).toEqual(['PORTAL_SESSION_KEY_FILE: the file cannot be read']);
  });

  it('enforces the bounds and never echoes values', () => {
    const found = issues({
      ...base,
      PORTAL_SESSION_KEY: 'not-hex-secret-value',
      PORTAL_TRUST_PROXY_HOPS: '6',
      PORTAL_API_TIMEOUT_MS: '999',
      API_TRUSTED_FORWARDER_TOKEN: 'short',
      API_INTERNAL_URL: 'http://api:3000/api',
    });
    expect(found.join('\n')).toMatch(/PORTAL_SESSION_KEY/);
    expect(found.join('\n')).toMatch(/PORTAL_TRUST_PROXY_HOPS/);
    expect(found.join('\n')).toMatch(/PORTAL_API_TIMEOUT_MS/);
    expect(found.join('\n')).toMatch(/API_TRUSTED_FORWARDER_TOKEN/);
    expect(found.join('\n')).toMatch(/API_INTERNAL_URL/);
    expect(found.join('\n')).not.toContain('not-hex-secret-value');
  });

  it('refuses production without the forwarder token (ADR-0060)', () => {
    expect(issues({ ...base, NODE_ENV: 'production' })).toEqual([
      'API_TRUSTED_FORWARDER_TOKEN: is required when NODE_ENV=production (ADR-0060)',
    ]);
  });

  it('refuses dev fixture mode outside development (design P9)', () => {
    expect(
      issues({
        ...base,
        NODE_ENV: 'production',
        API_TRUSTED_FORWARDER_TOKEN: TEST_FORWARDER_TOKEN,
        PORTAL_DEV_MOCKS: 'enabled',
      }),
    ).toEqual(['PORTAL_DEV_MOCKS: enabled is allowed only with NODE_ENV=development (design P9)']);
    expect(issues({ ...base, NODE_ENV: 'test', PORTAL_DEV_MOCKS: 'enabled' })).toHaveLength(1);
    expect(issues({ ...base, PORTAL_DEV_MOCKS: 'enabled' })).toEqual([]);
  });

  it('requires an https public origin and at least one proxy hop outside local and ci', () => {
    expect(issues({ ...base, APP_ENV: 'staging', PORTAL_TRUST_PROXY_HOPS: '1' })).toEqual([
      'PORTAL_PUBLIC_URL: must be an https:// origin unless APP_ENV is local or ci',
    ]);
    expect(
      issues({
        ...base,
        APP_ENV: 'production',
        PORTAL_PUBLIC_URL: 'https://portal.example.test',
      })[0],
    ).toMatch(/^PORTAL_TRUST_PROXY_HOPS: must be at least 1/);
    expect(
      loadServerConfig({
        ...base,
        APP_ENV: 'staging',
        PORTAL_TRUST_PROXY_HOPS: '1',
        PORTAL_PUBLIC_URL: 'https://portal.example.test',
      }).secure,
    ).toBe(true);
  });

  it('refuses a previous key equal to the current one', () => {
    expect(issues({ ...base, PORTAL_SESSION_KEY_PREVIOUS: TEST_KEY.toUpperCase() })).toEqual([
      'PORTAL_SESSION_KEY_PREVIOUS: must differ from PORTAL_SESSION_KEY',
    ]);
  });
});
