import { describe, expect, it } from 'vitest';
import { testEnv } from './click/click.test-support';
import { loadClickConfig } from './config';

const production = {
  NODE_ENV: 'production',
  APP_ENV: 'production',
  URL_CLICK_BASE_URL: 'https://protect.example.com',
};

describe('click-service config', () => {
  it('loads the design defaults (§5)', () => {
    const config = loadClickConfig(testEnv());
    expect(config).toMatchObject({
      CLICK_HTTP_PORT: 3080,
      CLICK_ADMIN_PORT: 3081,
      CLICK_DB_TX_TIMEOUT_MS: 120_000,
      CLICK_RATE_LIMIT_IP_PER_MINUTE: 120,
      CLICK_RATE_LIMIT_TOKEN_PER_MINUTE: 30,
      CLICK_RATE_LIMIT_INVALID_PER_MINUTE: 20,
      CLICK_EVENT_MAX_PENDING: 1000,
      CLICK_CONTINUE_TTL_SECONDS: 600,
      CLICK_TRUST_PROXY: 0,
      CLICK_STORE_CLIENT_NETWORK: true,
      clickHost: 'localhost',
    });
    expect(config.tokenKeys.current.id).toBe(2);
    expect(config.tokenKeys.previous?.id).toBe(1);
    expect(config.platform.scanTimeFetch).toBe('suspicious');
  });

  it('accepts production with https and without test seams', () => {
    expect(() => loadClickConfig(testEnv(production))).not.toThrow();
  });

  it.each([
    [
      'URL_CLICK_BASE_URL http in production',
      { ...production, URL_CLICK_BASE_URL: 'http://protect.example.com' },
      'URL_CLICK_BASE_URL',
    ],
    [
      'test allow CIDRs in production',
      { ...production, URL_FETCH_TEST_ALLOW_CIDRS: '203.0.113.0/24' },
      'URL_FETCH_TEST_ALLOW_CIDRS',
    ],
    [
      'dial map in production',
      { ...production, URL_FETCH_TEST_DIAL_MAP: '203.0.113.10:80=127.0.0.1:18080' },
      'URL_FETCH_TEST_DIAL_MAP',
    ],
    [
      'test seams with NODE_ENV=production and no APP_ENV',
      {
        NODE_ENV: 'production',
        APP_ENV: undefined,
        URL_CLICK_BASE_URL: 'https://p.example.com',
        URL_FETCH_TEST_ALLOW_CIDRS: '203.0.113.0/24',
      },
      'URL_FETCH_TEST_ALLOW_CIDRS',
    ],
    [
      'test allow CIDR outside the documentation ranges',
      { URL_FETCH_TEST_ALLOW_CIDRS: '10.0.0.0/8' },
      'URL_FETCH_TEST_ALLOW_CIDRS',
    ],
    [
      'previous key without id',
      { URL_TOKEN_KEY_PREVIOUS_ID: undefined },
      'URL_TOKEN_KEY_PREVIOUS_ID',
    ],
    ['short cache key', { URL_CACHE_HMAC_KEY: 'short' }, 'URL_CACHE_HMAC_KEY'],
    ['malformed token key', { URL_TOKEN_KEY_CURRENT: 'zz' }, 'URL_TOKEN_KEY_CURRENT'],
    ['same public and admin port', { CLICK_ADMIN_PORT: '3080' }, 'CLICK_ADMIN_PORT'],
    ['transaction budget below 60 s', { CLICK_DB_TX_TIMEOUT_MS: '5000' }, 'CLICK_DB_TX_TIMEOUT_MS'],
    ['not a mysql URL', { CLICK_DATABASE_URL: 'postgres://x' }, 'CLICK_DATABASE_URL'],
    [
      'a documented-only provider',
      { URL_REPUTATION_PROVIDERS: 'local_feed,google_safe_browsing' },
      'URL_REPUTATION_PROVIDERS',
    ],
    [
      'proxy URL without token',
      { URL_FETCH_EGRESS_PROXY_URL: 'http://url-egress-proxy:3128' },
      'URL_EGRESS_PROXY_TOKEN',
    ],
    [
      'base URL with a query',
      { URL_CLICK_BASE_URL: 'http://localhost:3080/?x=1' },
      'URL_CLICK_BASE_URL',
    ],
  ])('refuses %s', (_name, overrides, key) => {
    expect(() => loadClickConfig(testEnv(overrides as Record<string, string | undefined>))).toThrow(
      key,
    );
  });

  it('refuses the same key for current and previous, without echoing it', () => {
    let message = '';
    try {
      loadClickConfig(testEnv({ URL_TOKEN_KEY_PREVIOUS: 'a'.repeat(64) }));
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain('URL_TOKEN_KEY_');
    expect(message).not.toContain('a'.repeat(64));
  });
});
