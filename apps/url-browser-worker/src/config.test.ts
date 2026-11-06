import { describe, expect, it } from 'vitest';
import { forbiddenKeysPresent, loadProxyConfig, loadWorkerConfig } from './config';

const worker = {
  NODE_ENV: 'production',
  APP_ENV: 'local',
  RABBITMQ_URL_BROWSER_URL: 'amqp://eg-url-browser:pw@rabbitmq:5672/email-gateway',
  URL_BROWSER_PROXY_URL: 'http://url-egress-proxy:3128',
  URL_EGRESS_PROXY_TOKEN: 'x'.repeat(32),
};
const proxy = {
  NODE_ENV: 'production',
  APP_ENV: 'local',
  URL_EGRESS_PROXY_TOKEN: 'x'.repeat(32),
  URL_DNS_SERVERS: '172.31.250.53',
  URL_FETCH_TEST_ALLOW_CIDRS: '203.0.113.0/24',
};

describe('url-browser-worker config', () => {
  it('loads the design defaults (§5)', () => {
    expect(loadWorkerConfig(worker)).toMatchObject({
      URL_BROWSER_HTTP_PORT: 3090,
      URL_BROWSER_CONCURRENCY: 1,
      URL_BROWSER_JOB_TIMEOUT_MS: 20_000,
      URL_BROWSER_NAVIGATION_TIMEOUT_MS: 15_000,
      URL_BROWSER_MAX_JOBS_PER_BROWSER: 50,
      URL_BROWSER_MAX_RSS_MB: 768,
    });
  });

  it.each([
    'DATABASE_URL',
    'CLICK_DATABASE_URL',
    'REDIS_URL',
    'URL_CACHE_HMAC_KEY',
    'URL_TOKEN_KEY_CURRENT',
    'URL_TOKEN_KEY_PREVIOUS',
    'S3_ACCESS_KEY_ID',
    'S3_BUCKET_MAIL',
    'DATABASE_URL_FILE',
    'URL_TOKEN_KEY_CURRENT_FILE',
  ])('refuses to start with %s set, naming the key and never the value', (key) => {
    const secret = 'super-secret-value-123';
    let message = '';
    try {
      loadWorkerConfig({ ...worker, [key]: secret });
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain(key);
    expect(message).not.toContain(secret);
    expect(() => loadProxyConfig({ ...proxy, [key]: secret })).toThrow(key);
  });

  it('ignores empty forbidden keys (Compose blanks)', () => {
    expect(forbiddenKeysPresent({ DATABASE_URL: '', S3_REGION: '' })).toEqual([]);
  });

  it('bounds the concurrency to 1..4 and needs an http proxy without credentials', () => {
    expect(() => loadWorkerConfig({ ...worker, URL_BROWSER_CONCURRENCY: '5' })).toThrow(
      'URL_BROWSER_CONCURRENCY',
    );
    expect(() => loadWorkerConfig({ ...worker, URL_BROWSER_PROXY_URL: 'https://p:3128' })).toThrow(
      'URL_BROWSER_PROXY_URL',
    );
    expect(() =>
      loadWorkerConfig({ ...worker, URL_BROWSER_PROXY_URL: 'http://u:p@p:3128' }),
    ).toThrow('URL_BROWSER_PROXY_URL');
    expect(() => loadWorkerConfig({ ...worker, URL_EGRESS_PROXY_TOKEN: 'short' })).toThrow(
      'URL_EGRESS_PROXY_TOKEN',
    );
  });
});

describe('url-egress-proxy config', () => {
  it('loads the defaults', () => {
    expect(loadProxyConfig(proxy)).toMatchObject({
      URL_EGRESS_PORT: 3128,
      URL_EGRESS_ADMIN_PORT: 3091,
      URL_EGRESS_MAX_CONNECTIONS: 64,
      URL_EGRESS_MAX_BYTES_PER_CONNECTION: 10_485_760,
      URL_EGRESS_IDLE_TIMEOUT_MS: 15_000,
      URL_EGRESS_MAX_CONNECTION_MS: 30_000,
    });
  });

  it('refuses the test seams in production and outside the documentation ranges', () => {
    expect(() => loadProxyConfig({ ...proxy, APP_ENV: 'production' })).toThrow(
      'URL_FETCH_TEST_ALLOW_CIDRS',
    );
    expect(() => loadProxyConfig({ ...proxy, APP_ENV: undefined })).toThrow(
      'URL_FETCH_TEST_ALLOW_CIDRS',
    );
    expect(() => loadProxyConfig({ ...proxy, URL_FETCH_TEST_ALLOW_CIDRS: '10.0.0.0/8' })).toThrow(
      'URL_FETCH_TEST_ALLOW_CIDRS',
    );
    expect(() =>
      loadProxyConfig({
        ...proxy,
        APP_ENV: 'staging',
        URL_FETCH_TEST_ALLOW_CIDRS: '',
        URL_FETCH_TEST_DIAL_MAP: '203.0.113.10:80=127.0.0.1:1',
      }),
    ).toThrow('URL_FETCH_TEST_DIAL_MAP');
    expect(() => loadProxyConfig({ ...proxy, URL_EGRESS_ADMIN_PORT: '3128' })).toThrow(
      'URL_EGRESS_ADMIN_PORT',
    );
  });
});
