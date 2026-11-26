import { describe, expect, it } from 'vitest';
import { hasRole, loadWorkerConfig, notificationsAvailable } from './config';

const KEY = 'a'.repeat(64);
const base = {
  APP_ENV: 'local',
  DATABASE_URL: 'mysql://user:example-password@127.0.0.1:3306/db',
  REDIS_URL: 'redis://127.0.0.1:6379/0',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'gateway-mail',
  S3_BUCKET_ARCHIVE: 'gateway-archive',
  RABBITMQ_MAILBOX_URL: 'amqp://eg-mailbox:example-password@127.0.0.1:5672/email-gateway',
  PROVIDER_CREDENTIAL_ENCRYPTION_KEY: KEY,
};

const fails = (env: Record<string, string>, key: string) => {
  expect(() => loadWorkerConfig(env as NodeJS.ProcessEnv)).toThrow(key);
};

describe('mailbox-worker configuration (D16)', () => {
  it('applies the design defaults', () => {
    const cfg = loadWorkerConfig(base);
    expect(cfg.MAILBOX_WORKER_HTTP_PORT).toBe(3087);
    expect(cfg.MAILBOX_WORKER_ROLES).toEqual(['copies', 'feeds', 'inventory', 'health']);
    expect(cfg.API_MODE_GRAPH_URL).toBe('https://graph.microsoft.com');
    expect(cfg.API_MODE_FEED_TICK_MS).toBe(5000);
    expect(cfg.API_MODE_FEED_BATCH).toBe(50);
    expect(cfg.API_MODE_FETCH_CONCURRENCY).toBe(16);
    expect(cfg.API_MODE_FETCH_CONCURRENCY_PER_CONNECTION).toBe(4);
    expect(cfg.API_MODE_GRAPH_REQUESTS_PER_SECOND).toBe(8);
    expect(cfg.API_MODE_GMAIL_REQUESTS_PER_SECOND).toBe(10);
    expect(cfg.API_MODE_DIRECTORY_REQUESTS_PER_SECOND).toBe(5);
    expect(cfg.API_MODE_MAX_MESSAGE_BYTES).toBe(52_428_800);
    expect(cfg.API_MODE_GRAPH_SUBSCRIPTION_MINUTES).toBe(4230);
    expect(cfg.API_MODE_SUBSCRIPTION_RENEW_BEFORE_MINUTES).toBe(720);
    expect(cfg.API_MODE_DEDUPE_WINDOW_HOURS).toBe(168);
    expect(cfg.API_MODE_HYBRID_LINK_WINDOW_HOURS).toBe(72);
    expect(cfg.API_MODE_COUNTER_FLUSH_SECONDS).toBe(30);
    expect(cfg.INGEST_HEADER_MAX_BYTES).toBe(65_536);
    expect(notificationsAvailable(cfg)).toBe(false);
    expect(hasRole(cfg, 'health')).toBe(true);
  });

  it('parses roles and refuses unknown or repeated ones', () => {
    const cfg = loadWorkerConfig({ ...base, MAILBOX_WORKER_ROLES: 'copies, health' });
    expect(cfg.MAILBOX_WORKER_ROLES).toEqual(['copies', 'health']);
    fails({ ...base, MAILBOX_WORKER_ROLES: 'copies,remediate' }, 'MAILBOX_WORKER_ROLES');
    fails({ ...base, MAILBOX_WORKER_ROLES: 'copies,copies' }, 'MAILBOX_WORKER_ROLES');
  });

  it('refuses http and foreign provider origins outside local/ci', () => {
    const prod = { ...base, APP_ENV: 'production' };
    expect(() => loadWorkerConfig(prod as NodeJS.ProcessEnv)).not.toThrow();
    fails({ ...prod, API_MODE_GRAPH_URL: 'https://graph.example' }, 'API_MODE_GRAPH_URL');
    fails({ ...prod, API_MODE_ALLOW_HTTP_ENDPOINTS: 'true' }, 'API_MODE_ALLOW_HTTP_ENDPOINTS');
    fails({ ...prod, PROVIDER_ALLOW_HTTP_ENDPOINTS: 'true' }, 'PROVIDER_ALLOW_HTTP_ENDPOINTS');
    fails(
      {
        ...prod,
        API_MODE_GRAPH_NOTIFICATION_URL: 'http://api.example/api/v1/provider-notifications/graph',
        API_MODE_NOTIFICATION_SECRET: 'b'.repeat(64),
      },
      'API_MODE_GRAPH_NOTIFICATION_URL',
    );
  });

  it('allows the simulator origins over http locally only with the switch', () => {
    const sim = { ...base, API_MODE_GRAPH_URL: 'http://idp-simulator:8080/graph' };
    fails(sim, 'API_MODE_GRAPH_URL');
    const cfg = loadWorkerConfig({ ...sim, API_MODE_ALLOW_HTTP_ENDPOINTS: 'true' });
    expect(cfg.API_MODE_GRAPH_URL).toBe('http://idp-simulator:8080/graph');
  });

  it('needs the credential key for provider roles, the broker URL for copies', () => {
    const { PROVIDER_CREDENTIAL_ENCRYPTION_KEY: _k, ...noKey } = base;
    fails(noKey, 'PROVIDER_CREDENTIAL_ENCRYPTION_KEY');
    expect(() =>
      loadWorkerConfig({ ...noKey, MAILBOX_WORKER_ROLES: 'copies,health' }),
    ).not.toThrow();
    const { RABBITMQ_MAILBOX_URL: _u, ...noBroker } = base;
    fails(noBroker, 'RABBITMQ_MAILBOX_URL');
    expect(() => loadWorkerConfig({ ...noBroker, MAILBOX_WORKER_ROLES: 'feeds' })).not.toThrow();
  });

  it('needs the notification secret with a notification URL', () => {
    const url = 'https://gateway.example/api/v1/provider-notifications/graph';
    fails({ ...base, API_MODE_GRAPH_NOTIFICATION_URL: url }, 'API_MODE_NOTIFICATION_SECRET');
    fails(
      {
        ...base,
        API_MODE_GRAPH_NOTIFICATION_URL: `${url}?token=x`,
        API_MODE_NOTIFICATION_SECRET: 'c'.repeat(64),
      },
      'API_MODE_GRAPH_NOTIFICATION_URL',
    );
    const cfg = loadWorkerConfig({
      ...base,
      API_MODE_GRAPH_NOTIFICATION_URL: url,
      API_MODE_NOTIFICATION_SECRET: 'c'.repeat(64),
    });
    expect(notificationsAvailable(cfg)).toBe(true);
  });

  it('keeps thresholds ordered', () => {
    fails(
      { ...base, API_MODE_COVERAGE_FAIL_PERCENT: '96', API_MODE_COVERAGE_WARN_PERCENT: '95' },
      'API_MODE_COVERAGE_FAIL_PERCENT',
    );
    fails({ ...base, API_MODE_LAG_FAIL_SECONDS: '100' }, 'API_MODE_LAG_FAIL_SECONDS');
    fails(
      { ...base, API_MODE_SUBSCRIPTION_RENEW_BEFORE_MINUTES: '4230' },
      'API_MODE_SUBSCRIPTION_RENEW_BEFORE_MINUTES',
    );
  });

  it('names keys, never values, when refusing', () => {
    try {
      loadWorkerConfig({ ...base, PROVIDER_CREDENTIAL_ENCRYPTION_KEY: 'not-hex-secret-value' });
      expect.unreachable();
    } catch (error) {
      expect(String(error)).toContain('PROVIDER_CREDENTIAL_ENCRYPTION_KEY');
      expect(String(error)).not.toContain('not-hex-secret-value');
    }
  });
});
