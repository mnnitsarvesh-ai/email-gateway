import { describe, expect, it } from 'vitest';
import { loadWorkerConfig, webhookRetryConfig } from './config';

const KEY = '0123456789abcdef'.repeat(4);
const valid = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  REDIS_URL: 'redis://localhost:6379/0',
  RABBITMQ_WEBHOOK_URL: 'amqp://eg-webhook:pw@localhost:5672/email-gateway',
  WEBHOOK_SECRET_ENCRYPTION_KEY: KEY,
};

const rejection = (env: Record<string, string>): string => {
  try {
    loadWorkerConfig(env);
  } catch (error) {
    return String(error);
  }
  return '';
};

describe('loadWorkerConfig (step 6.2 §4.4)', () => {
  it('defaults every key to the §4.4 value', () => {
    const cfg = loadWorkerConfig(valid);
    expect(cfg).toMatchObject({
      HTTP_PORT: 3075,
      WEBHOOK_WORKER_ROLES: ['fanout', 'delivery'],
      WEBHOOK_FANOUT_PREFETCH: 16,
      WEBHOOK_FANOUT_TX_TIMEOUT_MS: 120_000,
      WEBHOOK_SUBSCRIPTION_CACHE_SECONDS: 5,
      WEBHOOK_DELIVERY_POLL_INTERVAL_MS: 500,
      WEBHOOK_DELIVERY_CONCURRENCY: 32,
      WEBHOOK_MAX_INFLIGHT_PER_ORG: 16,
      WEBHOOK_MAX_INFLIGHT_PER_SUBSCRIPTION: 4,
      WEBHOOK_RATE_PER_SUBSCRIPTION_PER_MINUTE: 600,
      WEBHOOK_ALLOWED_PORTS: [443],
      WEBHOOK_ALLOW_HTTP: false,
      WEBHOOK_HTTP_CONNECT_TIMEOUT_MS: 3_000,
      WEBHOOK_HTTP_TOTAL_TIMEOUT_MS: 10_000,
      WEBHOOK_RESPONSE_MAX_BYTES: 4_096,
      WEBHOOK_DNS_SERVERS: [],
      WEBHOOK_MAX_ATTEMPTS: 8,
      WEBHOOK_RETRY_BASE_SECONDS: 30,
      WEBHOOK_RETRY_MAX_DELAY_SECONDS: 21_600,
      WEBHOOK_RETRY_AFTER_MAX_SECONDS: 3_600,
      WEBHOOK_MAX_RETRY_AGE_HOURS: 24,
      WEBHOOK_MAX_PENDING_PER_SUBSCRIPTION: 50_000,
      WEBHOOK_DISABLE_AFTER_FAILURES: 50,
      WEBHOOK_DISABLE_AFTER_HOURS: 24,
      WEBHOOK_REPLAY_MAX_EVENTS: 10_000,
      WEBHOOK_REPLAY_MAX_PER_DELIVERY: 10,
      WEBHOOK_MAINTENANCE_INTERVAL_MS: 60_000,
      WEBHOOK_DELETED_RETENTION_DAYS: 62,
      WEBHOOK_TEST_ALLOW_CIDRS: [],
    });
    expect(cfg.WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS).toBeUndefined();
    expect(cfg.WEBHOOK_TEST_DIAL_MAP).toBeUndefined();
    expect(cfg.WEBHOOK_EXTRA_CA_PATH).toBeUndefined();
    expect(cfg.RABBITMQ_WEBHOOK_URL).toHaveLength(1);
    expect(webhookRetryConfig(cfg)).toEqual({
      baseSeconds: 30,
      maxDelaySeconds: 21_600,
      retryAfterMaxSeconds: 3_600,
      maxAttempts: 8,
      maxRetryAgeHours: 24,
    });
  });

  it('accepts the bounds and the local test seams', () => {
    const cfg = loadWorkerConfig({
      ...valid,
      APP_ENV: 'local',
      WEBHOOK_WORKER_ROLES: 'delivery',
      WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS: 'f'.repeat(64),
      WEBHOOK_FANOUT_PREFETCH: '64',
      WEBHOOK_FANOUT_TX_TIMEOUT_MS: '600000',
      WEBHOOK_SUBSCRIPTION_CACHE_SECONDS: '60',
      WEBHOOK_DELIVERY_POLL_INTERVAL_MS: '100',
      WEBHOOK_DELIVERY_CONCURRENCY: '256',
      WEBHOOK_MAX_INFLIGHT_PER_ORG: '128',
      WEBHOOK_MAX_INFLIGHT_PER_SUBSCRIPTION: '32',
      WEBHOOK_RATE_PER_SUBSCRIPTION_PER_MINUTE: '6000',
      WEBHOOK_ALLOWED_PORTS: '443, 80,443',
      WEBHOOK_ALLOW_HTTP: 'true',
      WEBHOOK_HTTP_CONNECT_TIMEOUT_MS: '10000',
      WEBHOOK_HTTP_TOTAL_TIMEOUT_MS: '30000',
      WEBHOOK_RESPONSE_MAX_BYTES: '65536',
      WEBHOOK_DNS_SERVERS: '172.31.250.53,127.0.0.1:1053,[::1]:53,2001:db8::1',
      WEBHOOK_MAX_ATTEMPTS: '15',
      WEBHOOK_RETRY_BASE_SECONDS: '600',
      WEBHOOK_RETRY_MAX_DELAY_SECONDS: '86400',
      WEBHOOK_RETRY_AFTER_MAX_SECONDS: '86400',
      WEBHOOK_MAX_RETRY_AGE_HOURS: '72',
      WEBHOOK_MAX_PENDING_PER_SUBSCRIPTION: '1000',
      WEBHOOK_DISABLE_AFTER_FAILURES: '5',
      WEBHOOK_DISABLE_AFTER_HOURS: '168',
      WEBHOOK_REPLAY_MAX_EVENTS: '100000',
      WEBHOOK_REPLAY_MAX_PER_DELIVERY: '50',
      WEBHOOK_MAINTENANCE_INTERVAL_MS: '3600000',
      WEBHOOK_DELETED_RETENTION_DAYS: '365',
      WEBHOOK_TEST_ALLOW_CIDRS: '203.0.113.0/24',
      WEBHOOK_TEST_DIAL_MAP: '203.0.113.20:443=127.0.0.1:18443',
      WEBHOOK_EXTRA_CA_PATH: '/pki/ca/ca.pem',
    });
    expect(cfg).toMatchObject({
      WEBHOOK_WORKER_ROLES: ['delivery'],
      WEBHOOK_ALLOWED_PORTS: [443, 80],
      WEBHOOK_ALLOW_HTTP: true,
      WEBHOOK_TEST_ALLOW_CIDRS: ['203.0.113.0/24'],
      WEBHOOK_EXTRA_CA_PATH: '/pki/ca/ca.pem',
    });
    expect(cfg.WEBHOOK_DNS_SERVERS).toHaveLength(4);
    // ci allows the seams too.
    expect(
      loadWorkerConfig({ ...valid, APP_ENV: 'ci', WEBHOOK_ALLOW_HTTP: 'true' }).WEBHOOK_ALLOW_HTTP,
    ).toBe(true);
  });

  it.each([
    [{ RABBITMQ_WEBHOOK_URL: '' }, 'RABBITMQ_WEBHOOK_URL'],
    [{ RABBITMQ_WEBHOOK_URL: 'http://x' }, 'RABBITMQ_WEBHOOK_URL'],
    [{ REDIS_URL: 'http://x' }, 'REDIS_URL'],
    [{ WEBHOOK_SECRET_ENCRYPTION_KEY: 'abc' }, 'WEBHOOK_SECRET_ENCRYPTION_KEY'],
    [{ WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS: 'xyz' }, 'WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS'],
    [{ WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS: KEY }, 'WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS'],
    [{ WEBHOOK_WORKER_ROLES: ',' }, 'WEBHOOK_WORKER_ROLES'],
    [{ WEBHOOK_WORKER_ROLES: 'fanout,replay' }, 'WEBHOOK_WORKER_ROLES'],
    [{ WEBHOOK_WORKER_ROLES: 'fanout,fanout' }, 'WEBHOOK_WORKER_ROLES'],
    [{ WEBHOOK_FANOUT_PREFETCH: '0' }, 'WEBHOOK_FANOUT_PREFETCH'],
    [{ WEBHOOK_FANOUT_PREFETCH: '65' }, 'WEBHOOK_FANOUT_PREFETCH'],
    [{ WEBHOOK_FANOUT_TX_TIMEOUT_MS: '119999' }, 'WEBHOOK_FANOUT_TX_TIMEOUT_MS'],
    [{ WEBHOOK_FANOUT_TX_TIMEOUT_MS: '600001' }, 'WEBHOOK_FANOUT_TX_TIMEOUT_MS'],
    [{ WEBHOOK_SUBSCRIPTION_CACHE_SECONDS: '61' }, 'WEBHOOK_SUBSCRIPTION_CACHE_SECONDS'],
    [{ WEBHOOK_DELIVERY_POLL_INTERVAL_MS: '99' }, 'WEBHOOK_DELIVERY_POLL_INTERVAL_MS'],
    [{ WEBHOOK_DELIVERY_CONCURRENCY: '257' }, 'WEBHOOK_DELIVERY_CONCURRENCY'],
    [{ WEBHOOK_MAX_INFLIGHT_PER_ORG: '129' }, 'WEBHOOK_MAX_INFLIGHT_PER_ORG'],
    [{ WEBHOOK_MAX_INFLIGHT_PER_SUBSCRIPTION: '33' }, 'WEBHOOK_MAX_INFLIGHT_PER_SUBSCRIPTION'],
    [
      { WEBHOOK_RATE_PER_SUBSCRIPTION_PER_MINUTE: '6001' },
      'WEBHOOK_RATE_PER_SUBSCRIPTION_PER_MINUTE',
    ],
    [{ WEBHOOK_ALLOWED_PORTS: '443,70000' }, 'WEBHOOK_ALLOWED_PORTS'],
    [{ WEBHOOK_ALLOWED_PORTS: 'https' }, 'WEBHOOK_ALLOWED_PORTS'],
    [{ WEBHOOK_HTTP_CONNECT_TIMEOUT_MS: '499' }, 'WEBHOOK_HTTP_CONNECT_TIMEOUT_MS'],
    [{ WEBHOOK_HTTP_TOTAL_TIMEOUT_MS: '30001' }, 'WEBHOOK_HTTP_TOTAL_TIMEOUT_MS'],
    [{ WEBHOOK_RESPONSE_MAX_BYTES: '255' }, 'WEBHOOK_RESPONSE_MAX_BYTES'],
    [{ WEBHOOK_DNS_SERVERS: 'dns.example' }, 'WEBHOOK_DNS_SERVERS'],
    [{ WEBHOOK_DNS_SERVERS: '10.0.0.1:0' }, 'WEBHOOK_DNS_SERVERS'],
    [{ WEBHOOK_MAX_ATTEMPTS: '16' }, 'WEBHOOK_MAX_ATTEMPTS'],
    [{ WEBHOOK_RETRY_BASE_SECONDS: '601' }, 'WEBHOOK_RETRY_BASE_SECONDS'],
    [{ WEBHOOK_RETRY_MAX_DELAY_SECONDS: '59' }, 'WEBHOOK_RETRY_MAX_DELAY_SECONDS'],
    [{ WEBHOOK_RETRY_AFTER_MAX_SECONDS: '0' }, 'WEBHOOK_RETRY_AFTER_MAX_SECONDS'],
    [{ WEBHOOK_MAX_RETRY_AGE_HOURS: '73' }, 'WEBHOOK_MAX_RETRY_AGE_HOURS'],
    [{ WEBHOOK_MAX_PENDING_PER_SUBSCRIPTION: '999' }, 'WEBHOOK_MAX_PENDING_PER_SUBSCRIPTION'],
    [{ WEBHOOK_DISABLE_AFTER_FAILURES: '4' }, 'WEBHOOK_DISABLE_AFTER_FAILURES'],
    [{ WEBHOOK_DISABLE_AFTER_HOURS: '169' }, 'WEBHOOK_DISABLE_AFTER_HOURS'],
    [{ WEBHOOK_REPLAY_MAX_EVENTS: '100001' }, 'WEBHOOK_REPLAY_MAX_EVENTS'],
    [{ WEBHOOK_REPLAY_MAX_PER_DELIVERY: '51' }, 'WEBHOOK_REPLAY_MAX_PER_DELIVERY'],
    [{ WEBHOOK_REPLAY_MAX_PER_DELIVERY: '0' }, 'WEBHOOK_REPLAY_MAX_PER_DELIVERY'],
    [{ WEBHOOK_MAINTENANCE_INTERVAL_MS: '9999' }, 'WEBHOOK_MAINTENANCE_INTERVAL_MS'],
    [{ WEBHOOK_DELETED_RETENTION_DAYS: '61' }, 'WEBHOOK_DELETED_RETENTION_DAYS'],
    // Cross-field rules.
    [
      { WEBHOOK_RETRY_BASE_SECONDS: '120', WEBHOOK_RETRY_MAX_DELAY_SECONDS: '60' },
      'WEBHOOK_RETRY_BASE_SECONDS',
    ],
    [
      { WEBHOOK_HTTP_CONNECT_TIMEOUT_MS: '5000', WEBHOOK_HTTP_TOTAL_TIMEOUT_MS: '5000' },
      'WEBHOOK_HTTP_CONNECT_TIMEOUT_MS',
    ],
    // Seams: documentation ranges only, a valid dial map.
    [{ APP_ENV: 'local', WEBHOOK_TEST_ALLOW_CIDRS: '10.0.0.0/8' }, 'WEBHOOK_TEST_ALLOW_CIDRS'],
    [{ APP_ENV: 'local', WEBHOOK_TEST_DIAL_MAP: 'nonsense' }, 'WEBHOOK_TEST_DIAL_MAP'],
  ])('refuses %o naming %s', (env, key) => {
    expect(rejection({ ...valid, ...env })).toContain(key);
  });

  it.each([
    ['WEBHOOK_ALLOW_HTTP', 'true'],
    ['WEBHOOK_TEST_ALLOW_CIDRS', '203.0.113.0/24'],
    ['WEBHOOK_TEST_DIAL_MAP', '203.0.113.20:443=127.0.0.1:18443'],
    ['WEBHOOK_EXTRA_CA_PATH', '/pki/ca/ca.pem'],
  ])('refuses the test seam %s outside APP_ENV local/ci', (key, value) => {
    for (const appEnv of ['staging', 'production']) {
      expect(rejection({ ...valid, APP_ENV: appEnv, [key]: value }), appEnv).toContain(key);
    }
    // NODE_ENV=production without APP_ENV is production, never local by omission.
    expect(rejection({ ...valid, NODE_ENV: 'production', [key]: value })).toContain(key);
  });

  it('never echoes a secret value in an error', () => {
    const message = rejection({ ...valid, WEBHOOK_SECRET_ENCRYPTION_KEY: 'secret-value-123' });
    expect(message).toContain('WEBHOOK_SECRET_ENCRYPTION_KEY');
    expect(message).not.toContain('secret-value-123');
  });
});
