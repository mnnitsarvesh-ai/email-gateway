import { ConfigValidationError } from '@email-gateway/config';
import { describe, expect, it } from 'vitest';
import { loadRelayConfig } from './config';

const SECRET = 's3cr3t-value-never-echoed';
const base = {
  DATABASE_URL: `mysql://relay:${SECRET}@localhost:3306/test`,
  RABBITMQ_RELAY_URL: `amqp://eg-relay:${SECRET}@localhost:5672/email-gateway`,
};

const issues = (env: Record<string, string>): string[] => {
  try {
    loadRelayConfig({ ...base, ...env });
  } catch (err) {
    if (err instanceof ConfigValidationError) return err.issues;
    throw err;
  }
  return [];
};

describe('event-relay config (§6)', () => {
  it('applies the design defaults', () => {
    expect(loadRelayConfig(base)).toMatchObject({
      HTTP_PORT: 3070,
      RABBITMQ_RELAY_URL: [base.RABBITMQ_RELAY_URL],
      RELAY_ENABLED: true,
      RECONCILE_ENABLED: true,
      RELAY_SHARDS: 4,
      RELAY_MAX_HELD_SHARDS: 4,
      RELAY_BATCH_SIZE: 200,
      RELAY_SCAN_LIMIT: 1000,
      RELAY_POLL_INTERVAL_MS: 250,
      RELAY_CONFIRM_TIMEOUT_MS: 15_000,
      RELAY_BROKER_BACKOFF_BASE_MS: 500,
      RELAY_BROKER_BACKOFF_MAX_MS: 30_000,
      RELAY_ROW_BACKOFF_BASE_MS: 1000,
      RELAY_ROW_BACKOFF_MAX_MS: 300_000,
      RELAY_MAX_ATTEMPTS: 10,
      RELAY_MAX_MESSAGE_BYTES: 131_072,
      RECONCILE_INTERVAL_MS: 60_000,
      RECONCILE_UNCONSUMED_AFTER_SECONDS: 900,
      RECONCILE_MAX_REDRIVES: 3,
      RECONCILE_LOOKBACK_HOURS: 72,
      RECONCILE_BATCH_SIZE: 1000,
      RECONCILE_QUEUES: ['email.received', 'email.delivery.pending'],
      RECONCILE_START_POSITION: 'oldest',
    });
  });

  it('parses a cluster URL list and the role flags', () => {
    const config = loadRelayConfig({
      ...base,
      RABBITMQ_RELAY_URL: 'amqp://a:b@n1:5672/v, amqp://a:b@n2:5672/v',
      RELAY_ENABLED: 'false',
      RECONCILE_ENABLED: '0',
      RECONCILE_QUEUES: 'email.delivery.pending',
    });
    expect(config.RABBITMQ_RELAY_URL).toEqual(['amqp://a:b@n1:5672/v', 'amqp://a:b@n2:5672/v']);
    expect(config.RELAY_ENABLED).toBe(false);
    expect(config.RECONCILE_ENABLED).toBe(false);
    expect(config.RECONCILE_QUEUES).toEqual(['email.delivery.pending']);
  });

  it.each([
    ['RELAY_SHARDS', '0'],
    ['RELAY_SHARDS', '65'],
    ['RELAY_MAX_HELD_SHARDS', '0'],
    ['RELAY_BATCH_SIZE', '1001'],
    ['RELAY_SCAN_LIMIT', '10001'],
    ['RELAY_POLL_INTERVAL_MS', '49'],
    ['RELAY_POLL_INTERVAL_MS', '60001'],
    ['RELAY_CONFIRM_TIMEOUT_MS', '999'],
    ['RELAY_CONFIRM_TIMEOUT_MS', '120001'],
    ['RELAY_MAX_ATTEMPTS', '0'],
    ['RELAY_MAX_ATTEMPTS', '101'],
    ['RELAY_MAX_MESSAGE_BYTES', '4095'],
    ['RELAY_MAX_MESSAGE_BYTES', '262145'],
    ['RECONCILE_INTERVAL_MS', '999'],
    ['RECONCILE_INTERVAL_MS', '3600001'],
    ['RECONCILE_UNCONSUMED_AFTER_SECONDS', '299'],
    ['RECONCILE_MAX_REDRIVES', '21'],
    ['RECONCILE_MAX_REDRIVES', '-1'],
    ['RECONCILE_LOOKBACK_HOURS', '0'],
    ['RECONCILE_LOOKBACK_HOURS', '145'],
    ['RECONCILE_BATCH_SIZE', '10001'],
    ['RECONCILE_START_POSITION', 'newest'],
    ['RELAY_ENABLED', 'yes'],
  ])('refuses %s=%s', (key, value) => {
    const found = issues({ [key]: value });
    expect(found.some((issue) => issue.startsWith(`${key}:`))).toBe(true);
  });

  it('accepts the bounds', () => {
    expect(
      issues({
        RELAY_SHARDS: '64',
        RELAY_MAX_HELD_SHARDS: '64',
        RELAY_BATCH_SIZE: '1000',
        RELAY_SCAN_LIMIT: '10000',
        RECONCILE_UNCONSUMED_AFTER_SECONDS: '300',
        RECONCILE_MAX_REDRIVES: '0',
        RECONCILE_LOOKBACK_HOURS: '144',
      }),
    ).toEqual([]);
  });

  it('applies the cross-field rules', () => {
    expect(issues({ RELAY_BATCH_SIZE: '500', RELAY_SCAN_LIMIT: '400' })).toEqual([
      'RELAY_SCAN_LIMIT: must be at least RELAY_BATCH_SIZE',
    ]);
    expect(
      issues({ RELAY_BROKER_BACKOFF_BASE_MS: '2000', RELAY_BROKER_BACKOFF_MAX_MS: '1000' }),
    ).toEqual(['RELAY_BROKER_BACKOFF_MAX_MS: must be at least RELAY_BROKER_BACKOFF_BASE_MS']);
    expect(issues({ RELAY_ROW_BACKOFF_BASE_MS: '2000', RELAY_ROW_BACKOFF_MAX_MS: '1000' })).toEqual(
      ['RELAY_ROW_BACKOFF_MAX_MS: must be at least RELAY_ROW_BACKOFF_BASE_MS'],
    );
    expect(
      issues({ RECONCILE_LOOKBACK_HOURS: '1', RECONCILE_UNCONSUMED_AFTER_SECONDS: '3600' }),
    ).toEqual([
      'RECONCILE_UNCONSUMED_AFTER_SECONDS: must be below RECONCILE_LOOKBACK_HOURS (no row would ever be due)',
    ]);
  });

  it('accepts only work queues with a ledger consumer in RECONCILE_QUEUES', () => {
    for (const value of ['scan.auth', 'email.delivery.retry', 'email.dead-letter', 'nope']) {
      const found = issues({ RECONCILE_QUEUES: value });
      expect(found).toHaveLength(1);
      expect(found[0]).toMatch(/^RECONCILE_QUEUES: entry 1 /);
    }
    expect(issues({ RECONCILE_QUEUES: 'email.received,email.received' })).toEqual([
      'RECONCILE_QUEUES: entry 2 is listed twice',
    ]);
  });

  it('requires the relay URL and never echoes a value in an error', () => {
    const missing = issues({ RABBITMQ_RELAY_URL: '' });
    expect(missing.some((i) => i.startsWith('RABBITMQ_RELAY_URL:'))).toBe(true);
    const bad = issues({ RABBITMQ_RELAY_URL: `http://u:${SECRET}@h`, RELAY_SHARDS: SECRET });
    expect(bad.length).toBeGreaterThan(0);
    for (const issue of bad) expect(issue).not.toContain(SECRET);
  });

  it('ignores keys and *_FILE indirections of other services', () => {
    const config = loadRelayConfig({ ...base, REDIS_URL_FILE: '/nonexistent', OTHER: 'x' });
    expect(config).not.toHaveProperty('REDIS_URL');
  });
});
