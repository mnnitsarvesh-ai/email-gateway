import { ConfigValidationError } from '@email-gateway/config';
import { describe, expect, it } from 'vitest';
import { DEV_PASSTHROUGH_REFUSAL, loadWorkerConfig } from './config';

const base = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  RABBITMQ_DELIVERY_WORKER_URL: 'amqp://dw:dw-secret@localhost:5672/email-gateway',
  REDIS_URL: 'redis://localhost:6379',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
  GATEWAY_TRACE_SECRET: 'x'.repeat(32),
};

const issues = (env: Record<string, string>): string[] => {
  try {
    loadWorkerConfig({ ...base, ...env });
  } catch (err) {
    if (err instanceof ConfigValidationError) return err.issues;
    throw err;
  }
  return [];
};

describe('delivery-worker config', () => {
  it('applies the .env.example defaults of design §5', () => {
    const config = loadWorkerConfig(base);
    expect(config).toMatchObject({
      HTTP_PORT: 3040,
      DELIVERY_REINJECT_HOST: 'postfix-outbound',
      DELIVERY_REINJECT_INBOUND_PORT: 10026,
      DELIVERY_REINJECT_OUTBOUND_PORT: 10027,
      DELIVERY_REINJECT_HELO: 'delivery.gateway.local',
      DELIVERY_REINJECT_CONCURRENCY: 8,
      DELIVERY_BATCH_MAX_RECIPIENTS: 100,
      DELIVERY_REINJECT_COMMAND_TIMEOUT_MS: 60_000,
      DELIVERY_REINJECT_DATA_TIMEOUT_MS: 600_000,
      DELIVERY_REINJECT_LEASE_SECONDS: 900,
      DELIVERY_REINJECT_RETRY_BASE_SECONDS: 30,
      DELIVERY_REINJECT_RETRY_MAX_SECONDS: 900,
      DELIVERY_REINJECT_MAX_AGE_SECONDS: 432_000,
      RABBITMQ_DELIVERY_WORKER_URL: ['amqp://dw:dw-secret@localhost:5672/email-gateway'],
      DELIVERY_APPROVAL_PREFETCH: 4,
      DELIVERY_POLL_INTERVAL_MS: 1000,
      DELIVERY_OUTBOX_POLL_INTERVAL_MS: 1000,
      DELIVERY_OUTBOX_SAFETY_LAG_MS: 120_000,
      DELIVERY_OUTBOX_BATCH_SIZE: 500,
      DELIVERY_APPROVALS_ENABLED: true,
      DELIVERY_REINJECTION_ENABLED: true,
      DELIVERY_STATUS_LOG_ENABLED: true,
      DELIVERY_DEV_PASSTHROUGH_ENABLED: false,
      DELIVERY_STATUS_LOG_PATH: '/var/log/postfix-outbound/maillog',
      DELIVERY_STATUS_LOG_SOURCE_ID: 'out.gateway.local',
      DELIVERY_STATUS_LOG_POLL_MS: 500,
      DELIVERY_STATUS_UNMATCHED_RETRY_SECONDS: 60,
      DELIVERY_STATUS_STALE_AFTER_SECONDS: 518_400,
      DELIVERY_RECONCILE_INTERVAL_MS: 30_000,
      DELIVERY_RATE_TENANT_RCPT_PER_MINUTE: 600,
      DELIVERY_RATE_TENANT_DOMAIN_RCPT_PER_MINUTE: 300,
      DELIVERY_RATE_DESTINATION_DOMAIN_RCPT_PER_MINUTE: 6000,
      ROUTING_MAX_RECEIVED_HEADERS: 25,
      ROUTING_MAX_GATEWAY_PASSES: 4,
      GATEWAY_TRACE_ID: 'gw-local',
      POSTFIX_OUTBOUND_MYHOSTNAME: 'out.gateway.local',
      INGEST_HEADER_MAX_BYTES: 65_536,
    });
  });

  it('applies the step 4.2 §6.2 database defaults: no socket timeout, a 120 s transaction budget', () => {
    expect(loadWorkerConfig(base)).toMatchObject({
      DATABASE_SOCKET_TIMEOUT_SECONDS: 0,
      DELIVERY_DB_TX_TIMEOUT_MS: 120_000,
      DELIVERY_REINJECT_MAX_ATTEMPTS: 10,
    });
  });

  it('requires the transaction budget to outlast a configured socket timeout', () => {
    expect(
      loadWorkerConfig({
        ...base,
        DATABASE_SOCKET_TIMEOUT_SECONDS: '30',
        DELIVERY_DB_TX_TIMEOUT_MS: '90000',
      }),
    ).toMatchObject({ DATABASE_SOCKET_TIMEOUT_SECONDS: 30, DELIVERY_DB_TX_TIMEOUT_MS: 90_000 });
    expect(
      issues({
        DATABASE_SOCKET_TIMEOUT_SECONDS: '120',
        DELIVERY_DB_TX_TIMEOUT_MS: '120000',
      }).join(),
    ).toContain('DELIVERY_DB_TX_TIMEOUT_MS');
  });

  it.each([
    ['DELIVERY_DB_TX_TIMEOUT_MS', '59999'],
    ['DELIVERY_DB_TX_TIMEOUT_MS', '900001'],
    ['DATABASE_SOCKET_TIMEOUT_SECONDS', '-1'],
    ['DATABASE_SOCKET_TIMEOUT_SECONDS', '3601'],
    ['DELIVERY_REINJECT_MAX_ATTEMPTS', '0'],
  ])('refuses %s=%s', (key, value) => {
    expect(issues({ [key]: value }).join()).toContain(key);
  });

  it('accepts the dev pass-through in local and ci', () => {
    for (const APP_ENV of ['local', 'ci']) {
      const config = loadWorkerConfig({
        ...base,
        APP_ENV,
        DELIVERY_DEV_PASSTHROUGH_ENABLED: 'true',
      });
      expect(config.DELIVERY_DEV_PASSTHROUGH_ENABLED).toBe(true);
    }
  });

  it.each(['staging', 'production'])('refuses the dev pass-through with APP_ENV=%s', (APP_ENV) => {
    expect(issues({ APP_ENV, DELIVERY_DEV_PASSTHROUGH_ENABLED: 'true' })).toEqual([
      `DELIVERY_DEV_PASSTHROUGH_ENABLED: ${DEV_PASSTHROUGH_REFUSAL}`,
    ]);
    expect(issues({ APP_ENV, DELIVERY_DEV_PASSTHROUGH_ENABLED: 'false' })).toEqual([]);
  });

  it('refuses the pass-through without the approvals role', () => {
    expect(
      issues({ DELIVERY_DEV_PASSTHROUGH_ENABLED: 'true', DELIVERY_APPROVALS_ENABLED: 'false' }),
    ).toEqual([expect.stringContaining('requires DELIVERY_APPROVALS_ENABLED=true')]);
  });

  it('parses the role flags', () => {
    const config = loadWorkerConfig({
      ...base,
      DELIVERY_APPROVALS_ENABLED: 'false',
      DELIVERY_REINJECTION_ENABLED: '0',
      DELIVERY_STATUS_LOG_ENABLED: '1',
    });
    expect(config.DELIVERY_APPROVALS_ENABLED).toBe(false);
    expect(config.DELIVERY_REINJECTION_ENABLED).toBe(false);
    expect(config.DELIVERY_STATUS_LOG_ENABLED).toBe(true);
    expect(issues({ DELIVERY_STATUS_LOG_ENABLED: 'yes' })).toEqual([
      expect.stringContaining('DELIVERY_STATUS_LOG_ENABLED'),
    ]);
  });

  it('refuses a short trace secret, a missing secret and secrets are never echoed', () => {
    expect(issues({ GATEWAY_TRACE_SECRET: 'short-secret-value' })).toEqual([
      expect.stringContaining('GATEWAY_TRACE_SECRET'),
    ]);
    expect(issues({ GATEWAY_TRACE_SECRET: 'short-secret-value' }).join(' ')).not.toContain(
      'short-secret-value',
    );
    const { GATEWAY_TRACE_SECRET: _omit, ...withoutSecret } = base;
    expect(() => loadWorkerConfig(withoutSecret)).toThrow(/GATEWAY_TRACE_SECRET/);
  });

  it('refuses invalid values', () => {
    expect(issues({ DELIVERY_BATCH_MAX_RECIPIENTS: '101' })).toHaveLength(1);
    expect(issues({ DELIVERY_BATCH_MAX_RECIPIENTS: '0' })).toHaveLength(1);
    expect(issues({ DELIVERY_REINJECT_CONCURRENCY: '0' })).toHaveLength(1);
    expect(issues({ DELIVERY_REINJECT_INBOUND_PORT: '70000' })).toHaveLength(1);
    expect(issues({ DELIVERY_REINJECT_HELO: 'not a host' })).toHaveLength(1);
    expect(issues({ DELIVERY_STATUS_LOG_SOURCE_ID: 'x'.repeat(49) })).toHaveLength(1);
    expect(issues({ DELIVERY_STATUS_LOG_SOURCE_ID: 'out gateway' })).toHaveLength(1);
    expect(issues({ GATEWAY_TRACE_ID: 'bad id' })).toHaveLength(1);
    expect(issues({ ROUTING_MAX_GATEWAY_PASSES: '0' })).toHaveLength(1);
    expect(issues({ INGEST_HEADER_MAX_BYTES: '100' })).toHaveLength(1);
    expect(issues({ REDIS_URL: 'http://redis' })).toHaveLength(1);
  });

  it('refuses a retry maximum below the base and identical reinjection ports', () => {
    expect(
      issues({
        DELIVERY_REINJECT_RETRY_BASE_SECONDS: '60',
        DELIVERY_REINJECT_RETRY_MAX_SECONDS: '30',
      }),
    ).toEqual([expect.stringContaining('DELIVERY_REINJECT_RETRY_MAX_SECONDS')]);
    expect(
      issues({ DELIVERY_REINJECT_INBOUND_PORT: '2626', DELIVERY_REINJECT_OUTBOUND_PORT: '2626' }),
    ).toEqual([expect.stringContaining('DELIVERY_REINJECT_OUTBOUND_PORT')]);
  });

  it('reads its own RabbitMQ role URL list and approval prefetch (step 3.2 Q10, Q13)', () => {
    expect(
      loadWorkerConfig({
        ...base,
        RABBITMQ_DELIVERY_WORKER_URL: 'amqp://a:b@rmq1:5672/v,amqp://a:b@rmq2:5672/v',
        DELIVERY_APPROVAL_PREFETCH: '64',
      }),
    ).toMatchObject({
      RABBITMQ_DELIVERY_WORKER_URL: ['amqp://a:b@rmq1:5672/v', 'amqp://a:b@rmq2:5672/v'],
      DELIVERY_APPROVAL_PREFETCH: 64,
    });
    expect(issues({ DELIVERY_APPROVAL_PREFETCH: '0' })).toEqual([
      expect.stringContaining('DELIVERY_APPROVAL_PREFETCH'),
    ]);
    expect(issues({ DELIVERY_APPROVAL_PREFETCH: '65' })).toEqual([
      expect.stringContaining('DELIVERY_APPROVAL_PREFETCH'),
    ]);
    const bad = issues({ RABBITMQ_DELIVERY_WORKER_URL: 'redis://dw:dw-secret@localhost' });
    expect(bad).toEqual([expect.stringContaining('RABBITMQ_DELIVERY_WORKER_URL')]);
    expect(bad.join(' ')).not.toContain('dw-secret');
    const { RABBITMQ_DELIVERY_WORKER_URL: _omit, ...withoutUrl } = base;
    expect(() => loadWorkerConfig(withoutUrl)).toThrow(/RABBITMQ_DELIVERY_WORKER_URL/);
    // The pre-3.2 administrator URL is not read any more.
    expect(
      Object.keys(loadWorkerConfig({ ...base, RABBITMQ_URL: 'amqp://admin:x@rabbitmq:5672' })),
    ).not.toContain('RABBITMQ_URL');
  });

  it('ignores foreign *_FILE keys of other services', () => {
    expect(() =>
      loadWorkerConfig({ ...base, SOME_OTHER_SERVICE_KEY_FILE: '/does/not/exist' }),
    ).not.toThrow();
  });
});
