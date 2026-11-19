import { describe, expect, it } from 'vitest';
import { loadWorkerConfig } from '../config';

const base = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  REDIS_URL: 'redis://localhost:6379',
  RABBITMQ_DELIVERY_WORKER_URL: 'amqp://user:pass@localhost:5672/email-gateway',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
  GATEWAY_TRACE_SECRET: 'test-trace-secret-0123456789abcdef0123456789',
};

describe('PROVIDER_ROUTE_TOKEN_KEY (step 8.2 D9)', () => {
  it('is optional and validated as 64 hex characters', () => {
    expect(loadWorkerConfig(base).PROVIDER_ROUTE_TOKEN_KEY).toBeUndefined();
    const key = 'ab'.repeat(32);
    expect(
      loadWorkerConfig({ ...base, PROVIDER_ROUTE_TOKEN_KEY: key }).PROVIDER_ROUTE_TOKEN_KEY,
    ).toBe(key);
    expect(() => loadWorkerConfig({ ...base, PROVIDER_ROUTE_TOKEN_KEY: 'ab'.repeat(31) })).toThrow(
      /PROVIDER_ROUTE_TOKEN_KEY/,
    );
    expect(() =>
      loadWorkerConfig({ ...base, PROVIDER_ROUTE_TOKEN_KEY: 'zz'.repeat(32) }),
    ).toThrow();
  });
});
