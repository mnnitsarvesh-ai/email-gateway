import { ConfigValidationError } from '@email-gateway/config';
import { describe, expect, it } from 'vitest';
import { loadWorkerConfig } from './config';

const base = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  REDIS_URL: 'redis://localhost:6379',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
  RABBITMQ_POLICY_ENGINE_URL: 'amqp://pe:pe-secret@localhost:5672/email-gateway',
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

describe('policy-engine config (step 5.2 §5)', () => {
  it('applies the §5 defaults', () => {
    expect(loadWorkerConfig(base)).toMatchObject({
      HTTP_PORT: 3030,
      RABBITMQ_POLICY_ENGINE_URL: ['amqp://pe:pe-secret@localhost:5672/email-gateway'],
      POLICY_PLATFORM_DEFAULT: 'pol-default/1',
      POLICY_EVALUATE_PREFETCH: 8,
      POLICY_DB_TX_TIMEOUT_MS: 120_000,
      POLICY_SNAPSHOT_CACHE_MAX_ENTRIES: 1000,
      POLICY_COPY_MAX_MESSAGE_BYTES: 26_214_400,
      POLICY_COPY_MAX_HEADER_BYTES: 262_144,
    });
  });

  it('requires the broker URL of eg-policy-engine', () => {
    const { RABBITMQ_POLICY_ENGINE_URL: _omit, ...rest } = base;
    expect(() => loadWorkerConfig(rest)).toThrow(ConfigValidationError);
  });

  it.each([
    ['POLICY_EVALUATE_PREFETCH', '1', '64', '0', '65'],
    ['POLICY_DB_TX_TIMEOUT_MS', '120000', '600000', '119999', '600001'],
    ['POLICY_SNAPSHOT_CACHE_MAX_ENTRIES', '10', '100000', '9', '100001'],
    ['POLICY_COPY_MAX_MESSAGE_BYTES', '1048576', '52428800', '1048575', '52428801'],
    ['POLICY_COPY_MAX_HEADER_BYTES', '16384', '1048576', '16383', '1048577'],
  ])('bounds %s to [%s, %s]', (key, min, max, below, above) => {
    expect(issues({ [key]: min })).toEqual([]);
    expect(issues({ [key]: max })).toEqual([]);
    expect(issues({ [key]: below }).join()).toContain(key);
    expect(issues({ [key]: above }).join()).toContain(key);
  });

  it('accepts only a known platform default', () => {
    expect(issues({ POLICY_PLATFORM_DEFAULT: 'pol-default/1' })).toEqual([]);
    expect(issues({ POLICY_PLATFORM_DEFAULT: 'pol-default/9' }).join()).toContain(
      'POLICY_PLATFORM_DEFAULT',
    );
  });

  it('ignores keys of other services (shared .env)', () => {
    expect(
      issues({ DELIVERY_DEV_PASSTHROUGH_ENABLED: 'true', OTHER_SECRET_FILE: '/nope' }),
    ).toEqual([]);
  });
});
