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
  URL_TOKEN_KEY_CURRENT: 'ab'.repeat(32),
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

describe('policy-engine config: quarantine (step 5.3 §5, Q19, Q22, Q23, Q28)', () => {
  it('applies the §5 defaults', () => {
    expect(loadWorkerConfig(base)).toMatchObject({
      POLICY_ENGINE_ROLES: ['evaluate', 'quarantine'],
      QUARANTINE_MAX_HOLD_DAYS: 60,
      QUARANTINE_MAX_REVIEW_DAYS: 13,
      LIFECYCLE_DEADLINE_QUARANTINED_HOURS: 2160,
      LIFECYCLE_DEADLINE_HELD_FOR_REVIEW_HOURS: 336,
      QUARANTINE_RELEASE_PREFETCH: 4,
      QUARANTINE_DB_TX_TIMEOUT_MS: 120_000,
      QUARANTINE_SWEEP_INTERVAL_MS: 60_000,
      QUARANTINE_SWEEP_BATCH_SIZE: 200,
      QUARANTINE_ENTRY_RETENTION_DAYS: 186,
      QUARANTINE_DIGEST_MAX_USERS_PER_RUN: 5_000,
      QUARANTINE_RELEASE_MAX_VERDICT_AGE_HOURS: 72,
      QUARANTINE_RELEASE_SIGNATURE_MAX_LAG_HOURS: 24,
      POLICY_BANNER_MAX_PART_BYTES: 1_048_576,
      POLICY_URL_REWRITE_ENABLED: true,
      URL_TOKEN_KEY_CURRENT_ID: 1,
      URL_CLICK_BASE_URL: 'http://localhost:3080',
      URL_TOKEN_DEFAULT_EXPIRY_DAYS: 30,
      URL_TOKEN_MAX_EXPIRY_DAYS: 90,
      URL_REWRITE_MAX_MESSAGE_BYTES: 26_214_400,
      URL_REWRITE_MAX_PART_BYTES: 5_242_880,
      URL_REWRITE_DKIM_SIGNED: 'rewrite',
    });
  });

  it.each([
    ['evaluate', ['evaluate']],
    ['quarantine', ['quarantine']],
    [' quarantine , evaluate ', ['quarantine', 'evaluate']],
    ['evaluate,evaluate', ['evaluate']],
  ])('POLICY_ENGINE_ROLES=%j → %j', (value, roles) => {
    expect(loadWorkerConfig({ ...base, POLICY_ENGINE_ROLES: value }).POLICY_ENGINE_ROLES).toEqual(
      roles,
    );
  });

  it.each([',', ' , ', 'sweeper', 'evaluate,deliver'])(
    'refuses POLICY_ENGINE_ROLES=%j',
    (value) => {
      expect(issues({ POLICY_ENGINE_ROLES: value }).join()).toContain('POLICY_ENGINE_ROLES');
    },
  );

  it.each([
    ['QUARANTINE_MAX_HOLD_DAYS', '7', '80', '6', '81'],
    ['QUARANTINE_MAX_REVIEW_DAYS', '1', '13', '0', '14'],
    ['QUARANTINE_RELEASE_PREFETCH', '1', '32', '0', '33'],
    ['QUARANTINE_DB_TX_TIMEOUT_MS', '120000', '600000', '119999', '600001'],
    ['QUARANTINE_SWEEP_INTERVAL_MS', '10000', '3600000', '9999', '3600001'],
    ['QUARANTINE_SWEEP_BATCH_SIZE', '10', '2000', '9', '2001'],
    ['QUARANTINE_ENTRY_RETENTION_DAYS', '186', '3650', '185', '3651'],
    ['QUARANTINE_DIGEST_MAX_USERS_PER_RUN', '100', '100000', '99', '100001'],
    ['QUARANTINE_RELEASE_MAX_VERDICT_AGE_HOURS', '1', '720', '0', '721'],
    ['QUARANTINE_RELEASE_SIGNATURE_MAX_LAG_HOURS', '1', '168', '0', '169'],
    ['POLICY_BANNER_MAX_PART_BYTES', '65536', '8388608', '65535', '8388609'],
  ])('bounds %s to [%s, %s]', (key, min, max, below, above) => {
    // The lifecycle deadlines are raised so that only the bound under test can fail.
    const deadlines = {
      LIFECYCLE_DEADLINE_QUARANTINED_HOURS: '87600',
      LIFECYCLE_DEADLINE_HELD_FOR_REVIEW_HOURS: '87600',
    };
    expect(issues({ ...deadlines, [key]: min })).toEqual([]);
    expect(issues({ ...deadlines, [key]: max })).toEqual([]);
    expect(issues({ ...deadlines, [key]: below }).join()).toContain(key);
    expect(issues({ ...deadlines, [key]: above }).join()).toContain(key);
  });

  it('keeps the hold and review bounds below the lifecycle deadlines (Q19)', () => {
    // 60 days × 24 = 1440 h must be below the quarantined deadline.
    expect(issues({ LIFECYCLE_DEADLINE_QUARANTINED_HOURS: '1441' })).toEqual([]);
    expect(issues({ LIFECYCLE_DEADLINE_QUARANTINED_HOURS: '1440' }).join()).toContain(
      'QUARANTINE_MAX_HOLD_DAYS',
    );
    expect(
      issues({ QUARANTINE_MAX_HOLD_DAYS: '30', LIFECYCLE_DEADLINE_QUARANTINED_HOURS: '1440' }),
    ).toEqual([]);
    // 13 days × 24 = 312 h must be below the held_for_review deadline (336 by default).
    expect(issues({ LIFECYCLE_DEADLINE_HELD_FOR_REVIEW_HOURS: '312' }).join()).toContain(
      'QUARANTINE_MAX_REVIEW_DAYS',
    );
    expect(
      issues({ QUARANTINE_MAX_REVIEW_DAYS: '7', LIFECYCLE_DEADLINE_HELD_FOR_REVIEW_HOURS: '312' }),
    ).toEqual([]);
  });

  it('requires the sign-only click-token key while policy URL rewriting is enabled', () => {
    const { URL_TOKEN_KEY_CURRENT: _key, ...rest } = base;
    expect(() => loadWorkerConfig(rest)).toThrow(ConfigValidationError);
    expect(loadWorkerConfig({ ...rest, POLICY_URL_REWRITE_ENABLED: 'false' })).toMatchObject({
      POLICY_URL_REWRITE_ENABLED: false,
    });
    expect(issues({ URL_TOKEN_KEY_CURRENT: 'xyz' }).join()).toContain('URL_TOKEN_KEY_CURRENT');
    // The previous key is never a policy-engine key (sign only).
    expect(
      loadWorkerConfig({ ...base, URL_TOKEN_KEY_PREVIOUS: 'cd'.repeat(32) }),
    ).not.toHaveProperty('URL_TOKEN_KEY_PREVIOUS');
  });

  it('checks the URL rewrite keys', () => {
    expect(issues({ URL_TOKEN_DEFAULT_EXPIRY_DAYS: '91' }).join()).toContain(
      'URL_TOKEN_DEFAULT_EXPIRY_DAYS',
    );
    expect(
      issues({ URL_REWRITE_MAX_PART_BYTES: '2000', URL_REWRITE_MAX_MESSAGE_BYTES: '1000' }).join(),
    ).toContain('URL_REWRITE_MAX_PART_BYTES');
    expect(issues({ URL_CLICK_BASE_URL: 'https://click.example/?q=1' }).join()).toContain(
      'URL_CLICK_BASE_URL',
    );
    expect(
      issues({ APP_ENV: 'production', URL_CLICK_BASE_URL: 'http://click.example' }).join(),
    ).toContain('URL_CLICK_BASE_URL');
    expect(issues({ APP_ENV: 'production', URL_CLICK_BASE_URL: 'https://click.example' })).toEqual(
      [],
    );
    expect(issues({ URL_REWRITE_DKIM_SIGNED: 'maybe' }).join()).toContain(
      'URL_REWRITE_DKIM_SIGNED',
    );
  });
});
