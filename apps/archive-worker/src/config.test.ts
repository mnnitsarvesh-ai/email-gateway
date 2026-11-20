import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { generateExportSigningKeyPair } from '@email-gateway/archive';
import { describe, expect, it } from 'vitest';
import { daySeconds, hasRole, loadWorkerConfig } from './config';

const hex = () => randomBytes(32).toString('hex');
const signing = generateExportSigningKeyPair();

const base = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
  ARCHIVE_ROOT_KEY: hex(),
  ARCHIVE_SEARCH_URL: 'http://localhost:9200',
  RABBITMQ_ARCHIVE_URL: 'amqp://u:p@localhost:5672/email-gateway',
  ARCHIVE_EXPORT_SIGNING_KEY: signing.privateKey,
};

const issues = (env: Record<string, string | undefined>): string => {
  try {
    loadWorkerConfig(env);
    return '';
  } catch (error) {
    return (error as Error).message;
  }
};

describe('archive-worker config (§4.8)', () => {
  it('applies the §4.8 defaults', () => {
    const c = loadWorkerConfig(base);
    expect(c.HTTP_PORT).toBe(3060);
    expect(c.ARCHIVE_WORKER_ROLES).toEqual(['capture', 'index', 'lifecycle', 'ediscovery']);
    expect(c).toMatchObject({
      ARCHIVE_PREFETCH: 20,
      ARCHIVE_DB_TX_TIMEOUT_MS: 60_000,
      ARCHIVE_CAPTURE_CONCURRENCY: 4,
      ARCHIVE_CAPTURE_LEASE_SECONDS: 600,
      ARCHIVE_CAPTURE_RETRY_BASE_MS: 5_000,
      ARCHIVE_CAPTURE_RETRY_MAX_MS: 3_600_000,
      ARCHIVE_INTENT_MAX_AGE_DAYS: 25,
      ARCHIVE_OUTCOME_WINDOW_DAYS: 7,
      ARCHIVE_SWEEP_INTERVAL_MS: 15_000,
      ARCHIVE_SWEEP_BATCH_SIZE: 1_000,
      ARCHIVE_SWEEP_SAFETY_LAG_SECONDS: 120,
      ARCHIVE_POLICY_RECONCILE_SAFETY_LAG_SECONDS: 300,
      ARCHIVE_JOURNAL_SWEEP_START: 'now',
      ARCHIVE_POLICY_RECONCILE_START: 'oldest',
      ARCHIVE_S3_TIMEOUT_MS: 120_000,
      ARCHIVE_S3_PART_SIZE_BYTES: 8 * 1_048_576,
      ARCHIVE_CHUNK_BYTES: 65_536,
      ARCHIVE_PREVIEW_PART_MAX_BYTES: 1_048_576,
      ARCHIVE_SETTINGS_CACHE_TTL_MS: 30_000,
      ARCHIVE_KEY_CACHE_TTL_MS: 60_000,
      ARCHIVE_INDEX_BATCH_SIZE: 500,
      ARCHIVE_INDEX_INTERVAL_MS: 2_000,
      ARCHIVE_INDEX_SHARDS: 1,
      ARCHIVE_INDEX_REPLICAS: 0,
      ARCHIVE_RECONCILE_INTERVAL_MS: 600_000,
      ARCHIVE_RECONCILE_RECENT_DAYS: 3,
      ARCHIVE_LIFECYCLE_INTERVAL_MS: 60_000,
      ARCHIVE_LIFECYCLE_BATCH_SIZE: 200,
      ARCHIVE_HOLD_EXTENSION_DAYS: 30,
      ARCHIVE_REVIEW_EXTENSION_DAYS: 30,
      ARCHIVE_DISPOSAL_MAX_ATTEMPTS: 20,
      ARCHIVE_GOVERNANCE_BYPASS_ORPHANS: true,
      ARCHIVE_REPLICA_TARGETS: [],
      ARCHIVE_EXPORT_SIGNING_KEY_ID: 'es1',
      ARCHIVE_EXPORT_MAX_ITEMS: 10_000,
      ARCHIVE_EXPORT_MAX_BYTES: 2_147_483_648,
      ARCHIVE_EXPORT_TTL_HOURS: 168,
      ARCHIVE_EXPORT_CONCURRENCY: 1,
      ARCHIVE_CASE_SEARCH_MAX_HITS: 100_000,
      ARCHIVE_CASE_SEARCH_DEADLINE_MS: 600_000,
      ARCHIVE_OBJECT_LOCK: 'auto',
      ARCHIVE_SEARCH_INDEX_PREFIX: 'eg-archive',
    });
    expect(daySeconds(c)).toBe(86_400);
  });

  it('validates roles like WEBHOOK_WORKER_ROLES', () => {
    expect(
      loadWorkerConfig({ ...base, ARCHIVE_WORKER_ROLES: 'lifecycle, ediscovery' })
        .ARCHIVE_WORKER_ROLES,
    ).toEqual(['lifecycle', 'ediscovery']);
    expect(issues({ ...base, ARCHIVE_WORKER_ROLES: 'capture,capture' })).toContain(
      'lists a role twice',
    );
    expect(issues({ ...base, ARCHIVE_WORKER_ROLES: 'capture,search' })).toContain(
      'ARCHIVE_WORKER_ROLES',
    );
    // An empty value is dropped by loadConfig (the default applies), a list of commas is refused.
    expect(issues({ ...base, ARCHIVE_WORKER_ROLES: ',' })).toContain('at least one');
    const c = loadWorkerConfig({ ...base, ARCHIVE_WORKER_ROLES: 'index' });
    expect(hasRole(c, 'index')).toBe(true);
    expect(hasRole(c, 'capture')).toBe(false);
  });

  it('requires the role dependencies: broker for capture, search for index/ediscovery, the signing key for ediscovery', () => {
    expect(issues({ ...base, RABBITMQ_ARCHIVE_URL: undefined })).toContain('RABBITMQ_ARCHIVE_URL');
    expect(
      issues({
        ...base,
        RABBITMQ_ARCHIVE_URL: undefined,
        ARCHIVE_WORKER_ROLES: 'index,lifecycle,ediscovery',
      }),
    ).toBe('');
    expect(issues({ ...base, ARCHIVE_SEARCH_URL: undefined })).toContain('ARCHIVE_SEARCH_URL');
    expect(
      issues({ ...base, ARCHIVE_SEARCH_URL: undefined, ARCHIVE_WORKER_ROLES: 'capture,lifecycle' }),
    ).toBe('');
    expect(issues({ ...base, ARCHIVE_EXPORT_SIGNING_KEY: undefined })).toContain(
      'ARCHIVE_EXPORT_SIGNING_KEY',
    );
    expect(
      issues({
        ...base,
        ARCHIVE_EXPORT_SIGNING_KEY: undefined,
        ARCHIVE_WORKER_ROLES: 'capture,index',
      }),
    ).toBe('');
  });

  it('enforces bounds and pairs; messages name keys, never values', () => {
    const key = hex();
    expect(issues({ ...base, ARCHIVE_CAPTURE_CONCURRENCY: '33' })).toContain(
      'ARCHIVE_CAPTURE_CONCURRENCY',
    );
    expect(issues({ ...base, ARCHIVE_S3_PART_SIZE_BYTES: String(4 * 1_048_576) })).toContain(
      'ARCHIVE_S3_PART_SIZE_BYTES',
    );
    expect(issues({ ...base, ARCHIVE_CHUNK_BYTES: '1024' })).toContain('ARCHIVE_CHUNK_BYTES');
    expect(issues({ ...base, ARCHIVE_INTENT_MAX_AGE_DAYS: '31' })).toContain(
      'ARCHIVE_INTENT_MAX_AGE_DAYS',
    );
    expect(issues({ ...base, ARCHIVE_SWEEP_SAFETY_LAG_SECONDS: '10' })).toContain(
      'ARCHIVE_SWEEP_SAFETY_LAG_SECONDS',
    );
    expect(
      issues({
        ...base,
        ARCHIVE_CAPTURE_RETRY_BASE_MS: '60000',
        ARCHIVE_CAPTURE_RETRY_MAX_MS: '5000',
      }),
    ).toContain('ARCHIVE_CAPTURE_RETRY_BASE_MS');
    const message = issues({ ...base, ARCHIVE_ROOT_KEY_PREVIOUS: key });
    expect(message).toContain('ARCHIVE_ROOT_KEY_PREVIOUS');
    expect(message).not.toContain(key);
    expect(issues({ ...base, ARCHIVE_ROOT_KEY: 'zz' })).not.toContain('zz"');
    expect(issues({ ...base, ARCHIVE_JOURNAL_SWEEP_START: 'yesterday' })).toContain(
      'ARCHIVE_JOURNAL_SWEEP_START',
    );
  });

  it('parses replica targets (bucket or bucket@region) and refuses the archive bucket itself', () => {
    const c = loadWorkerConfig({
      ...base,
      ARCHIVE_REPLICA_TARGETS: 'gateway-archive-replica, dr-bucket@eu-west-1',
    });
    expect(c.ARCHIVE_REPLICA_TARGETS).toEqual([
      { bucket: 'gateway-archive-replica', region: null },
      { bucket: 'dr-bucket', region: 'eu-west-1' },
    ]);
    expect(issues({ ...base, ARCHIVE_REPLICA_TARGETS: 'Bad_Bucket' })).toContain(
      'ARCHIVE_REPLICA_TARGETS',
    );
    expect(issues({ ...base, ARCHIVE_REPLICA_TARGETS: 'test-archive' })).toContain(
      'must not list the archive bucket',
    );
  });

  it('accepts ARCHIVE_TEST_DAY_SECONDS only in local/ci; NODE_ENV=production without APP_ENV is production', () => {
    expect(
      daySeconds(loadWorkerConfig({ ...base, APP_ENV: 'ci', ARCHIVE_TEST_DAY_SECONDS: '2' })),
    ).toBe(2);
    expect(issues({ ...base, APP_ENV: 'staging', ARCHIVE_TEST_DAY_SECONDS: '2' })).toContain(
      'ARCHIVE_TEST_DAY_SECONDS',
    );
    expect(issues({ ...base, NODE_ENV: 'production', ARCHIVE_TEST_DAY_SECONDS: '2' })).toContain(
      'ARCHIVE_TEST_DAY_SECONDS',
    );
  });

  it('refuses search URLs with embedded credentials and unpaired search credentials', () => {
    expect(issues({ ...base, ARCHIVE_SEARCH_URL: 'http://u:p@localhost:9200' })).toContain(
      'ARCHIVE_SEARCH_URL',
    );
    expect(issues({ ...base, ARCHIVE_SEARCH_USERNAME: 'eg-archive-worker' })).toContain(
      'ARCHIVE_SEARCH_PASSWORD',
    );
  });

  it('every worker key of §4.8 is in .env.example (the Compose and Kubernetes source of truth)', () => {
    const example = readFileSync(resolve(__dirname, '../../../.env.example'), 'utf8');
    for (const key of [
      'ARCHIVE_WORKER_ROLES',
      'ARCHIVE_PREFETCH',
      'ARCHIVE_DB_TX_TIMEOUT_MS',
      'ARCHIVE_CAPTURE_CONCURRENCY',
      'ARCHIVE_CAPTURE_LEASE_SECONDS',
      'ARCHIVE_CAPTURE_RETRY_BASE_MS',
      'ARCHIVE_CAPTURE_RETRY_MAX_MS',
      'ARCHIVE_INTENT_MAX_AGE_DAYS',
      'ARCHIVE_OUTCOME_WINDOW_DAYS',
      'ARCHIVE_SWEEP_INTERVAL_MS',
      'ARCHIVE_SWEEP_BATCH_SIZE',
      'ARCHIVE_SWEEP_SAFETY_LAG_SECONDS',
      'ARCHIVE_POLICY_RECONCILE_SAFETY_LAG_SECONDS',
      'ARCHIVE_JOURNAL_SWEEP_START',
      'ARCHIVE_POLICY_RECONCILE_START',
      'ARCHIVE_S3_TIMEOUT_MS',
      'ARCHIVE_S3_PART_SIZE_BYTES',
      'ARCHIVE_CHUNK_BYTES',
      'ARCHIVE_PREVIEW_PART_MAX_BYTES',
      'ARCHIVE_SETTINGS_CACHE_TTL_MS',
      'ARCHIVE_KEY_CACHE_TTL_MS',
      'ARCHIVE_INDEX_BATCH_SIZE',
      'ARCHIVE_INDEX_INTERVAL_MS',
      'ARCHIVE_INDEX_SHARDS',
      'ARCHIVE_INDEX_REPLICAS',
      'ARCHIVE_RECONCILE_INTERVAL_MS',
      'ARCHIVE_RECONCILE_RECENT_DAYS',
      'ARCHIVE_LIFECYCLE_INTERVAL_MS',
      'ARCHIVE_LIFECYCLE_BATCH_SIZE',
      'ARCHIVE_HOLD_EXTENSION_DAYS',
      'ARCHIVE_REVIEW_EXTENSION_DAYS',
      'ARCHIVE_DISPOSAL_MAX_ATTEMPTS',
      'ARCHIVE_GOVERNANCE_BYPASS_ORPHANS',
      'ARCHIVE_REPLICA_TARGETS',
      'ARCHIVE_EXPORT_SIGNING_KEY',
      'ARCHIVE_EXPORT_SIGNING_KEY_ID',
      'ARCHIVE_EXPORT_MAX_ITEMS',
      'ARCHIVE_EXPORT_MAX_BYTES',
      'ARCHIVE_EXPORT_TTL_HOURS',
      'ARCHIVE_EXPORT_CONCURRENCY',
      'ARCHIVE_CASE_SEARCH_MAX_HITS',
      'ARCHIVE_CASE_SEARCH_DEADLINE_MS',
      'RABBITMQ_ARCHIVE_URL',
    ]) {
      expect(example, key).toMatch(new RegExp(`^${key}=`, 'm'));
    }
  });
});

describe('journal intake and dedupe keys (step 8.6 §4.4)', () => {
  it('applies the defaults', () => {
    expect(loadWorkerConfig(base)).toMatchObject({
      JOURNAL_INTAKE_HEALTH_INTERVAL_MS: 60_000,
      JOURNAL_INTAKE_ALERT_MIN_INTERVAL_HOURS: 24,
      ARCHIVE_DEDUPE_WINDOW_HOURS: 72,
      ARCHIVE_MAX_CONTENT_VARIANTS: 4,
      ARCHIVE_MAX_MERGED_COPIES: 8,
    });
  });

  it('bounds the keys and keeps variants ≤ merged copies (names keys, never values)', () => {
    expect(issues({ ...base, ARCHIVE_MAX_MERGED_COPIES: '9' })).toContain(
      'ARCHIVE_MAX_MERGED_COPIES',
    );
    expect(issues({ ...base, JOURNAL_INTAKE_HEALTH_INTERVAL_MS: '10' })).toContain(
      'JOURNAL_INTAKE_HEALTH_INTERVAL_MS',
    );
    expect(
      issues({ ...base, ARCHIVE_MAX_CONTENT_VARIANTS: '6', ARCHIVE_MAX_MERGED_COPIES: '4' }),
    ).toContain('ARCHIVE_MAX_CONTENT_VARIANTS');
    expect(
      loadWorkerConfig({ ...base, ARCHIVE_DEDUPE_WINDOW_HOURS: '1' }).ARCHIVE_DEDUPE_WINDOW_HOURS,
    ).toBe(1);
  });
});
