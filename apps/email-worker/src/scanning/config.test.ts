import {
  ATTACHMENT_PLATFORM_DEFAULTS,
  RSPAMD_PLATFORM_DEFAULTS,
} from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { loadWorkerConfig } from '../config';
import {
  attachmentPlatformFromConfig,
  attachmentScalingWarnings,
  consumerEngines,
  engineQueueMaxAttempts,
  minimumRoundDeadlineSeconds,
  rspamdPlatformFromConfig,
  runsAttachmentConsumer,
  SCAN_ROUND_DEADLINE_MAX_SECONDS,
} from './config';

const base = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  RABBITMQ_EMAIL_WORKER_URL: 'amqp://ew:secret-pw@localhost:5672/email-gateway',
  RABBITMQ_SCANNER_URL: 'amqp://sc:scanner-pw@localhost:5672/email-gateway',
  SCAN_RSPAMD_URL: 'http://127.0.0.1:11333',
  REDIS_URL: 'redis://localhost:6379',
  ATTACHMENT_CACHE_HMAC_KEY: 'test-content-cache-mac-key-0123456789',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
};

const load = (env: Record<string, string> = {}) => loadWorkerConfig({ ...base, ...env });
const without = (...keys: string[]) =>
  Object.fromEntries(Object.entries(base).filter(([k]) => !keys.includes(k)));
const refusal = (env: Record<string, string>, key: string) =>
  expect(() => load(env)).toThrow(new RegExp(key));

describe('email-worker scan config (step 4.1 §5, S5, S8, S10)', () => {
  it('applies the design defaults', () => {
    const config = load();
    expect(config.SCAN_ENABLED).toBe(true);
    // Step 4.2 A1: the attachment engine is enabled (and required) by default.
    expect(config.SCAN_ENGINES).toEqual(['rspamd', 'attachment']);
    expect(config.SCAN_CONSUMERS).toEqual([]);
    expect(consumerEngines(config)).toEqual(['rspamd', 'attachment']);
    expect(config.RABBITMQ_SCANNER_URL).toEqual([base.RABBITMQ_SCANNER_URL]);
    expect(config).toMatchObject({
      SCAN_RSPAMD_CONCURRENCY: 8,
      SCAN_RSPAMD_TIMEOUT_MS: 20_000,
      SCAN_RSPAMD_MAX_ATTEMPTS: 6,
      SCAN_RSPAMD_MAX_BYTES: 26_214_400,
      SCAN_RETRY_BASE_MS: 2_000,
      SCAN_RETRY_MAX_MS: 60_000,
      SCAN_S3_TIMEOUT_MS: 30_000,
      SCAN_DB_TIMEOUT_MS: 120_000,
      SCAN_ROUND_DEADLINE_SECONDS: 1_800,
      SCAN_SWEEP_INTERVAL_MS: 30_000,
      SCAN_SWEEP_LOOKBACK_HOURS: 48,
      SCAN_SWEEP_BATCH_SIZE: 200,
      SCAN_BREAKER_FAILURE_THRESHOLD: 5,
      SCAN_BREAKER_FAILURE_RATIO: 0.5,
      SCAN_BREAKER_WINDOW: 20,
      SCAN_BREAKER_OPEN_MS: 15_000,
      SCAN_BREAKER_HALF_OPEN_PROBES: 1,
      SCAN_SETTINGS_CACHE_TTL_MS: 30_000,
      SCAN_ENGINE_VERSION_TTL_MS: 300_000,
    });
    expect(rspamdPlatformFromConfig(config)).toEqual(RSPAMD_PLATFORM_DEFAULTS);
    // The default deadline covers every engine's attempt budget (step 4.2 A12): rspamd
    // 6 x (20 s + 60 s) = 480 s, attachment 6 x (180 s + 60 s) = 1 440 s ≤ 1 800 s.
    expect(minimumRoundDeadlineSeconds(config)).toBe(1_440);
    expect(minimumRoundDeadlineSeconds(load({ SCAN_ENGINES: 'rspamd' }))).toBe(480);
  });

  it('validates SCAN_ENGINES against the engine catalog', () => {
    refusal({ SCAN_ENGINES: 'clamav' }, 'SCAN_ENGINES');
    refusal({ SCAN_ENGINES: 'rspamd,rspamd' }, 'SCAN_ENGINES');
    refusal({ SCAN_ENGINES: 'nope' }, 'SCAN_ENGINES');
    expect(load({ SCAN_ENGINES: ' rspamd ' }).SCAN_ENGINES).toEqual(['rspamd']);
  });

  it('refuses an attempt budget at or above the scan.spam attempt limit', () => {
    expect(engineQueueMaxAttempts('rspamd')).toBe(10);
    refusal({ SCAN_RSPAMD_MAX_ATTEMPTS: '10' }, 'SCAN_RSPAMD_MAX_ATTEMPTS');
    expect(
      load({
        SCAN_ENGINES: 'rspamd',
        SCAN_RSPAMD_MAX_ATTEMPTS: '9',
        SCAN_ROUND_DEADLINE_SECONDS: '720',
      }).SCAN_RSPAMD_MAX_ATTEMPTS,
    ).toBe(9);
  });

  it('refuses a retry cap above the 60 s hold limit or below its base', () => {
    refusal({ SCAN_RETRY_MAX_MS: '60001' }, 'SCAN_RETRY_MAX_MS');
    refusal({ SCAN_RETRY_BASE_MS: '5000', SCAN_RETRY_MAX_MS: '4000' }, 'SCAN_RETRY_MAX_MS');
  });

  it('bounds the round deadline by the attempt budget and 6 hours (S10)', () => {
    const rspamdOnly = { SCAN_ENGINES: 'rspamd' };
    refusal({ ...rspamdOnly, SCAN_ROUND_DEADLINE_SECONDS: '479' }, 'SCAN_ROUND_DEADLINE_SECONDS');
    expect(
      load({ ...rspamdOnly, SCAN_ROUND_DEADLINE_SECONDS: '480' }).SCAN_ROUND_DEADLINE_SECONDS,
    ).toBe(480);
    refusal(
      { SCAN_ROUND_DEADLINE_SECONDS: String(SCAN_ROUND_DEADLINE_MAX_SECONDS + 1) },
      'SCAN_ROUND_DEADLINE_SECONDS',
    );
    // A short test budget allows a short deadline: 1 x (500 + 500) ms = 1 s.
    expect(
      load({
        ...rspamdOnly,
        SCAN_RSPAMD_MAX_ATTEMPTS: '1',
        SCAN_RSPAMD_TIMEOUT_MS: '500',
        SCAN_RETRY_BASE_MS: '100',
        SCAN_RETRY_MAX_MS: '500',
        SCAN_ROUND_DEADLINE_SECONDS: '1',
      }).SCAN_ROUND_DEADLINE_SECONDS,
    ).toBe(1);
  });

  it('validates the platform Rspamd settings (S8)', () => {
    refusal({ SCAN_RSPAMD_SUSPICIOUS_SCORE: '7' }, 'SCAN_RSPAMD_SUSPICIOUS_SCORE');
    refusal({ SCAN_RSPAMD_SPAM_SCORE: '16' }, 'SCAN_RSPAMD_SPAM_SCORE');
    refusal({ SCAN_RSPAMD_SCORE_MIN: '20' }, 'SCAN_RSPAMD_SCORE_MIN');
    refusal({ SCAN_RSPAMD_SPAM_SCORE: '6.125' }, 'SCAN_RSPAMD_SPAM_SCORE');
    refusal({ SCAN_RSPAMD_PHISHING_VERDICT: 'clean' }, 'SCAN_RSPAMD_PHISHING_VERDICT');
    refusal({ SCAN_RSPAMD_AUTH_FAILURE_VERDICT: 'malicious' }, 'SCAN_RSPAMD_AUTH_FAILURE_VERDICT');
    const tuned = load({
      SCAN_RSPAMD_SPAM_SCORE: '8',
      SCAN_RSPAMD_DMARC_REJECT_VERDICT: 'malicious',
    });
    expect(rspamdPlatformFromConfig(tuned)).toMatchObject({
      spamScore: 8,
      dmarcRejectVerdict: 'malicious',
    });
  });

  it('bounds the breaker and the caches', () => {
    refusal({ SCAN_BREAKER_WINDOW: '9' }, 'SCAN_BREAKER_WINDOW');
    refusal({ SCAN_BREAKER_FAILURE_RATIO: '0' }, 'SCAN_BREAKER_FAILURE_RATIO');
    refusal({ SCAN_BREAKER_FAILURE_RATIO: '1.5' }, 'SCAN_BREAKER_FAILURE_RATIO');
    refusal({ SCAN_SETTINGS_CACHE_TTL_MS: '300001' }, 'SCAN_SETTINGS_CACHE_TTL_MS');
    refusal({ SCAN_RSPAMD_CONCURRENCY: '65' }, 'SCAN_RSPAMD_CONCURRENCY');
  });

  it('requires the scanner broker URL and the Rspamd URL for the scan role only', () => {
    expect(() => loadWorkerConfig(without('RABBITMQ_SCANNER_URL'))).toThrow(/RABBITMQ_SCANNER_URL/);
    expect(() => loadWorkerConfig(without('SCAN_RSPAMD_URL'))).toThrow(/SCAN_RSPAMD_URL/);
    const mimeOnly = loadWorkerConfig({
      ...without('RABBITMQ_SCANNER_URL', 'SCAN_RSPAMD_URL'),
      SCAN_ENABLED: 'false',
    });
    expect(mimeOnly.SCAN_ENABLED).toBe(false);
    // A scan-only replica needs no email-worker broker user (S1).
    const scanOnly = loadWorkerConfig({
      ...without('RABBITMQ_EMAIL_WORKER_URL'),
      MIME_INGESTION_ENABLED: 'false',
    });
    expect(scanOnly.RABBITMQ_EMAIL_WORKER_URL).toBeUndefined();
    expect(() => loadWorkerConfig(without('RABBITMQ_EMAIL_WORKER_URL'))).toThrow(
      /RABBITMQ_EMAIL_WORKER_URL/,
    );
    refusal({ RSPAMD_CONTROLLER_PASSWORD: 'pw' }, 'RSPAMD_CONTROLLER_URL');
    refusal({ SCAN_RSPAMD_URL: 'ftp://rspamd' }, 'SCAN_RSPAMD_URL');
  });

  it('refuses a worker with no role enabled', () => {
    refusal({ MIME_INGESTION_ENABLED: 'false', SCAN_ENABLED: 'false' }, 'SCAN_ENABLED');
  });

  it('never echoes the scanner URL or the controller password', () => {
    let message = '';
    try {
      load({
        RABBITMQ_SCANNER_URL: 'http://sc:hidden-pw@localhost',
        RSPAMD_CONTROLLER_PASSWORD: 'x',
      });
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toMatch(/RABBITMQ_SCANNER_URL/);
    expect(message).not.toContain('hidden-pw');
  });

  it('generalizes the deadline to the maximum over the enabled engines (step 4.2 A12)', () => {
    refusal({ SCAN_ROUND_DEADLINE_SECONDS: '1439' }, 'SCAN_ROUND_DEADLINE_SECONDS');
    expect(load({ SCAN_ROUND_DEADLINE_SECONDS: '1440' }).SCAN_ROUND_DEADLINE_SECONDS).toBe(1440);
    // A longer Rspamd budget dominates: 9 x (100 s + 60 s) = 1 440 s with attachment 2 x 240.
    const tuned = load({
      SCAN_RSPAMD_MAX_ATTEMPTS: '9',
      SCAN_RSPAMD_TIMEOUT_MS: '100000',
      SCAN_ATTACHMENT_MAX_ATTEMPTS: '2',
      SCAN_ROUND_DEADLINE_SECONDS: '1440',
    });
    expect(minimumRoundDeadlineSeconds(tuned)).toBe(1440);
  });
});

describe('email-worker attachment config (step 4.2 §5, A1, A4, A8, A12, A20)', () => {
  it('applies the design defaults', () => {
    const config = load();
    expect(config).toMatchObject({
      CLAMAV_HOST: '127.0.0.1',
      CLAMAV_PORT: 3310,
      CLAMAV_TIMEOUT_MS: 60_000,
      CLAMAV_MAX_CONNECTIONS: 4,
      CLAMAV_CHUNK_BYTES: 65_536,
      SCAN_ATTACHMENT_CONCURRENCY: 4,
      SCAN_ATTACHMENT_TIMEOUT_MS: 180_000,
      SCAN_ATTACHMENT_MAX_ATTEMPTS: 6,
      ATTACHMENT_MAX_PER_MESSAGE: 100,
      ATTACHMENT_PER_MESSAGE_PARALLELISM: 2,
      ATTACHMENT_MEMORY_BUDGET_BYTES: 134_217_728,
      ATTACHMENT_INSPECTOR_POOL_SIZE: 2,
      ATTACHMENT_INSPECTOR_MAX_JOBS: 500,
      ATTACHMENT_INSPECTOR_HEAP_MB: 192,
      ATTACHMENT_INSPECTOR_RLIMITS: 'required',
      ATTACHMENT_INSPECTOR_TMPDIR: '',
      ATTACHMENT_INSPECT_TIMEOUT_MS: 30_000,
      ATTACHMENT_INSPECT_CPU_SECONDS: 10,
      ATTACHMENT_INSPECT_MAX_RSS_MB: 384,
      ATTACHMENT_YARA_TIMEOUT_MS: 10_000,
      ATTACHMENT_YARA_RULES_DIR: '',
      EG_INSPECTOR_SELFTEST: false,
      ATTACHMENT_CACHE_ENABLED: true,
      ATTACHMENT_CACHE_CLEAN_TTL_SECONDS: 21_600,
      ATTACHMENT_CACHE_MALICIOUS_TTL_SECONDS: 604_800,
      ATTACHMENT_CACHE_OTHER_TTL_SECONDS: 3_600,
      ATTACHMENT_CACHE_TIMEOUT_MS: 200,
      ATTACHMENT_SANDBOX_SUBMIT: true,
      ATTACHMENT_SANDBOX_MAX_PER_MESSAGE: 5,
      ATTACHMENT_SIGNATURE_POLL_MS: 300_000,
      ATTACHMENT_SIGNATURE_RESCAN: 'record',
      ATTACHMENT_RESCAN_INTERVAL_MS: 10_000,
      ATTACHMENT_RESCAN_BATCH_SIZE: 50,
      ATTACHMENT_RESCAN_MAX_MESSAGES: 5_000,
      ATTACHMENT_RESCAN_WINDOW_HOURS: 24,
    });
    expect(attachmentPlatformFromConfig(config)).toEqual({
      ...ATTACHMENT_PLATFORM_DEFAULTS,
      deniedTypes: [...ATTACHMENT_PLATFORM_DEFAULTS.deniedTypes],
    });
    expect(runsAttachmentConsumer(config)).toBe(true);
    expect(attachmentScalingWarnings(config)).toEqual([]);
  });

  it('selects the consumers of this replica (SCAN_CONSUMERS ⊆ SCAN_ENGINES)', () => {
    const attachmentOnly = load({ SCAN_CONSUMERS: 'attachment' });
    expect(consumerEngines(attachmentOnly)).toEqual(['attachment']);
    expect(runsAttachmentConsumer(attachmentOnly)).toBe(true);
    // The Rspamd URL is needed only where the rspamd consumer runs.
    expect(() =>
      loadWorkerConfig({ ...without('SCAN_RSPAMD_URL'), SCAN_CONSUMERS: 'attachment' }),
    ).not.toThrow();
    expect(runsAttachmentConsumer(load({ SCAN_CONSUMERS: 'rspamd' }))).toBe(false);
    refusal({ SCAN_ENGINES: 'rspamd', SCAN_CONSUMERS: 'attachment' }, 'SCAN_CONSUMERS');
    refusal({ SCAN_CONSUMERS: 'nope' }, 'SCAN_CONSUMERS');
    expect(runsAttachmentConsumer(load({ SCAN_ENABLED: 'false' }))).toBe(false);
  });

  it('refuses the test hook and best-effort rlimits in production (A4)', () => {
    refusal(
      { NODE_ENV: 'production', ATTACHMENT_INSPECTOR_RLIMITS: 'best_effort' },
      'ATTACHMENT_INSPECTOR_RLIMITS',
    );
    refusal({ NODE_ENV: 'production', EG_INSPECTOR_SELFTEST: 'true' }, 'EG_INSPECTOR_SELFTEST');
    expect(
      load({ ATTACHMENT_INSPECTOR_RLIMITS: 'best_effort', EG_INSPECTOR_SELFTEST: '1' }),
    ).toMatchObject({
      ATTACHMENT_INSPECTOR_RLIMITS: 'best_effort',
      EG_INSPECTOR_SELFTEST: true,
    });
    expect(load({ NODE_ENV: 'production' }).ATTACHMENT_INSPECTOR_RLIMITS).toBe('required');
    refusal({ ATTACHMENT_INSPECTOR_RLIMITS: 'none' }, 'ATTACHMENT_INSPECTOR_RLIMITS');
  });

  it('requires a content-cache MAC key of 32+ characters where the attachment engine consumes (A10)', () => {
    const noKey = without('ATTACHMENT_CACHE_HMAC_KEY');
    const loadNoKey = (env: Record<string, string> = {}) => loadWorkerConfig({ ...noKey, ...env });
    expect(() => loadNoKey()).toThrow(/ATTACHMENT_CACHE_HMAC_KEY/);
    refusal({ ATTACHMENT_CACHE_HMAC_KEY: 'too-short' }, 'ATTACHMENT_CACHE_HMAC_KEY');
    // Not needed without the cache, without an attachment consumer or without the scan role.
    expect(loadNoKey({ ATTACHMENT_CACHE_ENABLED: 'false' }).ATTACHMENT_CACHE_HMAC_KEY).toBe(
      undefined,
    );
    expect(() => loadNoKey({ SCAN_CONSUMERS: 'rspamd' })).not.toThrow();
    expect(() => loadNoKey({ SCAN_ENABLED: 'false' })).not.toThrow();
    // Never echoed in a refusal.
    expect(() => load({ ATTACHMENT_CACHE_HMAC_KEY: 'short-secret-value' })).toThrow(
      expect.not.objectContaining({ message: expect.stringContaining('short-secret-value') }),
    );
  });

  it('keeps the attempt budget below the scan.attachment attempt limit', () => {
    expect(engineQueueMaxAttempts('attachment')).toBe(10);
    refusal(
      { SCAN_ATTACHMENT_MAX_ATTEMPTS: '10', SCAN_ROUND_DEADLINE_SECONDS: '3000' },
      'SCAN_ATTACHMENT_MAX_ATTEMPTS',
    );
  });

  it('validates the platform settings and the budgets (A8, A14, A20)', () => {
    refusal({ ATTACHMENT_MEMORY_BUDGET_BYTES: '1048576' }, 'ATTACHMENT_MEMORY_BUDGET_BYTES');
    refusal({ ATTACHMENT_MAX_BYTES: '1000' }, 'ATTACHMENT_MAX_BYTES');
    refusal({ ATTACHMENT_MAX_BYTES: '31457281' }, 'ATTACHMENT_MAX_BYTES');
    refusal(
      { ATTACHMENT_MAX_BYTES: '26214400', MIME_MAX_ATTACHMENT_BYTES: '20971520' },
      'ATTACHMENT_MAX_BYTES',
    );
    refusal({ ATTACHMENT_DENIED_TYPES: 'pe_executable,unknown' }, 'ATTACHMENT_DENIED_TYPES');
    refusal({ ATTACHMENT_DENIED_TYPES: 'nope' }, 'ATTACHMENT_DENIED_TYPES');
    expect(load({ ATTACHMENT_DENIED_TYPES: 'none' }).ATTACHMENT_DENIED_TYPES).toEqual([]);
    expect(load({ ATTACHMENT_DENIED_TYPES: ' msi , lnk ' }).ATTACHMENT_DENIED_TYPES).toEqual([
      'msi',
      'lnk',
    ]);
    refusal({ ATTACHMENT_MAX_ENTRY_BYTES: '209715200' }, 'ATTACHMENT_MAX_ENTRY_BYTES');
    refusal({ ATTACHMENT_MAX_COMPRESSION_RATIO: '1' }, 'ATTACHMENT_MAX_COMPRESSION_RATIO');
    refusal({ ATTACHMENT_DENIED_TYPE_VERDICT: 'clean' }, 'ATTACHMENT_DENIED_TYPE_VERDICT');
    refusal({ CLAMAV_MAX_CONNECTIONS: '65' }, 'CLAMAV_MAX_CONNECTIONS');
    refusal({ ATTACHMENT_INSPECTOR_POOL_SIZE: '17' }, 'ATTACHMENT_INSPECTOR_POOL_SIZE');
    refusal({ ATTACHMENT_CACHE_CLEAN_TTL_SECONDS: '86401' }, 'ATTACHMENT_CACHE_CLEAN_TTL_SECONDS');
    refusal({ ATTACHMENT_RESCAN_MAX_MESSAGES: '50001' }, 'ATTACHMENT_RESCAN_MAX_MESSAGES');
    refusal({ ATTACHMENT_RESCAN_WINDOW_HOURS: '169' }, 'ATTACHMENT_RESCAN_WINDOW_HOURS');
    refusal({ ATTACHMENT_SIGNATURE_RESCAN: 'always' }, 'ATTACHMENT_SIGNATURE_RESCAN');
  });

  it('refuses per-file limits that cannot fire or do not fit one engine call (A4, A14)', () => {
    refusal({ ATTACHMENT_INSPECT_CPU_SECONDS: '31' }, 'ATTACHMENT_INSPECT_CPU_SECONDS');
    refusal({ ATTACHMENT_YARA_TIMEOUT_MS: '30001' }, 'ATTACHMENT_YARA_TIMEOUT_MS');
    refusal({ ATTACHMENT_INSPECT_MAX_RSS_MB: '192' }, 'ATTACHMENT_INSPECT_MAX_RSS_MB');
    refusal({ SCAN_ATTACHMENT_TIMEOUT_MS: '60000' }, 'SCAN_ATTACHMENT_TIMEOUT_MS');
    refusal(
      { SCAN_ATTACHMENT_TIMEOUT_MS: '30000', SCAN_S3_TIMEOUT_MS: '30000' },
      'SCAN_S3_TIMEOUT_MS',
    );
  });

  it('skips the attachment rules when the engine is not enabled', () => {
    expect(
      load({
        SCAN_ENGINES: 'rspamd',
        ATTACHMENT_MEMORY_BUDGET_BYTES: '1',
        SCAN_ROUND_DEADLINE_SECONDS: '600',
      }).ATTACHMENT_MEMORY_BUDGET_BYTES,
    ).toBe(1);
  });

  it('warns about an inspector pool larger than the parallelism (A20)', () => {
    expect(
      attachmentScalingWarnings(
        load({
          SCAN_ATTACHMENT_CONCURRENCY: '1',
          ATTACHMENT_PER_MESSAGE_PARALLELISM: '1',
          ATTACHMENT_INSPECTOR_POOL_SIZE: '4',
          CLAMAV_MAX_CONNECTIONS: '2',
        }),
      ),
    ).toEqual(['inspector_pool_larger_than_parallelism', 'clamav_connections_below_pool_size']);
  });
});
