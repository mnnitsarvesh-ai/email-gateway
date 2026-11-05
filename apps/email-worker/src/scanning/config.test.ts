import { RSPAMD_PLATFORM_DEFAULTS } from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { loadWorkerConfig } from '../config';
import {
  engineQueueMaxAttempts,
  minimumRoundDeadlineSeconds,
  rspamdPlatformFromConfig,
  SCAN_ROUND_DEADLINE_MAX_SECONDS,
} from './config';

const base = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  RABBITMQ_EMAIL_WORKER_URL: 'amqp://ew:secret-pw@localhost:5672/email-gateway',
  RABBITMQ_SCANNER_URL: 'amqp://sc:scanner-pw@localhost:5672/email-gateway',
  SCAN_RSPAMD_URL: 'http://127.0.0.1:11333',
  REDIS_URL: 'redis://localhost:6379',
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
    expect(config.SCAN_ENGINES).toEqual(['rspamd']);
    expect(config.RABBITMQ_SCANNER_URL).toEqual([base.RABBITMQ_SCANNER_URL]);
    expect(config).toMatchObject({
      SCAN_RSPAMD_CONCURRENCY: 8,
      SCAN_RSPAMD_TIMEOUT_MS: 20_000,
      SCAN_RSPAMD_MAX_ATTEMPTS: 6,
      SCAN_RSPAMD_MAX_BYTES: 26_214_400,
      SCAN_RETRY_BASE_MS: 2_000,
      SCAN_RETRY_MAX_MS: 60_000,
      SCAN_S3_TIMEOUT_MS: 30_000,
      SCAN_DB_TIMEOUT_MS: 15_000,
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
    // The default deadline covers the whole attempt budget: 6 x (20 s + 60 s) = 480 s.
    expect(minimumRoundDeadlineSeconds(config)).toBe(480);
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
      load({ SCAN_RSPAMD_MAX_ATTEMPTS: '9', SCAN_ROUND_DEADLINE_SECONDS: '720' })
        .SCAN_RSPAMD_MAX_ATTEMPTS,
    ).toBe(9);
  });

  it('refuses a retry cap above the 60 s hold limit or below its base', () => {
    refusal({ SCAN_RETRY_MAX_MS: '60001' }, 'SCAN_RETRY_MAX_MS');
    refusal({ SCAN_RETRY_BASE_MS: '5000', SCAN_RETRY_MAX_MS: '4000' }, 'SCAN_RETRY_MAX_MS');
  });

  it('bounds the round deadline by the attempt budget and 6 hours (S10)', () => {
    refusal({ SCAN_ROUND_DEADLINE_SECONDS: '479' }, 'SCAN_ROUND_DEADLINE_SECONDS');
    expect(load({ SCAN_ROUND_DEADLINE_SECONDS: '480' }).SCAN_ROUND_DEADLINE_SECONDS).toBe(480);
    refusal(
      { SCAN_ROUND_DEADLINE_SECONDS: String(SCAN_ROUND_DEADLINE_MAX_SECONDS + 1) },
      'SCAN_ROUND_DEADLINE_SECONDS',
    );
    // A short test budget allows a short deadline: 1 x (500 + 500) ms = 1 s.
    expect(
      load({
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
});
