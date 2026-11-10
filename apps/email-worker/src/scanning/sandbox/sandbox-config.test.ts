import { ENGINE_REGISTRY, enabledRegistrations } from '../registry';
import { SANDBOX_PLATFORM_DEFAULTS } from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { loadWorkerConfig } from '../../config';
import {
  consumerEngines,
  runsAttachmentConsumer,
  runsSandboxConsumers,
  sandboxPlatformFromConfig,
} from '../config';

const SAMPLE = 'a1'.repeat(32);
const RESULT = 'b2'.repeat(32);

const base = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  RABBITMQ_EMAIL_WORKER_URL: 'amqp://ew:secret-pw@localhost:5672/email-gateway',
  RABBITMQ_SCANNER_URL: 'amqp://sc:scanner-pw@localhost:5672/email-gateway',
  SCAN_RSPAMD_URL: 'http://127.0.0.1:11333',
  REDIS_URL: 'redis://localhost:6379',
  ATTACHMENT_CACHE_HMAC_KEY: 'test-content-cache-mac-key-0123456789',
  URL_CACHE_HMAC_KEY: 'test-url-cache-mac-key-0123456789abcdef',
  BEC_CONTEXT_HMAC_KEY: 'test-bec-context-hmac-key-0123456789abcdef',
  DLP_EVIDENCE_KEY: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  URL_TOKEN_KEY_CURRENT: '0123456789abcdef'.repeat(4),
  URL_DNSBL_DOMAIN_ZONES: 'dbl.scan.test=127.0.1.2:spam,127.0.1.4:phishing',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
};
const enabled = {
  SANDBOX_ENABLED: 'true',
  SANDBOX_S3_BUCKET: 'test-sandbox',
  SANDBOX_SAMPLE_KEY: SAMPLE,
  SANDBOX_RESULT_KEY: RESULT,
};

const load = (env: Record<string, string> = {}) => loadWorkerConfig({ ...base, ...env });
const refusal = (env: Record<string, string>, key: string) =>
  expect(() => load(env)).toThrow(new RegExp(key));

describe('email-worker sandbox config (step 4.6 §5, X13, X17)', () => {
  it('applies the design defaults; the engine is off by default', () => {
    const config = load();
    expect(config).toMatchObject({
      SANDBOX_ENABLED: false,
      SANDBOX_TENANT_DEFAULT_ENABLED: false,
      SANDBOX_MAX_SAMPLE_BYTES: 26_214_400,
      SANDBOX_BROWSER_ANALYSIS: true,
      SANDBOX_DISPATCH_CONCURRENCY: 4,
      SANDBOX_RESULTS_CONCURRENCY: 4,
      SANDBOX_TASK_DEADLINE_SECONDS: 900,
      SANDBOX_SUBMISSION_TTL_SECONDS: 3_600,
      SANDBOX_REUSE_DEFINITE_SECONDS: 86_400,
      SANDBOX_REUSE_UNKNOWN_SECONDS: 21_600,
      SANDBOX_REUSE_NOT_EXECUTED_SECONDS: 3_600,
      SANDBOX_ANALYSIS_EPOCH: 1,
      SANDBOX_RUN_TIMEOUT_MS: 60_000,
      SANDBOX_RUN_MEMORY_MB: 512,
      SANDBOX_RUN_CPU_MILLIS: 1_000,
      SANDBOX_RUN_PIDS: 128,
      SANDBOX_RUN_SCRATCH_MB: 64,
      SANDBOX_MAX_ARTIFACTS: 16,
      SANDBOX_MAX_ARTIFACT_BYTES: 2_097_152,
      SANDBOX_MAX_TOTAL_ARTIFACT_BYTES: 8_388_608,
      SANDBOX_SWEEP_INTERVAL_MS: 60_000,
      SANDBOX_SWEEP_BATCH: 500,
      SANDBOX_ARTIFACT_RETENTION_DAYS: 30,
      SANDBOX_ANALYSIS_RETENTION_DAYS: 180,
      SANDBOX_SAMPLE_RETENTION_HOURS: 24,
      SANDBOX_PUBLISH_HASHES: false,
    });
    expect(sandboxPlatformFromConfig(config)).toEqual(SANDBOX_PLATFORM_DEFAULTS);
    expect(runsSandboxConsumers(config)).toBe(false);
  });

  it('SANDBOX_ENABLED requires the bucket, the sample key and the result key (never echoed)', () => {
    expect(runsSandboxConsumers(load(enabled))).toBe(true);
    refusal({ ...enabled, SANDBOX_S3_BUCKET: '' }, 'SANDBOX_S3_BUCKET');
    refusal({ ...enabled, SANDBOX_SAMPLE_KEY: '' }, 'SANDBOX_SAMPLE_KEY');
    refusal({ ...enabled, SANDBOX_SAMPLE_KEY: 'zz'.repeat(32) }, 'SANDBOX_SAMPLE_KEY');
    refusal({ ...enabled, SANDBOX_RESULT_KEY: 'abc' }, 'SANDBOX_RESULT_KEY');
    refusal({ ...enabled, SANDBOX_RESULT_KEY: SAMPLE }, 'SANDBOX_RESULT_KEY');
    refusal({ ...enabled, SANDBOX_SAMPLE_KEY_PREVIOUS: SAMPLE }, 'SANDBOX_SAMPLE_KEY_PREVIOUS');
    refusal({ ...enabled, SANDBOX_SAMPLE_KEY_PREVIOUS: '12' }, 'SANDBOX_SAMPLE_KEY_PREVIOUS');
    expect(
      load({ ...enabled, SANDBOX_SAMPLE_KEY_PREVIOUS: 'c3'.repeat(32) })
        .SANDBOX_SAMPLE_KEY_PREVIOUS,
    ).toBe('c3'.repeat(32));
    expect(() => load({ ...enabled, SANDBOX_SAMPLE_KEY: `${SAMPLE.slice(0, 62)}zz` })).toThrow(
      expect.not.objectContaining({ message: expect.stringContaining(SAMPLE.slice(0, 62)) }),
    );
    // Not required where the sandbox consumers do not run.
    expect(() => load({ SANDBOX_ENABLED: 'true', SCAN_CONSUMERS: 'attachment' })).not.toThrow();
    expect(() => load({ SANDBOX_ENABLED: 'true', SCAN_ENABLED: 'false' })).not.toThrow();
  });

  it('validates retention relations, deadlines and the run limits below the controller maxima', () => {
    refusal(
      { SANDBOX_ANALYSIS_RETENTION_DAYS: '10', SANDBOX_ARTIFACT_RETENTION_DAYS: '30' },
      'SANDBOX_ANALYSIS_RETENTION_DAYS',
    );
    refusal({ SANDBOX_ARTIFACT_RETENTION_DAYS: '181' }, 'SANDBOX_ARTIFACT_RETENTION_DAYS');
    refusal({ SANDBOX_SAMPLE_RETENTION_HOURS: '49' }, 'SANDBOX_SAMPLE_RETENTION_HOURS');
    refusal(
      { SANDBOX_TASK_DEADLINE_SECONDS: '7200', SANDBOX_SAMPLE_RETENTION_HOURS: '1' },
      'SANDBOX_SAMPLE_RETENTION_HOURS',
    );
    refusal(
      { SANDBOX_TASK_DEADLINE_SECONDS: '60', SANDBOX_RUN_TIMEOUT_MS: '60000' },
      'SANDBOX_TASK_DEADLINE_SECONDS',
    );
    refusal({ SANDBOX_TASK_DEADLINE_SECONDS: '59' }, 'SANDBOX_TASK_DEADLINE_SECONDS');
    refusal({ SANDBOX_SUBMISSION_TTL_SECONDS: '299' }, 'SANDBOX_SUBMISSION_TTL_SECONDS');
    refusal({ SANDBOX_RUN_MEMORY_MB: '2048' }, 'SANDBOX_RUN_MEMORY_MB');
    refusal(
      { SANDBOX_RUN_TIMEOUT_MS: '400000', SANDBOX_TASK_DEADLINE_SECONDS: '900' },
      'SANDBOX_RUN_TIMEOUT_MS',
    );
    refusal({ SANDBOX_RUN_PIDS: '300' }, 'SANDBOX_RUN_PIDS');
    refusal({ SANDBOX_RUN_CPU_MILLIS: '3000' }, 'SANDBOX_RUN_CPU_MILLIS');
    refusal({ SANDBOX_RUN_SCRATCH_MB: '512' }, 'SANDBOX_RUN_SCRATCH_MB');
    refusal({ SANDBOX_MAX_ARTIFACTS: '17' }, 'SANDBOX_MAX_ARTIFACTS');
    refusal(
      { SANDBOX_MAX_ARTIFACT_BYTES: '9000000', SANDBOX_MAX_TOTAL_ARTIFACT_BYTES: '8388608' },
      'SANDBOX_MAX_ARTIFACT_BYTES',
    );
    refusal({ SANDBOX_DISPATCH_CONCURRENCY: '33' }, 'SANDBOX_DISPATCH_CONCURRENCY');
    refusal({ SANDBOX_REUSE_DEFINITE_SECONDS: '-1' }, 'SANDBOX_REUSE_DEFINITE_SECONDS');
    expect(load({ SANDBOX_REUSE_DEFINITE_SECONDS: '0' }).SANDBOX_REUSE_DEFINITE_SECONDS).toBe(0);
  });

  it('validates the platform settings (file types, maximum sample size)', () => {
    refusal({ SANDBOX_FILE_TYPES: 'pdf,nope' }, 'SANDBOX_FILE_TYPES');
    refusal({ SANDBOX_MAX_SAMPLE_BYTES: String(64 * 1024 * 1024 + 1) }, 'SANDBOX_MAX_SAMPLE_BYTES');
    expect(load({ SANDBOX_FILE_TYPES: 'pdf, zip' }).SANDBOX_FILE_TYPES).toEqual(['pdf', 'zip']);
    expect(
      load({ SANDBOX_TENANT_DEFAULT_ENABLED: 'true', SANDBOX_BROWSER_ANALYSIS: 'false' }),
    ).toMatchObject({
      SANDBOX_TENANT_DEFAULT_ENABLED: true,
      SANDBOX_BROWSER_ANALYSIS: false,
    });
  });
});

describe('SCAN_CONSUMERS accepts the asynchronous sandbox (step 4.6 X10, X13)', () => {
  it('accepts sandbox alone or with synchronous engines; SCAN_ENGINES never does', () => {
    const alone = load({ ...enabled, SCAN_CONSUMERS: 'sandbox' });
    expect(alone.SCAN_CONSUMERS).toEqual(['sandbox']);
    expect(consumerEngines(alone)).toEqual(['sandbox']);
    expect(runsSandboxConsumers(alone)).toBe(true);
    expect(runsAttachmentConsumer(alone)).toBe(false);
    // No round engine runs on a sandbox-only replica (its Rspamd URL is not needed).
    const { SCAN_RSPAMD_URL: _rspamd, ...noRspamd } = base;
    expect(() =>
      loadWorkerConfig({ ...noRspamd, ...enabled, SCAN_CONSUMERS: 'sandbox' }),
    ).not.toThrow();
    const both = load({ ...enabled, SCAN_CONSUMERS: 'attachment, sandbox' });
    expect(both.SCAN_CONSUMERS).toEqual(['attachment', 'sandbox']);
    expect(runsSandboxConsumers(both)).toBe(true);
    expect(runsSandboxConsumers(load({ ...enabled, SCAN_CONSUMERS: 'attachment' }))).toBe(false);
    expect(runsSandboxConsumers(load({ ...enabled, SCAN_ENABLED: 'false' }))).toBe(false);
    refusal({ SCAN_ENGINES: 'rspamd,sandbox' }, 'SCAN_ENGINES');
    refusal({ ...enabled, SCAN_CONSUMERS: 'sandbox,sandbox' }, 'SCAN_CONSUMERS');
    refusal({ SCAN_CONSUMERS: 'sandbox' }, 'SCAN_CONSUMERS');
  });

  it('the round engine registry is unchanged: the sandbox is never a round engine', () => {
    expect(ENGINE_REGISTRY.map((r) => r.catalog.name)).not.toContain('sandbox');
    expect(enabledRegistrations(load(enabled).SCAN_ENGINES).map((r) => r.catalog.name)).toEqual([
      'rspamd',
      'attachment',
      'url',
      'bec',
      'dlp',
    ]);
  });
});
