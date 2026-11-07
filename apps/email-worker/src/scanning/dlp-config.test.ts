import { DLP_PLATFORM_DEFAULTS } from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { loadWorkerConfig } from '../config';
import {
  consumerEngines,
  engineBudgetFromConfig,
  minimumRoundDeadlineSeconds,
  runsDlpConsumer,
} from './config';
import { dlpPlatformFromConfig } from './dlp-config';

const KEY = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
const base = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  RABBITMQ_EMAIL_WORKER_URL: 'amqp://ew:secret-pw@localhost:5672/email-gateway',
  RABBITMQ_SCANNER_URL: 'amqp://sc:scanner-pw@localhost:5672/email-gateway',
  SCAN_RSPAMD_URL: 'http://127.0.0.1:11333',
  REDIS_URL: 'redis://localhost:6379',
  ATTACHMENT_CACHE_HMAC_KEY: 'test-content-cache-mac-key-0123456789',
  URL_CACHE_HMAC_KEY: 'test-url-cache-mac-key-0123456789abcdef',
  BEC_CONTEXT_HMAC_KEY: 'test-bec-context-hmac-key-0123456789abcdef',
  DLP_EVIDENCE_KEY: KEY,
  URL_TOKEN_KEY_CURRENT: '0123456789abcdef'.repeat(4),
  URL_DNSBL_DOMAIN_ZONES: 'dbl.scan.test=127.0.1.2:spam',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
};

const load = (env: Record<string, string> = {}) => loadWorkerConfig({ ...base, ...env });
const without = (...keys: string[]) =>
  Object.fromEntries(Object.entries(base).filter(([k]) => !keys.includes(k)));
const message = (env: Record<string, string | undefined>): string => {
  try {
    loadWorkerConfig(env);
    return '';
  } catch (error) {
    return (error as Error).message;
  }
};
const refusal = (env: Record<string, string>, key: string) =>
  expect(() => load(env)).toThrow(new RegExp(`${key}:`));

describe('dlp engine config (step 4.5 §5, D1, D4, D16, D18)', () => {
  it('applies the design defaults (dlp is a default engine, stage 1)', () => {
    const config = load();
    expect(config.SCAN_ENGINES).toContain('dlp');
    expect(runsDlpConsumer(config)).toBe(true);
    expect(consumerEngines(config)).toContain('dlp');
    expect(engineBudgetFromConfig(config, 'dlp')).toEqual({
      concurrency: 4,
      timeoutMs: 120_000,
      maxAttempts: 3,
    });
    expect(config).toMatchObject({
      DLP_EXTRACTOR_POOL_SIZE: 2,
      DLP_EXTRACTOR_MAX_JOBS: 200,
      DLP_EXTRACTOR_HEAP_MB: 256,
      DLP_EXTRACT_TIMEOUT_MS: 20_000,
      DLP_EXTRACT_CPU_SECONDS: 10,
      DLP_EXTRACT_MAX_RSS_MB: 512,
      DLP_MAX_ATTACHMENTS: 50,
      DLP_ATTACHMENT_MAX_BYTES: 26_214_400,
      DLP_BYTE_BUDGET_BYTES: 67_108_864,
      DLP_PDF_MAX_PAGES: 200,
      DLP_BODY_MAX_BYTES: 4_194_304,
      DLP_TEXT_MAX_CHARS_PER_PART: 1_000_000,
      DLP_TEXT_MAX_CHARS_PER_MESSAGE: 4_000_000,
      DLP_DETECT_TIMEOUT_MS: 15_000,
      DLP_SCAN_CHUNK_CHARS: 65_536,
      DLP_MAX_MATCHES_PER_DETECTOR: 1_000,
      DLP_MAX_FINDINGS: 64,
      DLP_EVIDENCE_ENABLED: true,
      DLP_EVIDENCE_MAX_BYTES: 32_768,
      DLP_EVIDENCE_MAX_MATCHES: 50,
      DLP_EVIDENCE_SWEEP_INTERVAL_MS: 3_600_000,
      DLP_TENANT_DATA_CACHE_TTL_MS: 30_000,
      DLP_EVIDENCE_KEY_PREVIOUS: '',
    });
    expect(dlpPlatformFromConfig(config)).toEqual(DLP_PLATFORM_DEFAULTS);
  });

  it('deadline rule: dlp is stage 1 (3 x (120 + 60) = 540 s, below url) and is included', () => {
    expect(minimumRoundDeadlineSeconds(load({ SCAN_ENGINES: 'dlp' }))).toBe(540);
    refusal(
      { SCAN_ENGINES: 'dlp', SCAN_ROUND_DEADLINE_SECONDS: '539' },
      'SCAN_ROUND_DEADLINE_SECONDS',
    );
    expect(() => load({ SCAN_ENGINES: 'dlp', SCAN_ROUND_DEADLINE_SECONDS: '540' })).not.toThrow();
    // Stage-1 maximum unchanged by dlp: the default deadline still fits.
    expect(minimumRoundDeadlineSeconds(load())).toBe(
      minimumRoundDeadlineSeconds(load({ SCAN_ENGINES: 'rspamd,attachment,url,bec' })),
    );
  });

  it('DLP_EVIDENCE_KEY: exactly 64 hex where dlp consumes with evidence enabled; never echoed', () => {
    const missing = message(without('DLP_EVIDENCE_KEY'));
    expect(missing).toMatch(/DLP_EVIDENCE_KEY: is required/);
    const short = message({ ...base, DLP_EVIDENCE_KEY: 'deadbeef-secret-value' });
    expect(short).toMatch(/DLP_EVIDENCE_KEY/);
    expect(short).not.toContain('deadbeef-secret-value');
    // Not required where dlp does not consume, nor with evidence disabled.
    expect(() =>
      loadWorkerConfig({ ...without('DLP_EVIDENCE_KEY'), SCAN_CONSUMERS: 'rspamd' }),
    ).not.toThrow();
    expect(() =>
      loadWorkerConfig({ ...without('DLP_EVIDENCE_KEY'), DLP_EVIDENCE_ENABLED: 'false' }),
    ).not.toThrow();
  });

  it('DLP_EVIDENCE_KEY_PREVIOUS: empty or 64 hex, different from the current key', () => {
    expect(() => load({ DLP_EVIDENCE_KEY_PREVIOUS: 'ff'.repeat(32) })).not.toThrow();
    const same = message({ ...base, DLP_EVIDENCE_KEY_PREVIOUS: KEY.toUpperCase() });
    expect(same).toMatch(/DLP_EVIDENCE_KEY_PREVIOUS: must differ/);
    expect(same).not.toContain(KEY);
    refusal({ DLP_EVIDENCE_KEY_PREVIOUS: 'not-hex' }, 'DLP_EVIDENCE_KEY_PREVIOUS');
  });

  it('refuses attempts at the queue limit, a byte budget below one attachment and bad bounds', () => {
    refusal({ SCAN_DLP_MAX_ATTEMPTS: '10' }, 'SCAN_DLP_MAX_ATTEMPTS');
    refusal(
      { DLP_ATTACHMENT_MAX_BYTES: '2000000', DLP_BYTE_BUDGET_BYTES: '1000000' },
      'DLP_ATTACHMENT_MAX_BYTES',
    );
    refusal(
      { DLP_ATTACHMENT_MAX_BYTES: '30000000', ATTACHMENT_MAX_BYTES: '26214400' },
      'DLP_ATTACHMENT_MAX_BYTES',
    );
    refusal(
      { DLP_EXTRACT_CPU_SECONDS: '30', DLP_EXTRACT_TIMEOUT_MS: '20000' },
      'DLP_EXTRACT_CPU_SECONDS',
    );
    refusal({ DLP_EXTRACT_MAX_RSS_MB: '256' }, 'DLP_EXTRACT_MAX_RSS_MB');
    refusal({ DLP_DETECT_TIMEOUT_MS: '120000' }, 'DLP_DETECT_TIMEOUT_MS');
    refusal(
      { DLP_EXTRACT_TIMEOUT_MS: '70000', DLP_DETECT_TIMEOUT_MS: '60000' },
      'DLP_DETECT_TIMEOUT_MS',
    );
    expect(() =>
      load({ DLP_EXTRACT_TIMEOUT_MS: '60000', DLP_DETECT_TIMEOUT_MS: '59000' }),
    ).not.toThrow();
    refusal({ DLP_TEXT_MAX_CHARS_PER_PART: '5000000' }, 'DLP_TEXT_MAX_CHARS_PER_PART');
    refusal({ DLP_CONFIDENCE_THRESHOLD: '0.4' }, 'DLP_CONFIDENCE_THRESHOLD');
    refusal({ DLP_EVIDENCE_MAX_RETENTION_DAYS: '365' }, 'DLP_EVIDENCE_MAX_RETENTION_DAYS');
    refusal({ DLP_DEFAULT_POLICY: 'block' }, 'DLP_DEFAULT_POLICY');
    refusal({ DLP_EXTRACTOR_POOL_SIZE: '0' }, 'DLP_EXTRACTOR_POOL_SIZE');
    refusal({ DLP_EVIDENCE_MAX_MATCHES: '51' }, 'DLP_EVIDENCE_MAX_MATCHES');
  });

  it('refuses best-effort rlimits in production', () => {
    refusal(
      { NODE_ENV: 'production', DLP_EXTRACTOR_RLIMITS: 'best_effort' },
      'DLP_EXTRACTOR_RLIMITS',
    );
  });
});
