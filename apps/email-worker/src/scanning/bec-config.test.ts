import { BEC_PLATFORM_DEFAULTS } from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { loadWorkerConfig } from '../config';
import { becPlatformFromConfig } from './bec-config';
import {
  consumerEngines,
  engineBudgetFromConfig,
  engineQueueMaxAttempts,
  minimumRoundDeadlineSeconds,
  runsBecConsumer,
  stageDependencyViolations,
} from './config';

const SECRET_KEY = 'test-bec-context-hmac-key-0123456789abcdef';
const base = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  RABBITMQ_EMAIL_WORKER_URL: 'amqp://ew:secret-pw@localhost:5672/email-gateway',
  RABBITMQ_SCANNER_URL: 'amqp://sc:scanner-pw@localhost:5672/email-gateway',
  SCAN_RSPAMD_URL: 'http://127.0.0.1:11333',
  REDIS_URL: 'redis://localhost:6379',
  ATTACHMENT_CACHE_HMAC_KEY: 'test-content-cache-mac-key-0123456789',
  URL_CACHE_HMAC_KEY: 'test-url-cache-mac-key-0123456789abcdef',
  BEC_CONTEXT_HMAC_KEY: SECRET_KEY,
  DLP_EVIDENCE_KEY: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  URL_TOKEN_KEY_CURRENT: '0123456789abcdef'.repeat(4),
  URL_DNSBL_DOMAIN_ZONES: 'dbl.scan.test=127.0.1.2:spam,127.0.1.4:phishing',
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
  expect(() => load(env)).toThrow(new RegExp(key));

describe('bec engine config (step 4.4 §5, B2, B4, B10, B13, B16)', () => {
  it('applies the design defaults', () => {
    const config = load();
    expect(runsBecConsumer(config)).toBe(true);
    expect(engineBudgetFromConfig(config, 'bec')).toEqual({
      concurrency: 8,
      timeoutMs: 45_000,
      maxAttempts: 3,
    });
    expect(config).toMatchObject({
      BEC_TEXT_MAX_BYTES: 65_536,
      BEC_TEXT_MAX_CHARS: 40_000,
      BEC_TEXT_TIMEOUT_MS: 2_000,
      BEC_LOCAL_MODEL: 'bec-lr/1',
      BEC_LOCAL_MODEL_SHADOW: '',
      BEC_LLM_PROVIDER: 'anthropic',
      BEC_LLM_MODEL: 'claude-opus-5-5',
      BEC_LLM_SHADOW_MODEL: '',
      BEC_LLM_REFUSAL_FALLBACK: 'default',
      BEC_LLM_TIMEOUT_MS: 20_000,
      BEC_LLM_MAX_OUTPUT_TOKENS: 4_096,
      BEC_LLM_MAX_EXCERPT_CHARS: 1_500,
      BEC_LLM_MIN_SCORE: 15,
      BEC_LLM_CONCURRENCY: 4,
      BEC_LLM_MAX_CALLS_PER_MINUTE: 120,
      BEC_LLM_BREAKER_THRESHOLD: 5,
      BEC_LLM_BREAKER_RESET_MS: 60_000,
      BEC_HISTORY_MIN_MESSAGES: 3,
      BEC_HISTORY_MAX_RECIPIENTS: 50,
      BEC_HISTORY_SWEEP_INTERVAL_MS: 3_600_000,
      BEC_TENANT_DATA_CACHE_TTL_MS: 30_000,
      BEC_SUPPRESSIONS_MAX_PER_TENANT: 200,
      BEC_SUPPRESSION_MAX_WEIGHT: 40,
      BEC_MAX_EXECUTIVES: 500,
      BEC_MAX_VENDORS: 2_000,
      BEC_MAX_TRUSTED_SENDERS: 1_000,
    });
    expect(config.BEC_LLM_API_KEY).toBeUndefined();
    expect(becPlatformFromConfig(config)).toEqual(BEC_PLATFORM_DEFAULTS);
    expect(engineQueueMaxAttempts('bec')).toBe(10);
  });

  it('dependency rule (B2): a stage-2 engine needs a dependency, a round needs a stage-1 engine', () => {
    expect(stageDependencyViolations(['rspamd', 'attachment', 'url', 'bec'])).toEqual([]);
    expect(stageDependencyViolations(['rspamd', 'bec'])).toEqual([]);
    expect(stageDependencyViolations(['url', 'bec'])).toEqual([]);
    expect(stageDependencyViolations(['attachment', 'bec'])).toEqual([
      'enables bec, which depends on rspamd|url: enable at least one of them',
    ]);
    expect(stageDependencyViolations(['bec'])).toHaveLength(2);
    const text = message({ ...base, SCAN_ENGINES: 'attachment,bec' });
    expect(text).toMatch(/SCAN_ENGINES: enables bec, which depends on rspamd\|url/);
    expect(message({ ...base, SCAN_ENGINES: 'bec' })).toMatch(
      /SCAN_ENGINES: must enable at least one stage-1 engine/,
    );
    expect(() => load({ SCAN_ENGINES: 'rspamd,bec' })).not.toThrow();
  });

  it('deadline rule (B2): max over stage 1 plus max over stage 2', () => {
    // rspamd 6 x (20 + 60) = 480 + bec 3 x (45 + 60) = 315.
    expect(minimumRoundDeadlineSeconds(load({ SCAN_ENGINES: 'rspamd,bec' }))).toBe(795);
    refusal(
      { SCAN_ENGINES: 'rspamd,bec', SCAN_ROUND_DEADLINE_SECONDS: '794' },
      'SCAN_ROUND_DEADLINE_SECONDS',
    );
    expect(() =>
      load({ SCAN_ENGINES: 'rspamd,bec', SCAN_ROUND_DEADLINE_SECONDS: '795' }),
    ).not.toThrow();
    const text = message({ ...base, SCAN_ROUND_DEADLINE_SECONDS: '1754' });
    expect(text).toMatch(/stage-1 engines of SCAN_ENGINES \(rspamd, attachment, url, dlp\)/);
    expect(text).toMatch(
      /plus the maximum over the stage-2 engines \(bec\) of SCAN_BEC_MAX_ATTEMPTS/,
    );
    expect(text).toMatch(/= 1755/);
    expect(() => load({ SCAN_ROUND_DEADLINE_SECONDS: '1755' })).not.toThrow();
    // A longer bec budget moves the minimum: 1 440 + 9 x (100 + 60) = 2 880.
    refusal(
      { SCAN_BEC_MAX_ATTEMPTS: '9', SCAN_BEC_TIMEOUT_MS: '100000' },
      'SCAN_ROUND_DEADLINE_SECONDS',
    );
  });

  it('keeps the attempt budget below the scan.bec limit and the sub-budgets below the call timeout', () => {
    refusal({ SCAN_BEC_MAX_ATTEMPTS: '10' }, 'SCAN_BEC_MAX_ATTEMPTS');
    refusal({ BEC_LLM_TIMEOUT_MS: '45000' }, 'BEC_LLM_TIMEOUT_MS');
    refusal({ BEC_TEXT_TIMEOUT_MS: '50000', SCAN_BEC_TIMEOUT_MS: '50000' }, 'BEC_TEXT_TIMEOUT_MS');
    refusal({ SCAN_S3_TIMEOUT_MS: '45000' }, 'SCAN_S3_TIMEOUT_MS');
    refusal({ BEC_HISTORY_MAX_RECIPIENTS: '51' }, 'BEC_HISTORY_MAX_RECIPIENTS');
    refusal({ BEC_TENANT_DATA_CACHE_TTL_MS: '300001' }, 'BEC_TENANT_DATA_CACHE_TTL_MS');
  });

  it('validates the platform settings through the contract (B13), naming the env key', () => {
    refusal({ BEC_SUSPICIOUS_SCORE: '20' }, 'BEC_SUSPICIOUS_SCORE');
    refusal({ BEC_MALICIOUS_SCORE: '96' }, 'BEC_MALICIOUS_SCORE');
    refusal({ BEC_AI_MALICIOUS_BAND: '16' }, 'BEC_AI_MALICIOUS_BAND');
    refusal({ BEC_AI_CORROBORATE_CONFIDENCE: '0.7' }, 'BEC_AI_CORROBORATE_CONFIDENCE');
    refusal({ BEC_AI_RAISE_CONFIDENCE: '0.5' }, 'BEC_AI_RAISE_CONFIDENCE');
    refusal({ BEC_HISTORY_DEFAULT_RETENTION_DAYS: '800' }, 'BEC_HISTORY_DEFAULT_RETENTION_DAYS');
    refusal({ BEC_LOCAL_MODEL_MODE: 'loud' }, 'BEC_LOCAL_MODEL_MODE');
    refusal({ BEC_SUSPICIOUS_SCORE: '60', BEC_MALICIOUS_SCORE: '60' }, 'BEC_SUSPICIOUS_SCORE');
  });

  it('LLM key rule (B10): a mode other than off with anthropic needs the key where bec consumes', () => {
    const noKey = message({ ...base, BEC_LLM_MODE: 'shadow' });
    expect(noKey).toMatch(/BEC_LLM_API_KEY: is required when BEC_LLM_MODE is not off/);
    expect(() =>
      load({ BEC_LLM_MODE: 'active', BEC_LLM_API_KEY: 'sk-ant-test-key-never-printed' }),
    ).not.toThrow();
    // Not consuming bec here: the key lives only on the bec replica.
    expect(() => load({ BEC_LLM_MODE: 'active', SCAN_CONSUMERS: 'rspamd,url' })).not.toThrow();
    // The fake provider needs no key.
    expect(() => load({ BEC_LLM_MODE: 'active', BEC_LLM_PROVIDER: 'fake' })).not.toThrow();
    // An empty key counts as unset (loadConfig drops empty values).
    expect(message({ ...base, BEC_LLM_MODE: 'shadow', BEC_LLM_API_KEY: '' })).toMatch(
      /BEC_LLM_API_KEY/,
    );
    // Errors never echo the key.
    const text = message({
      ...base,
      BEC_LLM_MODE: 'active',
      BEC_LLM_API_KEY: 'sk-ant-zz',
      SCAN_BEC_MAX_ATTEMPTS: '12',
    });
    expect(text).not.toContain('sk-ant-zz');
  });

  it('refuses the fake LLM provider in production (B10)', () => {
    refusal({ BEC_LLM_PROVIDER: 'fake', NODE_ENV: 'production' }, 'BEC_LLM_PROVIDER');
    expect(() => load({ BEC_LLM_PROVIDER: 'fake', NODE_ENV: 'test' })).not.toThrow();
  });

  it('requires the context HMAC key (>= 32) where bec consumes, never echoing it', () => {
    expect(message(without('BEC_CONTEXT_HMAC_KEY'))).toMatch(/BEC_CONTEXT_HMAC_KEY: is required/);
    const short = message({ ...base, BEC_CONTEXT_HMAC_KEY: 'too-short-secret-value' });
    expect(short).toMatch(/BEC_CONTEXT_HMAC_KEY/);
    expect(short).not.toContain('too-short-secret-value');
    const replica = load({
      ...without('BEC_CONTEXT_HMAC_KEY'),
      SCAN_CONSUMERS: 'rspamd,attachment,url',
    });
    expect(consumerEngines(replica)).toEqual(['rspamd', 'attachment', 'url']);
    expect(runsBecConsumer(replica)).toBe(false);
    expect(runsBecConsumer(load({ SCAN_ENGINES: 'rspamd,url' }))).toBe(false);
  });

  it('refuses local models that are not in the packaged manifest (B16)', () => {
    refusal({ BEC_LOCAL_MODEL: 'bec-lr/9' }, 'BEC_LOCAL_MODEL');
    expect(message({ ...base, BEC_LOCAL_MODEL: 'bec-lr/9' })).toMatch(
      /not in models\/manifest.json/,
    );
    refusal({ BEC_LOCAL_MODEL_SHADOW: 'bec-lr/2' }, 'BEC_LOCAL_MODEL_SHADOW');
    refusal({ BEC_LOCAL_MODEL_SHADOW: 'bec-lr/1' }, 'BEC_LOCAL_MODEL_SHADOW');
    refusal({ BEC_LOCAL_MODEL: 'not a version' }, 'BEC_LOCAL_MODEL');
    refusal({ BEC_LLM_SHADOW_MODEL: 'claude-opus-5-5' }, 'BEC_LLM_SHADOW_MODEL');
    refusal({ BEC_LLM_MODEL: 'Claude Opus' }, 'BEC_LLM_MODEL');
  });
});
