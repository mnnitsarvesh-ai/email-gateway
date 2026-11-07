import {
  AI_FEATURE_NAMES as PACKAGE_FEATURES,
  AI_INDICATORS as PACKAGE_INDICATORS,
  BEC_MAPPER_CODES,
  BEC_RULE_IDS as PACKAGE_RULE_IDS,
  BEC_RULES as PACKAGE_RULES,
  BEC_RULES_VERSION,
  BEC_SUPPRESSIBLE_CODES as PACKAGE_SUPPRESSIBLE,
  FakeBecLlmProvider,
} from '@email-gateway/bec';
import { MetricsService } from '@email-gateway/common';
import { createLogger } from '@email-gateway/logger';
import {
  AI_FEATURE_NAMES,
  AI_INDICATORS,
  BEC_MAPPING_VERSION,
  BEC_REASON_CODES,
  BEC_RULE_IDS,
  BEC_RULES,
  BEC_SUPPRESSIBLE_CODES,
  REASON_CODE_PATTERN,
} from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { loadWorkerConfig } from '../../../config';
import { ENGINE_REGISTRY, enabledRegistrations } from '../../registry';
import { ScanMetrics } from '../../scan-metrics';
import { mergeInfra } from '../../scan-repository';
import { BecMetrics } from './bec-metrics';
import {
  BEC_CONSUMER,
  becRegistration,
  becSettingsFor,
  createBecEngine,
  createLlmProviders,
} from './registration';

const base = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  RABBITMQ_EMAIL_WORKER_URL: 'amqp://ew:secret-pw@localhost:5672/email-gateway',
  RABBITMQ_SCANNER_URL: 'amqp://sc:scanner-pw@localhost:5672/email-gateway',
  SCAN_RSPAMD_URL: 'http://127.0.0.1:11333',
  REDIS_URL: 'redis://localhost:6379',
  ATTACHMENT_CACHE_HMAC_KEY: 'test-content-cache-mac-key-0123456789',
  URL_CACHE_HMAC_KEY: 'test-url-cache-mac-key-0123456789abcdef',
  BEC_CONTEXT_HMAC_KEY: 'test-bec-context-hmac-key-0123456789abcdef',
  // Step 4.5: dlp is a default engine (D1); a synthetic evidence key for its consumer.
  DLP_EVIDENCE_KEY: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  URL_TOKEN_KEY_CURRENT: '0123456789abcdef'.repeat(4),
  URL_DNSBL_DOMAIN_ZONES: 'dbl.scan.test=127.0.1.2:spam,127.0.1.4:phishing',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
};
const load = (env: Record<string, string> = {}) => loadWorkerConfig({ ...base, ...env });
const logger = createLogger({ service: 'test', level: 'silent' });

describe('bec engine registration (step 4.4 B1, B13, B16)', () => {
  it('is registered on scan.bec as a stage-2 engine with its ledger consumer and budget', () => {
    expect(ENGINE_REGISTRY.map((r) => r.catalog.name)).toContain('bec');
    expect(becRegistration.catalog).toMatchObject({
      name: 'bec',
      queue: 'scan.bec',
      requiredByDefault: true,
      tenantMayDisable: false,
      dependsOn: ['rspamd', 'url'],
    });
    expect(BEC_CONSUMER).toBe('email-worker.scan.bec');
    expect(becRegistration.consumerName).toBe(BEC_CONSUMER);
    expect(becRegistration.budget(load())).toEqual({
      concurrency: 8,
      timeoutMs: 45_000,
      maxAttempts: 3,
    });
    expect(enabledRegistrations(['rspamd', 'url', 'bec']).map((r) => r.catalog.name)).toEqual([
      'rspamd',
      'url',
      'bec',
    ]);
  });

  it('resolves tenant settings within the platform bounds; an invalid row falls back (B13)', () => {
    const config = load({ BEC_LLM_MODE: 'shadow', BEC_LLM_PROVIDER: 'fake' });
    const platform = becSettingsFor(config, null);
    expect(platform).toMatchObject({
      invalidRow: false,
      settings: {
        suspiciousScore: 40,
        maliciousScore: 80,
        history: { enabled: false, retentionDays: 365 },
        ai: { localModel: 'shadow', llm: 'off', llmDailyCallLimit: 1000, raiseConfidence: 0.8 },
      },
    });
    expect(platform.settingsVersion).toMatch(/^bec-map\/1;p=[0-9a-f]{12};t=none$/);
    const tenant = becSettingsFor(config, {
      settings: {
        suspiciousScore: 30,
        history: { enabled: true, retentionDays: 90 },
        ai: { llm: 'shadow' },
      },
      version: 4,
    });
    expect(tenant).toMatchObject({
      invalidRow: false,
      settingsVersion: expect.stringMatching(/;t=4$/),
      settings: {
        suspiciousScore: 30,
        history: { enabled: true, retentionDays: 90 },
        ai: { llm: 'shadow' },
      },
    });
    // Above the platform cap (llm active > shadow) or unknown keys: platform settings applied.
    const invalid = becSettingsFor(config, {
      settings: { ai: { llm: 'active' }, color: 'red' },
      version: 5,
    });
    expect(invalid).toMatchObject({ invalidRow: true, settings: { ai: { llm: 'off' } } });
    expect(invalid.violations).toEqual(expect.arrayContaining(['unknown_key']));
    expect(invalid.settingsVersion).toMatch(/;t=none$/);
  });

  it('builds LLM providers per mode: none when off, fake refused in production, anthropic needs the key', () => {
    const metrics = BecMetrics.for(new MetricsService({ service: 'bec-reg-test' }));
    expect(createLlmProviders(load(), metrics)).toEqual({ active: null, shadow: null });
    const fake = createLlmProviders(
      load({
        BEC_LLM_MODE: 'active',
        BEC_LLM_PROVIDER: 'fake',
        BEC_LLM_SHADOW_MODEL: 'fake-shadow',
      }),
      metrics,
    );
    expect(fake.active).toBeInstanceOf(FakeBecLlmProvider);
    expect(fake.shadow).toBeInstanceOf(FakeBecLlmProvider);
    expect(() => new FakeBecLlmProvider({ nodeEnv: 'production' })).toThrow(/production/);
    const anthropic = createLlmProviders(
      load({ BEC_LLM_MODE: 'active', BEC_LLM_API_KEY: 'sk-ant-test-never-used' }),
      metrics,
      () => Promise.reject(new Error('no network in unit tests')),
    );
    expect(anthropic.active).toMatchObject({ kind: 'llm', modelId: 'claude-opus-5-5' });
    expect(anthropic.shadow).toBeNull();
  });

  it('creates the engine with the packaged model and lexicons; refuses without the context key', async () => {
    const registry = new MetricsService({ service: 'bec-reg-create' });
    const metrics = new ScanMetrics(registry);
    const deps = {
      logger,
      prisma: {} as never,
      s3: { client: {} as never, mailBucket: 'test-mail' },
      redis: null,
      metrics,
      registry,
    };
    const engine = createBecEngine({ ...deps, config: load() });
    expect(engine.name).toBe('bec');
    expect(engine.engineVersion).toMatch(/^bec\/1;lex=[0-9a-f]{8};fm=[0-9a-f]{8};br=[0-9a-f]{8}$/);
    const text = await registry.metrics();
    expect(text).toMatch(
      new RegExp(
        `scan_engine_info\\{engine="bec",version="${engine.engineVersion.replace(/[/;=]/g, '.')}"`,
      ),
    );
    expect(text).toMatch(
      /bec_model_info\{layer="local",model="bec-lr",version="bec-lr\/1@[0-9a-f]{12}",mode="shadow"[^}]*\} 1/,
    );
    expect(text).toMatch(/bec_llm_breaker_state\{[^}]*\} 0/);
    expect(text).toMatch(/bec_llm_budget_total\{result="unavailable"[^}]*\} 0/);
    expect(() =>
      createBecEngine({ ...deps, config: { ...load(), BEC_CONTEXT_HMAC_KEY: undefined } }),
    ).toThrow(/BEC_CONTEXT_HMAC_KEY/);
  });
});

describe('shared BEC lists (step 4.4 B6 contract: @email-gateway/bec == security-contracts)', () => {
  it('BEC_MAPPER_CODES equals BEC_REASON_CODES (same order) and every code is a valid reason code', () => {
    expect([...BEC_MAPPER_CODES]).toEqual([...BEC_REASON_CODES]);
    for (const code of BEC_MAPPER_CODES) expect(code).toMatch(REASON_CODE_PATTERN);
    expect(BEC_RULES_VERSION).toBe(BEC_MAPPING_VERSION);
  });

  it('rule ids, rule codes/categories, suppressible codes, AI indicators and features are identical', () => {
    expect([...PACKAGE_RULE_IDS]).toEqual([...BEC_RULE_IDS]);
    for (const rule of PACKAGE_RULES) {
      expect(BEC_RULES[rule.id as keyof typeof BEC_RULES]).toEqual({
        code: rule.code,
        category: rule.category,
      });
    }
    expect([...PACKAGE_SUPPRESSIBLE]).toEqual([...BEC_SUPPRESSIBLE_CODES]);
    expect([...PACKAGE_INDICATORS]).toEqual([...AI_INDICATORS]);
    expect([...PACKAGE_FEATURES]).toEqual([...AI_FEATURE_NAMES]);
  });
});

describe('mergeInfra (B12 sender fingerprints)', () => {
  const at = (iso: string) => new Date(iso);
  it('adds, refreshes (count + latest time) and keeps the 8 most recent fingerprints', () => {
    const first = mergeInfra(null, { fp: '0000000000000001', seenAt: at('2026-01-01T00:00:00Z') });
    expect(first).toEqual([
      { fp: '0000000000000001', count: 1, lastSeenAt: '2026-01-01T00:00:00.000Z' },
    ]);
    const again = mergeInfra(JSON.stringify(first), {
      fp: '0000000000000001',
      seenAt: at('2025-12-01T00:00:00Z'),
    });
    expect(again).toEqual([
      { fp: '0000000000000001', count: 2, lastSeenAt: '2026-01-01T00:00:00.000Z' },
    ]);
    let list: unknown = again;
    for (let i = 2; i <= 10; i += 1) {
      list = mergeInfra(list, {
        fp: i.toString(16).padStart(16, '0'),
        seenAt: at(`2026-02-${String(i).padStart(2, '0')}T00:00:00Z`),
      });
    }
    const final = list as Array<{ fp: string }>;
    expect(final).toHaveLength(8);
    expect(final[0]!.fp).toBe('000000000000000a');
    expect(final.some((e) => e.fp === '0000000000000001')).toBe(false);
    // Malformed stored entries are dropped, never trusted.
    expect(
      mergeInfra([{ fp: 'zz', count: 1, lastSeenAt: 'x' }, 'junk'], {
        fp: 'abcdefabcdefabcd',
        seenAt: at('2026-01-01T00:00:00Z'),
      }),
    ).toHaveLength(1);
  });
});
