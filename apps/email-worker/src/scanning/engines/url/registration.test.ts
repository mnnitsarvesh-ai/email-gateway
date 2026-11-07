import { MetricsService } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import { createLogger } from '@email-gateway/logger';
import { RestrictedResolver } from '@email-gateway/url-security';
import { describe, expect, it } from 'vitest';
import { loadWorkerConfig } from '../../../config';
import { ENGINE_REGISTRY, enabledRegistrations } from '../../registry';
import { ScanMetrics } from '../../scan-metrics';
import {
  createUrlEngine,
  dnsProbe,
  URL_CONSUMER,
  urlLimitsFromConfig,
  urlRegistration,
  urlSettingsFor,
} from './registration';

const config = loadWorkerConfig({
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
});
const logger = createLogger({ service: 'url-registration-test', level: 'silent' });

function deps(overrides: Record<string, unknown> = {}) {
  const registry = new MetricsService({ service: 'url-registration-test' });
  return {
    config: { ...config, ...overrides } as typeof config,
    logger,
    prisma: {} as PrismaClient,
    s3: { client: {} as never, mailBucket: 'test-mail' },
    redis: {
      client: { get: () => Promise.resolve(null), set: () => Promise.resolve('OK') } as never,
    },
    metrics: new ScanMetrics(registry),
    registry,
  };
}

describe('url engine registration (step 4.3 U1, U13)', () => {
  it('is registered on scan.url with its ledger consumer and budget', () => {
    expect(ENGINE_REGISTRY.map((r) => r.catalog.name)).toContain('url');
    expect(enabledRegistrations(['url']).map((r) => r.consumerName)).toEqual([URL_CONSUMER]);
    expect(URL_CONSUMER).toBe('email-worker.scan.url');
    expect(urlRegistration.catalog).toMatchObject({
      name: 'url',
      stage: 'url',
      queue: 'scan.url',
      requiredByDefault: true,
      tenantMayDisable: false,
    });
    expect(urlRegistration.budget(config)).toEqual({
      concurrency: 4,
      timeoutMs: 120_000,
      maxAttempts: 6,
    });
  });

  it('resolves tenant settings and falls back to the platform for an invalid row', () => {
    const none = urlSettingsFor(config, null);
    expect(none).toMatchObject({ invalidRow: false, violations: [] });
    expect(none.settingsVersion).toMatch(/^url-map\/1;p=[0-9a-f]{12};t=none$/);
    const tuned = urlSettingsFor(config, {
      settings: { blockedDomains: ['evil.example'], rewrite: { expiryDays: 7 } },
      version: 3,
    });
    expect(tuned.invalidRow).toBe(false);
    expect(tuned.settingsVersion.endsWith(';t=3')).toBe(true);
    expect(tuned.settings).toMatchObject({
      blockedDomains: ['evil.example'],
      rewrite: { expiryDays: 7, enabled: true },
    });
    const invalid = urlSettingsFor(config, {
      settings: { scanTimeFetch: 'nope', bogus: 1 },
      version: 4,
    });
    expect(invalid).toMatchObject({ invalidRow: true });
    expect(invalid.violations.sort()).toEqual(['invalid', 'unknown_key']);
    expect(invalid.settingsVersion.endsWith(';t=none')).toBe(true);
    expect(invalid.settings).toEqual(none.settings);
    // A tenant may not fetch more than the platform (out_of_bounds), nor expire tokens later.
    expect(
      urlSettingsFor(config, { settings: { scanTimeFetch: 'all' }, version: 5 }),
    ).toMatchObject({
      invalidRow: true,
      violations: ['out_of_bounds'],
    });
    expect(
      urlSettingsFor(config, { settings: { rewrite: { expiryDays: 91 } }, version: 6 }),
    ).toMatchObject({
      invalidRow: true,
      violations: ['out_of_bounds'],
    });
  });

  it('derives the engine limits from the config', () => {
    expect(urlLimitsFromConfig(config)).toEqual({
      maxUrls: 200,
      maxOccurrences: 5_000,
      maxLength: 2_048,
      maxPartBytes: 10_485_760,
      maxExtraParts: 5,
      extraPartMaxBytes: 2_097_152,
      extractTimeoutMs: 5_000,
      fetchMaxPerMessage: 10,
      suspiciousHops: 4,
      dynamicMaxPerMessage: 3,
      dynamicPendingTtlSeconds: 3_600,
      rewriteMaxMessageBytes: 26_214_400,
      rewriteMaxPartBytes: 5_242_880,
      maxHeadSize: config.MIME_MAX_HEADER_BLOCK_BYTES,
      maxExpiryDays: 90,
    });
  });

  it('builds the engine: engine version ≤ 64, provider breakers reported, cache required', async () => {
    const d = deps();
    const engine = createUrlEngine(d);
    expect(engine.name).toBe('url');
    expect(engine.cache).not.toBeNull();
    const version = (engine as unknown as { options: { engineVersion: string } }).options
      .engineVersion;
    expect(version).toMatch(/^url\/2;url-fetch\/1;[0-9a-f]{8};[0-9a-f]{8}$/);
    expect(version.length).toBeLessThanOrEqual(64);
    // The same inputs give the same version (part of the result rows).
    expect(
      (createUrlEngine(deps()) as unknown as { options: { engineVersion: string } }).options
        .engineVersion,
    ).toBe(version);
    expect(await d.registry.metrics()).toMatch(
      /url_provider_breaker_state\{provider="local_feed"[^}]*\} 0/,
    );
    expect(() => createUrlEngine({ ...deps(), redis: null })).toThrow(/REDIS_URL/);
    expect(createUrlEngine(deps({ URL_CACHE_ENABLED: false })).cache).toBeNull();
    expect(() => createUrlEngine(deps({ URL_TOKEN_KEY_CURRENT: undefined }))).toThrow(
      /URL_TOKEN_KEY_CURRENT/,
    );
    expect(() =>
      createUrlEngine(deps({ URL_REPUTATION_PROVIDERS: ['local_feed', 'urlhaus'] })),
    ).toThrow(/not implemented/);
  });

  it('probes the resolver: an answer of any kind is reachable, a refused socket is not', async () => {
    const answering = new RestrictedResolver({}, () => ({
      resolve4: () => Promise.reject(Object.assign(new Error('x'), { code: 'ENOTFOUND' })),
      resolve6: () => Promise.reject(Object.assign(new Error('x'), { code: 'ENOTFOUND' })),
      cancel: () => undefined,
    }));
    expect(await dnsProbe(answering)).toBe('ok');
    const refusedAnswer = new RestrictedResolver({}, () => ({
      resolve4: () => Promise.reject(Object.assign(new Error('x'), { code: 'EREFUSED' })),
      resolve6: () => Promise.reject(Object.assign(new Error('x'), { code: 'EREFUSED' })),
      cancel: () => undefined,
    }));
    expect(await dnsProbe(refusedAnswer)).toBe('ok');
    const down = new RestrictedResolver({}, () => ({
      resolve4: () => Promise.reject(Object.assign(new Error('x'), { code: 'ECONNREFUSED' })),
      resolve6: () => Promise.reject(Object.assign(new Error('x'), { code: 'ECONNREFUSED' })),
      cancel: () => undefined,
    }));
    expect(await dnsProbe(down)).toBe('unreachable');
    const timeout = new RestrictedResolver({}, () => ({
      resolve4: () => Promise.reject(Object.assign(new Error('x'), { code: 'ETIMEOUT' })),
      resolve6: () => Promise.reject(Object.assign(new Error('x'), { code: 'ETIMEOUT' })),
      cancel: () => undefined,
    }));
    expect(await dnsProbe(timeout)).toBe('unreachable');
  });
});
