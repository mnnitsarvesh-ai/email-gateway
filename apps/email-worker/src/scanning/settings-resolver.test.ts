import { createLogger } from '@email-gateway/logger';
import { describe, expect, it } from 'vitest';
import { loadWorkerConfig } from '../config';
import { rspamdRegistration } from './engines/rspamd/registration';
import { newMetrics } from './fakes.test-support';
import type { EngineSettingsRow } from './registry';
import { SettingsResolver } from './settings-resolver';

const config = loadWorkerConfig({
  DATABASE_URL: 'mysql://t:t@localhost:3306/t',
  RABBITMQ_EMAIL_WORKER_URL: 'amqp://a:b@localhost:5672/v',
  RABBITMQ_SCANNER_URL: 'amqp://a:b@localhost:5672/v',
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

function setup(rows: Record<string, EngineSettingsRow>, ttlMs = 30_000, maxEntries?: number) {
  let now = 0;
  let loads = 0;
  const warnings: unknown[] = [];
  const logger = createLogger({ service: 'test', level: 'silent' });
  logger.warn = (details: unknown) => void warnings.push(details);
  const { metrics, registry } = newMetrics();
  const resolver = new SettingsResolver({
    source: {
      loadEngineSettings: (org, engine) => {
        loads += 1;
        return Promise.resolve(rows[`${org.toString()}:${engine}`] ?? null);
      },
    },
    config,
    metrics,
    logger,
    ttlMs,
    ...(maxEntries ? { maxEntries } : {}),
    now: () => now,
  });
  return { resolver, registry, warnings, loads: () => loads, advance: (ms: number) => (now += ms) };
}

describe('SettingsResolver (S8)', () => {
  it('applies a valid tenant row and records its version', async () => {
    const { resolver } = setup({
      '1:rspamd': { settings: { spamScore: 8, suspiciousScore: 5 }, version: 3 },
    });
    const r = await resolver.resolve(rspamdRegistration, 1n);
    expect(r.settings).toMatchObject({
      spamScore: 8,
      suspiciousScore: 5,
      phishingVerdict: 'suspicious',
    });
    expect(r.settingsVersion).toMatch(/^rspamd-map\/2;p=[0-9a-f]{12};t=3$/);
    expect(r.invalidRow).toBe(false);
    const none = await resolver.resolve(rspamdRegistration, 2n);
    expect(none.settingsVersion).toMatch(/;t=none$/);
  });

  it('an invalid row falls back to the platform settings, counted every time and logged once per version', async () => {
    const rows = { '1:rspamd': { settings: { spamScore: 99, extra: true }, version: 2 } };
    const { resolver, registry, warnings, advance } = setup(rows, 10);
    const a = await resolver.resolve(rspamdRegistration, 1n);
    expect(a.invalidRow).toBe(true);
    expect(a.settings).toMatchObject({ spamScore: 6, suspiciousScore: 4 });
    expect(a.settingsVersion).toMatch(/;t=none$/);
    expect(a.violations.sort()).toEqual(['unknown_key']);
    advance(20);
    await resolver.resolve(rspamdRegistration, 1n);
    expect(warnings).toHaveLength(1);
    expect(JSON.stringify(warnings[0])).not.toContain('99');
    expect(await registry.metrics()).toMatch(
      /scan_settings_invalid_total\{engine="rspamd"[^}]*\} 2/,
    );
    // A corrected row (a new version) applies again.
    rows['1:rspamd'] = { settings: { spamScore: 7 } as never, version: 3 };
    advance(20);
    expect((await resolver.resolve(rspamdRegistration, 1n)).invalidRow).toBe(false);
  });

  it('caches per (organization, engine) within the TTL', async () => {
    const { resolver, registry, loads, advance } = setup({});
    await resolver.resolve(rspamdRegistration, 1n);
    await resolver.resolve(rspamdRegistration, 1n);
    expect(loads()).toBe(1);
    advance(30_000);
    await resolver.resolve(rspamdRegistration, 1n);
    expect(loads()).toBe(2);
    const text = await registry.metrics();
    expect(text).toMatch(/scan_settings_cache_total\{result="hit"[^}]*\} 1/);
    expect(text).toMatch(/scan_settings_cache_total\{result="miss"[^}]*\} 2/);
  });

  it('TTL 0 disables the cache; the cache is bounded (LRU)', async () => {
    const none = setup({}, 0);
    await none.resolver.resolve(rspamdRegistration, 1n);
    await none.resolver.resolve(rspamdRegistration, 1n);
    expect(none.loads()).toBe(2);
    const lru = setup({}, 30_000, 2);
    await lru.resolver.resolve(rspamdRegistration, 1n);
    await lru.resolver.resolve(rspamdRegistration, 2n);
    await lru.resolver.resolve(rspamdRegistration, 1n); // 1 is most recent
    await lru.resolver.resolve(rspamdRegistration, 3n); // evicts 2
    expect(lru.resolver.size).toBe(2);
    await lru.resolver.resolve(rspamdRegistration, 1n);
    expect(lru.loads()).toBe(3);
    await lru.resolver.resolve(rspamdRegistration, 2n);
    expect(lru.loads()).toBe(4);
  });
});
