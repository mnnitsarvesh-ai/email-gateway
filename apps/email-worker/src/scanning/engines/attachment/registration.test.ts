import { ATTACHMENT_MAPPING_VERSION } from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { loadWorkerConfig } from '../../../config';
import { ENGINE_REGISTRY, enabledRegistrations } from '../../registry';
import { BUNDLED_RULES_DIR } from './inspector/bundle';
import {
  ATTACHMENT_CONSUMER,
  attachmentRegistration,
  attachmentSettingsFor,
  inspectLimitsFromConfig,
  rulesDirOf,
} from './registration';

const config = loadWorkerConfig({
  DATABASE_URL: 'mysql://t:t@localhost:3306/t',
  RABBITMQ_EMAIL_WORKER_URL: 'amqp://a:b@localhost:5672/v',
  RABBITMQ_SCANNER_URL: 'amqp://a:b@localhost:5672/v',
  SCAN_RSPAMD_URL: 'http://127.0.0.1:11333',
  REDIS_URL: 'redis://localhost:6379',
  ATTACHMENT_CACHE_HMAC_KEY: 'test-content-cache-mac-key-0123456789',
  URL_CACHE_HMAC_KEY: 'test-url-cache-mac-key-0123456789abcdef',
  BEC_CONTEXT_HMAC_KEY: 'test-bec-context-hmac-key-0123456789abcdef',
  URL_TOKEN_KEY_CURRENT: '0123456789abcdef'.repeat(4),
  URL_DNSBL_DOMAIN_ZONES: 'dbl.scan.test=127.0.1.2:spam,127.0.1.4:phishing',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
});

describe('attachment engine registration (step 4.2 A1, A8, A12)', () => {
  it('is registered on scan.attachment with its ledger consumer and budget', () => {
    expect(ENGINE_REGISTRY.map((r) => r.catalog.name)).toEqual([
      'rspamd',
      'attachment',
      'url',
      'bec',
    ]);
    expect(enabledRegistrations(['rspamd', 'attachment']).map((r) => r.consumerName)).toEqual([
      'email-worker.scan.rspamd',
      ATTACHMENT_CONSUMER,
    ]);
    expect(ATTACHMENT_CONSUMER).toBe('email-worker.scan.attachment');
    expect(attachmentRegistration.catalog).toMatchObject({
      queue: 'scan.attachment',
      requiredByDefault: true,
      tenantMayDisable: false,
    });
    expect(attachmentRegistration.budget(config)).toEqual({
      concurrency: 4,
      timeoutMs: 180_000,
      maxAttempts: 6,
    });
  });

  it('resolves tenant settings and falls back to the platform for an invalid row', () => {
    const none = attachmentSettingsFor(config, null);
    expect(none).toMatchObject({ invalidRow: false, violations: [] });
    expect(none.settingsVersion).toMatch(
      new RegExp(`^${ATTACHMENT_MAPPING_VERSION};p=[0-9a-f]{12};t=none$`),
    );
    const tuned = attachmentSettingsFor(config, {
      settings: { deniedTypes: ['pdf'], typeMismatchVerdict: 'malicious' },
      version: 3,
    });
    expect(tuned.invalidRow).toBe(false);
    expect(tuned.settingsVersion.endsWith(';t=3')).toBe(true);
    expect((tuned.settings as { deniedTypes: string[] }).deniedTypes).toContain('pdf');
    const invalid = attachmentSettingsFor(config, {
      settings: { deniedTypeVerdict: 'clean', bogus: 1 },
      version: 4,
    });
    expect(invalid.invalidRow).toBe(true);
    expect(invalid.violations).toEqual(['invalid', 'unknown_key']);
    expect(invalid.settingsVersion.endsWith(';t=none')).toBe(true);
    const lowered = attachmentSettingsFor(config, {
      settings: { maxAttachmentBytes: 10 },
      version: 5,
    });
    expect(lowered).toMatchObject({ invalidRow: true, violations: ['out_of_bounds'] });
  });

  it('derives the inspector limits and the rules directory from the config', () => {
    expect(inspectLimitsFromConfig(config)).toEqual({
      archiveMaxDepth: 3,
      archiveMaxEntries: 1000,
      maxEntryBytes: 26_214_400,
      maxDecompressedBytes: 104_857_600,
      maxCompressionRatio: 100,
      maxEntryFindings: 20,
      yaraTimeoutMs: 10_000,
      cpuSeconds: 10,
      maxRssMb: 384,
    });
    expect(rulesDirOf(config)).toBe(BUNDLED_RULES_DIR);
    expect(rulesDirOf({ ...config, ATTACHMENT_YARA_RULES_DIR: '/feed' })).toBe('/feed');
  });
});
