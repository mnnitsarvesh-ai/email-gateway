import { describe, expect, it } from 'vitest';
import { loadWorkerConfig } from '../../config';

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
const refusal = (env: Record<string, string>, key: string) =>
  expect(() => load(env)).toThrow(new RegExp(`${key}:`));

describe('risk scoring config (step 5.1 R16, §5)', () => {
  it('applies the design defaults', () => {
    const config = load();
    expect(config.RISK_PLATFORM_PROFILE).toBe('rsk-default/1');
    expect(config.RISK_PROFILE_CACHE_MAX_ENTRIES).toBe(10_000);
  });

  it('accepts a shipped platform profile and refuses any other id', () => {
    expect(load({ RISK_PLATFORM_PROFILE: 'rsk-default/1' }).RISK_PLATFORM_PROFILE).toBe(
      'rsk-default/1',
    );
    for (const value of ['rsk-default/2', 'rsk-default', 'custom']) {
      refusal({ RISK_PLATFORM_PROFILE: value }, 'RISK_PLATFORM_PROFILE');
    }
  });

  it('bounds the profile cache to 100..100000 entries', () => {
    expect(load({ RISK_PROFILE_CACHE_MAX_ENTRIES: '100' }).RISK_PROFILE_CACHE_MAX_ENTRIES).toBe(
      100,
    );
    expect(load({ RISK_PROFILE_CACHE_MAX_ENTRIES: '100000' }).RISK_PROFILE_CACHE_MAX_ENTRIES).toBe(
      100_000,
    );
    for (const value of ['99', '100001', '0', '-1', '1.5', 'many']) {
      refusal({ RISK_PROFILE_CACHE_MAX_ENTRIES: value }, 'RISK_PROFILE_CACHE_MAX_ENTRIES');
    }
  });

  it('never prints the value of a refused key', () => {
    try {
      load({ RISK_PLATFORM_PROFILE: 'secret-looking-value' });
      expect.unreachable();
    } catch (error) {
      expect((error as Error).message).not.toContain('secret-looking-value');
    }
  });
});
