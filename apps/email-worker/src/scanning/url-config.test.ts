import { URL_PLATFORM_DEFAULTS } from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { loadWorkerConfig } from '../config';
import {
  consumerEngines,
  engineBudgetFromConfig,
  engineQueueMaxAttempts,
  minimumRoundDeadlineSeconds,
  runsUrlConsumer,
} from './config';
import { isDnsServer, urlPlatformFromConfig, urlProductionLike } from './url-config';

const KEY = '0123456789abcdef'.repeat(4);
const OTHER_KEY = 'fedcba9876543210'.repeat(4);

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
  URL_TOKEN_KEY_CURRENT: KEY,
  URL_DNSBL_DOMAIN_ZONES: 'dbl.scan.test=127.0.1.2:spam,127.0.1.4:phishing',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
};

const load = (env: Record<string, string | undefined> = {}) =>
  loadWorkerConfig({ ...base, ...env });
const without = (...keys: string[]) =>
  Object.fromEntries(Object.entries(base).filter(([k]) => !keys.includes(k)));
const refusal = (env: Record<string, string | undefined>, key: string) =>
  expect(() => load(env)).toThrow(new RegExp(key));
/** Without base keys (the base would put them back). */
const loadExact = (env: Record<string, string>) => loadWorkerConfig(env);
/** Production as the k8s manifest runs it (NODE_ENV and APP_ENV production). */
const PROD = {
  NODE_ENV: 'production',
  APP_ENV: 'production',
  URL_CLICK_BASE_URL: 'https://protect.example.com',
};

describe('url engine config (step 4.3 §5, U17)', () => {
  it('applies the design defaults (SCAN_ENGINES includes url)', () => {
    const config = load();
    expect(config.SCAN_ENGINES).toEqual(['rspamd', 'attachment', 'url', 'bec', 'dlp']);
    expect(runsUrlConsumer(config)).toBe(true);
    expect(engineBudgetFromConfig(config, 'url')).toEqual({
      concurrency: 4,
      timeoutMs: 120_000,
      maxAttempts: 6,
    });
    expect(config).toMatchObject({
      URL_MAX_PER_MESSAGE: 200,
      URL_MAX_OCCURRENCES: 5_000,
      URL_MAX_LENGTH: 2_048,
      URL_MAX_PART_BYTES: 10_485_760,
      URL_MAX_EXTRA_PARTS: 5,
      URL_EXTRA_PART_MAX_BYTES: 2_097_152,
      URL_EXTRACT_TIMEOUT_MS: 5_000,
      URL_REPUTATION_PROVIDERS: ['local_feed', 'dnsbl'],
      URL_PROVIDER_TIMEOUT_MS: 3_000,
      URL_PROVIDER_CONCURRENCY: 16,
      URL_PROVIDER_BREAKER_THRESHOLD: 5,
      URL_PROVIDER_BREAKER_RESET_MS: 30_000,
      URL_DNS_SERVERS: [],
      URL_DNS_TIMEOUT_MS: 2_000,
      URL_DNS_TRIES: 2,
      URL_CACHE_ENABLED: true,
      URL_CACHE_CLEAN_TTL_SECONDS: 900,
      URL_CACHE_MALICIOUS_TTL_SECONDS: 86_400,
      URL_CACHE_OTHER_TTL_SECONDS: 300,
      URL_CACHE_ERROR_TTL_SECONDS: 30,
      URL_CACHE_TIMEOUT_MS: 200,
      URL_SCAN_TIME_FETCH: 'suspicious',
      URL_FETCH_MAX_PER_MESSAGE: 10,
      URL_FETCH_MAX_HOPS: 8,
      URL_FETCH_SUSPICIOUS_HOPS: 4,
      URL_FETCH_ALLOWED_PORTS: ['80', '443'],
      URL_FETCH_MAX_BODY_BYTES: 262_144,
      URL_FETCH_CONCURRENCY: 8,
      URL_LOOKALIKE_HIGH_SCORE: 0.85,
      URL_REWRITE_ENABLED: true,
      URL_REWRITE_DIRECTIONS: ['inbound'],
      URL_TOKEN_KEY_CURRENT_ID: 1,
      URL_TOKEN_DEFAULT_EXPIRY_DAYS: 30,
      URL_TOKEN_MAX_EXPIRY_DAYS: 90,
      URL_DYNAMIC_INSPECTION: true,
      URL_DYNAMIC_MAX_PER_MESSAGE: 3,
      URL_DYNAMIC_PENDING_TTL_SECONDS: 3_600,
      URL_DYNAMIC_SWEEP_INTERVAL_MS: 60_000,
    });
    expect(urlPlatformFromConfig(config)).toEqual({
      ...URL_PLATFORM_DEFAULTS,
      rewrite: { ...URL_PLATFORM_DEFAULTS.rewrite, directions: ['inbound'] },
    });
  });

  it('generalizes the round deadline to url: 6 x (120 + 60) s fits 1 800 s', () => {
    const config = load({ SCAN_ENGINES: 'url' });
    expect(minimumRoundDeadlineSeconds(config)).toBe(1_080);
    refusal(
      { SCAN_ENGINES: 'url', SCAN_URL_TIMEOUT_MS: '300000', SCAN_ROUND_DEADLINE_SECONDS: '1800' },
      'SCAN_ROUND_DEADLINE_SECONDS',
    );
    expect(() =>
      load({
        SCAN_ENGINES: 'url',
        SCAN_URL_TIMEOUT_MS: '300000',
        SCAN_ROUND_DEADLINE_SECONDS: '2160',
      }),
    ).not.toThrow();
  });

  it('refuses attempt budgets at the scan.url limit and timeouts not below the engine call', () => {
    expect(engineQueueMaxAttempts('url')).toBe(10);
    refusal({ SCAN_URL_MAX_ATTEMPTS: '10' }, 'SCAN_URL_MAX_ATTEMPTS');
    refusal(
      { SCAN_URL_TIMEOUT_MS: '5000', SCAN_ROUND_DEADLINE_SECONDS: '1800' },
      'URL_EXTRACT_TIMEOUT_MS',
    );
    refusal({ URL_FETCH_TOTAL_TIMEOUT_MS: '120000' }, 'URL_FETCH_TOTAL_TIMEOUT_MS');
    refusal({ SCAN_URL_TIMEOUT_MS: '30000' }, 'SCAN_S3_TIMEOUT_MS');
    refusal({ URL_FETCH_HEADER_TIMEOUT_MS: '20000' }, 'URL_FETCH_HEADER_TIMEOUT_MS');
    refusal({ URL_FETCH_SUSPICIOUS_HOPS: '9' }, 'URL_FETCH_SUSPICIOUS_HOPS');
  });

  it('bounds every numeric key', () => {
    refusal({ URL_MAX_PER_MESSAGE: '201' }, 'URL_MAX_PER_MESSAGE');
    refusal({ URL_MAX_LENGTH: '4096' }, 'URL_MAX_LENGTH');
    refusal({ URL_MAX_PART_BYTES: '20971520' }, 'URL_MAX_PART_BYTES');
    refusal({ URL_EXTRA_PART_MAX_BYTES: '20971520' }, 'URL_EXTRA_PART_MAX_BYTES');
    refusal({ URL_CACHE_CLEAN_TTL_SECONDS: '3601' }, 'URL_CACHE_CLEAN_TTL_SECONDS');
    refusal({ URL_CACHE_MALICIOUS_TTL_SECONDS: '604801' }, 'URL_CACHE_MALICIOUS_TTL_SECONDS');
    refusal({ URL_CACHE_ERROR_TTL_SECONDS: '121' }, 'URL_CACHE_ERROR_TTL_SECONDS');
    refusal({ URL_FETCH_MAX_PER_MESSAGE: '51' }, 'URL_FETCH_MAX_PER_MESSAGE');
    refusal({ URL_DYNAMIC_MAX_PER_MESSAGE: '11' }, 'URL_DYNAMIC_MAX_PER_MESSAGE');
    refusal({ URL_LOOKALIKE_HIGH_SCORE: '1.5' }, 'URL_LOOKALIKE_HIGH_SCORE');
    refusal({ URL_LOOKALIKE_LONG_LABEL: '4' }, 'URL_LOOKALIKE_LONG_LABEL');
    refusal({ URL_REWRITE_MAX_PART_BYTES: '30000000' }, 'URL_REWRITE_MAX_PART_BYTES');
    refusal({ URL_TOKEN_DEFAULT_EXPIRY_DAYS: '100' }, 'URL_TOKEN_DEFAULT_EXPIRY_DAYS');
    refusal({ URL_TOKEN_MAX_EXPIRY_DAYS: '181' }, 'URL_TOKEN_MAX_EXPIRY_DAYS');
  });

  it('validates providers, DNSBL zones (never echoed), DNS servers, ports, CIDRs and hosts', () => {
    refusal(
      { URL_REPUTATION_PROVIDERS: 'local_feed,google_safe_browsing' },
      'URL_REPUTATION_PROVIDERS',
    );
    refusal({ URL_REPUTATION_PROVIDERS: 'local_feed,nope' }, 'URL_REPUTATION_PROVIDERS');
    refusal({ URL_REPUTATION_PROVIDERS: 'dnsbl,dnsbl' }, 'URL_REPUTATION_PROVIDERS');
    expect(() =>
      load({ URL_DNSBL_DOMAIN_ZONES: 'secretkey123.zen.dq.example=128.0.0.1:spam' }),
    ).toThrow(/URL_DNSBL_DOMAIN_ZONES/);
    expect(() =>
      load({ URL_DNSBL_DOMAIN_ZONES: 'secretkey123.zen.dq.example=128.0.0.1:spam' }),
    ).not.toThrow(/secretkey123/);
    refusal(
      { URL_REPUTATION_PROVIDERS: 'dnsbl', URL_DNSBL_DOMAIN_ZONES: ' ', URL_DNSBL_IP_ZONES: ' ' },
      'URL_DNSBL_DOMAIN_ZONES',
    );
    refusal({ URL_DNSBL_ERROR_CODES: 'x' }, 'URL_DNSBL_ERROR_CODES');
    // No zone defaults: dnsbl without zones is refused (never the local test zones by accident).
    expect(() => loadExact(without('URL_DNSBL_DOMAIN_ZONES'))).toThrow(/URL_DNSBL_DOMAIN_ZONES/);
    expect(
      loadExact({ ...without('URL_DNSBL_DOMAIN_ZONES'), URL_REPUTATION_PROVIDERS: 'local_feed' })
        .URL_DNSBL_DOMAIN_ZONES,
    ).toBe('');
    refusal({ URL_DNS_SERVERS: '127.0.0.1:99999' }, 'URL_DNS_SERVERS');
    expect(
      load({ URL_DNS_SERVERS: '172.31.250.53, 127.0.0.1:1053,[::1]:53' }).URL_DNS_SERVERS,
    ).toEqual(['172.31.250.53', '127.0.0.1:1053', '[::1]:53']);
    expect(isDnsServer('dns.example')).toBe(false);
    refusal({ URL_FETCH_ALLOWED_PORTS: '80,http' }, 'URL_FETCH_ALLOWED_PORTS');
    refusal({ URL_FETCH_DENY_CIDRS: '10.0.0.0/33' }, 'URL_FETCH_DENY_CIDRS');
    refusal({ URL_FETCH_DENY_HOSTS: 'not a host' }, 'URL_FETCH_DENY_HOSTS');
    refusal({ URL_PROTECTED_EXTRA_DOMAINS: 'single' }, 'URL_PROTECTED_EXTRA_DOMAINS');
    refusal({ URL_FETCH_USER_AGENT: 'bad\u0007agent' }, 'URL_FETCH_USER_AGENT');
    refusal(
      { URL_FETCH_EGRESS_PROXY_URL: 'http://url-egress-proxy:3128' },
      'URL_EGRESS_PROXY_TOKEN',
    );
    refusal(
      { URL_FETCH_EGRESS_PROXY_URL: 'https://proxy:3128', URL_EGRESS_PROXY_TOKEN: 'x'.repeat(32) },
      'URL_FETCH_EGRESS_PROXY_URL',
    );
  });

  it('restricts the test seams to documentation ranges and refuses them in production', () => {
    expect(
      load({ URL_FETCH_TEST_ALLOW_CIDRS: '203.0.113.0/24' }).URL_FETCH_TEST_ALLOW_CIDRS,
    ).toEqual(['203.0.113.0/24']);
    refusal({ URL_FETCH_TEST_ALLOW_CIDRS: '10.0.0.0/8' }, 'URL_FETCH_TEST_ALLOW_CIDRS');
    refusal({ URL_FETCH_TEST_ALLOW_CIDRS: '127.0.0.1/32' }, 'URL_FETCH_TEST_ALLOW_CIDRS');
    refusal(
      { ...PROD, URL_FETCH_TEST_ALLOW_CIDRS: '203.0.113.0/24' },
      'URL_FETCH_TEST_ALLOW_CIDRS',
    );
    refusal(
      { ...PROD, APP_ENV: 'staging', URL_FETCH_TEST_DIAL_MAP: '203.0.113.10:80=127.0.0.1:18080' },
      'URL_FETCH_TEST_DIAL_MAP',
    );
    refusal({ URL_FETCH_TEST_DIAL_MAP: 'garbage' }, 'URL_FETCH_TEST_DIAL_MAP');
    // The local Compose containers: NODE_ENV=production with APP_ENV=local (WP2 deviation 4).
    expect(() =>
      load({
        NODE_ENV: 'production',
        APP_ENV: 'local',
        URL_FETCH_TEST_ALLOW_CIDRS: '203.0.113.0/24',
      }),
    ).not.toThrow();
    expect(urlProductionLike({ NODE_ENV: 'production', APP_ENV: 'production' })).toBe(true);
    expect(urlProductionLike({ NODE_ENV: 'production', APP_ENV: 'local' })).toBe(false);
  });

  it('requires an https click host in production, without query or userinfo', () => {
    refusal({ ...PROD, URL_CLICK_BASE_URL: 'http://protect.example.com' }, 'URL_CLICK_BASE_URL');
    expect(() => load(PROD)).not.toThrow();
    expect(() => load({ URL_CLICK_BASE_URL: 'http://localhost:3080' })).not.toThrow();
    refusal({ URL_CLICK_BASE_URL: 'https://protect.example.com/?a=1' }, 'URL_CLICK_BASE_URL');
    refusal({ URL_CLICK_BASE_URL: 'ftp://protect.example.com' }, 'URL_CLICK_BASE_URL');
  });

  it('parses token keys: 64 hex, ids 1..255, a previous slot with its own id and key', () => {
    refusal({ URL_TOKEN_KEY_CURRENT: 'abc' }, 'URL_TOKEN_KEY_CURRENT');
    refusal({ URL_TOKEN_KEY_CURRENT_ID: '0' }, 'URL_TOKEN_KEY_CURRENT_ID');
    refusal({ URL_TOKEN_KEY_CURRENT_ID: '256' }, 'URL_TOKEN_KEY_CURRENT_ID');
    refusal({ URL_TOKEN_KEY_PREVIOUS: OTHER_KEY }, 'URL_TOKEN_KEY_PREVIOUS_ID');
    refusal({ URL_TOKEN_KEY_PREVIOUS_ID: '2' }, 'URL_TOKEN_KEY_PREVIOUS_ID');
    refusal(
      { URL_TOKEN_KEY_PREVIOUS: OTHER_KEY, URL_TOKEN_KEY_PREVIOUS_ID: '1' },
      'URL_TOKEN_KEY_PREVIOUS',
    );
    refusal(
      { URL_TOKEN_KEY_PREVIOUS: KEY, URL_TOKEN_KEY_PREVIOUS_ID: '2' },
      'URL_TOKEN_KEY_PREVIOUS',
    );
    expect(
      load({ URL_TOKEN_KEY_PREVIOUS: OTHER_KEY, URL_TOKEN_KEY_PREVIOUS_ID: '2' }),
    ).toMatchObject({
      URL_TOKEN_KEY_CURRENT_ID: 1,
      URL_TOKEN_KEY_PREVIOUS_ID: 2,
    });
  });

  it('requires the cache MAC key and the token key only where the url engine consumes', () => {
    expect(() => loadExact(without('URL_CACHE_HMAC_KEY'))).toThrow(/URL_CACHE_HMAC_KEY/);
    refusal({ URL_CACHE_HMAC_KEY: 'short' }, 'URL_CACHE_HMAC_KEY');
    expect(() => loadExact(without('URL_TOKEN_KEY_CURRENT'))).toThrow(/URL_TOKEN_KEY_CURRENT/);
    expect(() =>
      loadExact({ ...without('URL_CACHE_HMAC_KEY'), URL_CACHE_ENABLED: 'false' }),
    ).not.toThrow();
    expect(() =>
      loadExact({ ...without('URL_TOKEN_KEY_CURRENT'), URL_REWRITE_ENABLED: 'false' }),
    ).not.toThrow();
    // A replica without the url consumer (production email-worker-scan / -attachment).
    const rspamdOnly = loadExact({
      ...without('URL_CACHE_HMAC_KEY', 'URL_TOKEN_KEY_CURRENT'),
      SCAN_CONSUMERS: 'rspamd',
    });
    expect(consumerEngines(rspamdOnly)).toEqual(['rspamd']);
    expect(runsUrlConsumer(rspamdOnly)).toBe(false);
    expect(runsUrlConsumer(load({ SCAN_ENGINES: 'rspamd,attachment' }))).toBe(false);
  });

  it('validates the platform settings through the contract (directions, dkim policy, dynamic)', () => {
    refusal({ URL_REWRITE_DIRECTIONS: 'inbound,sideways' }, 'URL_REWRITE_DIRECTIONS');
    refusal({ URL_REWRITE_DIRECTIONS: 'inbound,inbound' }, 'URL_REWRITE_DIRECTIONS');
    refusal({ URL_REWRITE_DKIM_SIGNED: 'maybe' }, 'URL_REWRITE_DKIM_SIGNED');
    refusal({ URL_DYNAMIC_INSPECTION: 'sometimes' }, 'URL_DYNAMIC_INSPECTION');
    expect(load({ URL_DYNAMIC_INSPECTION: 'off' }).URL_DYNAMIC_INSPECTION).toBe(false);
    expect(load({ URL_REWRITE_DIRECTIONS: 'inbound,outbound' }).URL_REWRITE_DIRECTIONS).toEqual([
      'inbound',
      'outbound',
    ]);
  });
});
