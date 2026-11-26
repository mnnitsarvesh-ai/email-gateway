import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ConfigValidationError } from '@email-gateway/config';
import {
  ATTACHMENT_PLATFORM_DEFAULTS,
  BEC_PLATFORM_DEFAULTS,
  DLP_PLATFORM_DEFAULTS,
  SANDBOX_PLATFORM_DEFAULTS,
} from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { TEST_DOMAIN_ENV } from '../test/support/test-env';
import {
  attachmentPlatformSettingsOf,
  becPlatformSettingsOf,
  dlpPlatformSettingsOf,
  loadApiConfig,
  rspamdPlatformSettingsOf,
  sandboxPlatformSettingsOf,
} from './config';

const hex64 = () => randomBytes(32).toString('hex');

const valid = {
  ...TEST_DOMAIN_ENV,
  HTTP_PORT: '3000',
  DATABASE_URL: 'mysql://u:p@mysql:3306/email_gateway',
  REDIS_URL: 'redis://redis:6379',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'mail',
  S3_BUCKET_ARCHIVE: 'archive',
  AUTH_JWT_SECRET: hex64(),
  AUTH_TOKEN_PEPPER: hex64(),
  DATA_ENCRYPTION_KEY: hex64(),
};

/** Returns the validation message for `env`; fails the test if it is valid. */
function rejection(env: Record<string, string | undefined>): string {
  try {
    loadApiConfig(env);
  } catch (err) {
    expect(err).toBeInstanceOf(ConfigValidationError);
    return (err as Error).message;
  }
  return expect.fail('expected ConfigValidationError');
}

describe('loadApiConfig', () => {
  it('parses CORS origins into a list', () => {
    const cfg = loadApiConfig({
      ...valid,
      CORS_ORIGINS: 'http://localhost:3001, https://admin.example.com',
    });
    expect(cfg.CORS_ORIGINS).toEqual(['http://localhost:3001', 'https://admin.example.com']);
  });

  it('runs writer-only by default, with the documented lag settings', () => {
    const cfg = loadApiConfig(valid);
    expect(cfg.DATABASE_READ_URL).toBeUndefined();
    expect(cfg.DATABASE_READ_MAX_LAG_SECONDS).toBe(10);
    expect(cfg.DATABASE_READ_LAG_CHECK_INTERVAL_MS).toBe(5000);
  });

  it('accepts a read replica URL and lag settings', () => {
    const cfg = loadApiConfig({
      ...valid,
      DATABASE_READ_URL: 'mysql://r:p@mysql-replica:3306/email_gateway',
      DATABASE_READ_MAX_LAG_SECONDS: '30',
      DATABASE_READ_LAG_CHECK_INTERVAL_MS: '2000',
    });
    expect(cfg.DATABASE_READ_URL).toBe('mysql://r:p@mysql-replica:3306/email_gateway');
    expect(cfg.DATABASE_READ_MAX_LAG_SECONDS).toBe(30);
    expect(cfg.DATABASE_READ_LAG_CHECK_INTERVAL_MS).toBe(2000);
  });

  it('rejects a read replica URL that is not mysql://', () => {
    expect(() => loadApiConfig({ ...valid, DATABASE_READ_URL: 'http://replica' })).toThrow(
      /DATABASE_READ_URL/,
    );
  });

  it('fails fast when a required dependency is not configured', () => {
    const { DATABASE_URL: _databaseUrl, ...missing } = valid;
    expect(() => loadApiConfig(missing)).toThrow(/DATABASE_URL/);
  });
});

describe('loadApiConfig: authentication and tenancy (D15)', () => {
  it('applies the documented defaults', () => {
    const cfg = loadApiConfig(valid);
    expect(cfg).toMatchObject({
      AUTH_JWT_ISSUER: 'email-gateway',
      AUTH_JWT_AUDIENCE: 'email-gateway-api',
      AUTH_ACCESS_TOKEN_TTL_SECONDS: 600,
      AUTH_REFRESH_TOKEN_TTL_SECONDS: 604800,
      AUTH_SESSION_MAX_AGE_SECONDS: 2592000,
      AUTH_ARGON2_MEMORY_KIB: 19456,
      AUTH_ARGON2_TIME_COST: 2,
      AUTH_ARGON2_PARALLELISM: 1,
      AUTH_LOGIN_MAX_ACCOUNT_FAILURES: 5,
      AUTH_LOGIN_MAX_IP_FAILURES: 50,
      AUTH_LOGIN_FAILURE_WINDOW_SECONDS: 900,
      AUTH_LOCKOUT_BASE_SECONDS: 900,
      AUTH_LOCKOUT_MAX_SECONDS: 86400,
      AUTH_MFA_ISSUER: 'EmailSecurityGateway',
      AUTH_PASSWORD_RESET_TTL_SECONDS: 1800,
      AUTH_EMAIL_VERIFICATION_TTL_SECONDS: 86400,
      AUTH_INVITATION_TTL_SECONDS: 604800,
      AUTH_LOGIN_AUDIT_RETENTION_DAYS: 365,
      AUTH_BACKGROUND_JOBS_ENABLED: true,
      PLATFORM_OVERRIDE_MAX_MINUTES: 60,
      ORG_DELETION_RETENTION_DAYS: 30,
      ORG_DELETION_CONFIRM_WINDOW_HOURS: 72,
      HTTP_TRUST_PROXY: 0,
      PORTAL_PUBLIC_URL: 'http://localhost:3001',
      NOTIFY_SMTP_PORT: 587,
      NOTIFY_SMTP_SECURE: 'starttls',
    });
    expect(cfg.AUTH_JWT_PREVIOUS_SECRET).toBeUndefined();
    expect(cfg.DATA_ENCRYPTION_KEY_PREVIOUS).toBeUndefined();
    expect(cfg.NOTIFY_SMTP_HOST).toBeUndefined();
  });

  it.each(['AUTH_JWT_SECRET', 'AUTH_TOKEN_PEPPER', 'DATA_ENCRYPTION_KEY'])('requires %s', (key) => {
    expect(rejection({ ...valid, [key]: undefined })).toContain(key);
  });

  it('treats empty previous keys (as in .env.example) as unset', () => {
    const cfg = loadApiConfig({
      ...valid,
      AUTH_JWT_PREVIOUS_SECRET: '',
      DATA_ENCRYPTION_KEY_PREVIOUS: '',
    });
    expect(cfg.AUTH_JWT_PREVIOUS_SECRET).toBeUndefined();
    expect(cfg.DATA_ENCRYPTION_KEY_PREVIOUS).toBeUndefined();
  });

  it('accepts rotation keys', () => {
    const previousSecret = hex64();
    const previousKey = hex64();
    const cfg = loadApiConfig({
      ...valid,
      AUTH_JWT_PREVIOUS_SECRET: previousSecret,
      DATA_ENCRYPTION_KEY_PREVIOUS: previousKey,
    });
    expect(cfg.AUTH_JWT_PREVIOUS_SECRET).toBe(previousSecret);
    expect(cfg.DATA_ENCRYPTION_KEY_PREVIOUS).toBe(previousKey);
  });

  const shortSecret = 'S3cretButTooShort-'.repeat(3);
  it.each([
    ['AUTH_JWT_SECRET', shortSecret],
    ['AUTH_JWT_PREVIOUS_SECRET', shortSecret],
    ['AUTH_TOKEN_PEPPER', shortSecret],
    ['DATA_ENCRYPTION_KEY', 'ab'.repeat(31)],
    ['DATA_ENCRYPTION_KEY', 'zz'.repeat(32)],
    ['DATA_ENCRYPTION_KEY', 'ab'.repeat(33)],
    ['DATA_ENCRYPTION_KEY_PREVIOUS', 'S3cretButNotHex'.repeat(5)],
    ['AUTH_ARGON2_MEMORY_KIB', '19455'],
    ['AUTH_ARGON2_TIME_COST', '1'],
    ['AUTH_ARGON2_PARALLELISM', '0'],
    ['AUTH_ACCESS_TOKEN_TTL_SECONDS', '59'],
    ['AUTH_ACCESS_TOKEN_TTL_SECONDS', '901'],
    ['AUTH_REFRESH_TOKEN_TTL_SECONDS', '3599'],
    ['PLATFORM_OVERRIDE_MAX_MINUTES', '4'],
    ['PLATFORM_OVERRIDE_MAX_MINUTES', '241'],
    ['ORG_DELETION_RETENTION_DAYS', '6'],
    ['HTTP_TRUST_PROXY', '-1'],
    ['HTTP_TRUST_PROXY', 'true'],
    ['PORTAL_PUBLIC_URL', 'not a url'],
    ['PORTAL_PUBLIC_URL', 'ftp://portal.example.com'],
    ['AUTH_BACKGROUND_JOBS_ENABLED', 'yes'],
    ['AUTH_MFA_ISSUER', 'Bad:Issuer'],
  ])('rejects %s=%s without echoing the value', (key, value) => {
    const message = rejection({ ...valid, [key]: value });
    expect(message).toContain(key);
    expect(message).not.toContain(value);
  });

  it('does not echo valid secrets when another key is invalid', () => {
    const message = rejection({ ...valid, HTTP_TRUST_PROXY: '-1' });
    for (const key of ['AUTH_JWT_SECRET', 'AUTH_TOKEN_PEPPER', 'DATA_ENCRYPTION_KEY'] as const) {
      expect(message).not.toContain(valid[key]);
    }
  });

  it('requires the absolute session age to cover the refresh TTL', () => {
    expect(
      rejection({
        ...valid,
        AUTH_REFRESH_TOKEN_TTL_SECONDS: '86400',
        AUTH_SESSION_MAX_AGE_SECONDS: '86399',
      }),
    ).toContain('AUTH_SESSION_MAX_AGE_SECONDS');
    expect(
      loadApiConfig({
        ...valid,
        AUTH_REFRESH_TOKEN_TTL_SECONDS: '86400',
        AUTH_SESSION_MAX_AGE_SECONDS: '86400',
      }).AUTH_SESSION_MAX_AGE_SECONDS,
    ).toBe(86400);
  });

  it('requires the lockout cap to be at least the base lockout', () => {
    expect(
      rejection({ ...valid, AUTH_LOCKOUT_BASE_SECONDS: '600', AUTH_LOCKOUT_MAX_SECONDS: '300' }),
    ).toContain('AUTH_LOCKOUT_MAX_SECONDS');
  });

  it('parses booleans, the proxy hop count and strips a trailing slash from the portal URL', () => {
    const cfg = loadApiConfig({
      ...valid,
      AUTH_BACKGROUND_JOBS_ENABLED: 'false',
      HTTP_TRUST_PROXY: '1',
      PORTAL_PUBLIC_URL: 'http://localhost:3001/',
    });
    expect(cfg.AUTH_BACKGROUND_JOBS_ENABLED).toBe(false);
    expect(cfg.HTTP_TRUST_PROXY).toBe(1);
    expect(cfg.PORTAL_PUBLIC_URL).toBe('http://localhost:3001');
  });

  it('requires an https portal URL in staging and production', () => {
    expect(rejection({ ...valid, APP_ENV: 'production' })).toContain('PORTAL_PUBLIC_URL');
    expect(
      loadApiConfig({
        ...valid,
        APP_ENV: 'production',
        PORTAL_PUBLIC_URL: 'https://portal.example.com',
      }).PORTAL_PUBLIC_URL,
    ).toBe('https://portal.example.com');
  });
});

describe('loadApiConfig: transactional email relay (NOTIFY_SMTP_*)', () => {
  const relay = {
    NOTIFY_SMTP_HOST: 'smtp.example.com',
    NOTIFY_SMTP_FROM: 'Gateway <no-reply@example.com>',
    NOTIFY_SMTP_USER: 'mailer',
    NOTIFY_SMTP_PASSWORD: 'RelayPasswordValue',
  };

  it('composes the shared relay schema', () => {
    const cfg = loadApiConfig({ ...valid, ...relay, NOTIFY_SMTP_SECURE: 'tls' });
    expect(cfg).toMatchObject({
      NOTIFY_SMTP_HOST: 'smtp.example.com',
      NOTIFY_SMTP_PORT: 587,
      NOTIFY_SMTP_SECURE: 'tls',
      NOTIFY_SMTP_FROM: 'Gateway <no-reply@example.com>',
    });
  });

  it('applies the cross-field relay rules', () => {
    const { NOTIFY_SMTP_FROM: _from, ...noFrom } = relay;
    expect(rejection({ ...valid, ...noFrom })).toContain('NOTIFY_SMTP_FROM');
  });

  it('accepts plaintext SMTP only locally and in CI', () => {
    expect(
      loadApiConfig({ ...valid, ...relay, APP_ENV: 'ci', NOTIFY_SMTP_SECURE: 'none' })
        .NOTIFY_SMTP_SECURE,
    ).toBe('none');
    const message = rejection({
      ...valid,
      ...relay,
      APP_ENV: 'staging',
      PORTAL_PUBLIC_URL: 'https://portal.example.com',
      NOTIFY_SMTP_SECURE: 'none',
    });
    expect(message).toContain('NOTIFY_SMTP_SECURE');
    expect(message).not.toContain('RelayPasswordValue');
  });
});

describe('loadApiConfig: domain onboarding and DNS (D16)', () => {
  const domainEnv = { ...valid, DOMAIN_BACKGROUND_JOBS_ENABLED: undefined };

  it('applies the documented defaults', () => {
    const cfg = loadApiConfig(domainEnv);
    expect(cfg).toMatchObject({
      DNS_RESOLVER_MODE: 'system',
      DNS_SERVERS: [],
      DNS_DOH_URL: 'https://cloudflare-dns.com/dns-query',
      DNS_TIMEOUT_MS: 2500,
      DNS_TRIES: 2,
      DNS_PROPAGATION_UPSTREAMS: [],
      DNS_CACHE_MAX_TTL_SECONDS: 300,
      DNS_CACHE_NEGATIVE_TTL_SECONDS: 60,
      GATEWAY_DMARC_RUA: [],
      GATEWAY_DMARC_RUF: [],
      DOMAIN_VERIFICATION_LABEL: '_emailgateway-verify',
      DOMAIN_VERIFICATION_TTL_DAYS: 7,
      DOMAIN_RESERVED_SUFFIXES: [],
      DOMAIN_BACKGROUND_JOBS_ENABLED: true,
      DOMAIN_JOBS_INTERVAL_SECONDS: 30,
      DOMAIN_CHECK_BATCH_SIZE: 50,
      DOMAIN_CHECK_CONCURRENCY: 4,
      DOMAIN_CHECK_DEADLINE_MS: 15000,
      DOMAIN_RETRY_BASE_SECONDS: 60,
      DOMAIN_RETRY_MAX_SECONDS: 3600,
      DOMAIN_RECHECK_INCOMPLETE_SECONDS: 1800,
      DOMAIN_RECHECK_INTERVAL_SECONDS: 86400,
      DKIM_ROTATION_OVERLAP_DAYS: 7,
    });
  });

  it('parses the gateway MX hosts and SPF include (normalized)', () => {
    const cfg = loadApiConfig({
      ...valid,
      GATEWAY_MX_HOSTS: '10:MX1.Mail-Gateway.test., 20:mx2.mail-gateway.test',
      GATEWAY_SPF_INCLUDE: '_SPF.mail-gateway.test.',
    });
    expect(cfg.GATEWAY_MX_HOSTS).toEqual([
      { priority: 10, host: 'mx1.mail-gateway.test' },
      { priority: 20, host: 'mx2.mail-gateway.test' },
    ]);
    expect(cfg.GATEWAY_SPF_INCLUDE).toBe('_spf.mail-gateway.test');
    expect(cfg.DOMAIN_BACKGROUND_JOBS_ENABLED).toBe(false);
  });

  it.each(['GATEWAY_MX_HOSTS', 'GATEWAY_SPF_INCLUDE'])('requires %s (no default)', (key) => {
    expect(rejection({ ...valid, [key]: undefined })).toContain(key);
    expect(rejection({ ...valid, [key]: '' })).toContain(key);
  });

  it('parses server lists, DMARC report URIs and reserved suffixes', () => {
    const cfg = loadApiConfig({
      ...valid,
      DNS_SERVERS: '10.0.0.2, 127.0.0.1:5353,[::1]:5353,2001:db8::1',
      DNS_PROPAGATION_UPSTREAMS: '1.1.1.1,8.8.8.8:53',
      GATEWAY_DMARC_RUA: 'mailto:dmarc@mail-gateway.test, mailto:agg@reports.mail-gateway.test!10m',
      GATEWAY_DMARC_RUF: 'mailto:forensic@mail-gateway.test',
      DOMAIN_RESERVED_SUFFIXES: 'Mail-Gateway.test, internal.example.com.',
    });
    expect(cfg.DNS_SERVERS).toEqual(['10.0.0.2', '127.0.0.1:5353', '[::1]:5353', '2001:db8::1']);
    expect(cfg.DNS_PROPAGATION_UPSTREAMS).toEqual(['1.1.1.1', '8.8.8.8:53']);
    expect(cfg.GATEWAY_DMARC_RUA).toEqual([
      'mailto:dmarc@mail-gateway.test',
      'mailto:agg@reports.mail-gateway.test!10m',
    ]);
    expect(cfg.GATEWAY_DMARC_RUF).toEqual(['mailto:forensic@mail-gateway.test']);
    expect(cfg.DOMAIN_RESERVED_SUFFIXES).toEqual(['mail-gateway.test', 'internal.example.com']);
  });

  it('accepts DoH URLs as propagation upstreams in doh mode', () => {
    const cfg = loadApiConfig({
      ...valid,
      DNS_RESOLVER_MODE: 'doh',
      DNS_DOH_URL: 'https://dns.example.net/dns-query',
      DNS_PROPAGATION_UPSTREAMS: 'https://dns.google/dns-query,https://dns.quad9.net/dns-query',
    });
    expect(cfg.DNS_PROPAGATION_UPSTREAMS).toEqual([
      'https://dns.google/dns-query',
      'https://dns.quad9.net/dns-query',
    ]);
  });

  it('rejects server addresses in doh mode and URLs in system mode', () => {
    expect(
      rejection({ ...valid, DNS_RESOLVER_MODE: 'doh', DNS_PROPAGATION_UPSTREAMS: '1.1.1.1' }),
    ).toContain('DNS_PROPAGATION_UPSTREAMS');
    expect(
      rejection({ ...valid, DNS_PROPAGATION_UPSTREAMS: 'https://dns.google/dns-query' }),
    ).toContain('DNS_PROPAGATION_UPSTREAMS');
  });

  it('accepts http DoH URLs only when APP_ENV is local or ci', () => {
    for (const appEnv of ['local', 'ci']) {
      expect(
        loadApiConfig({
          ...valid,
          APP_ENV: appEnv,
          DNS_DOH_URL: 'http://127.0.0.1:8053/dns-query',
        }).DNS_DOH_URL,
      ).toBe('http://127.0.0.1:8053/dns-query');
    }
    for (const appEnv of ['staging', 'production']) {
      const message = rejection({
        ...valid,
        APP_ENV: appEnv,
        PORTAL_PUBLIC_URL: 'https://portal.example.com',
        DNS_DOH_URL: 'http://doh-internal.example.net/dns-query',
      });
      expect(message).toContain('DNS_DOH_URL');
      expect(message).not.toContain('doh-internal');
    }
    expect(
      rejection({
        ...valid,
        APP_ENV: 'production',
        PORTAL_PUBLIC_URL: 'https://portal.example.com',
        DNS_RESOLVER_MODE: 'doh',
        DNS_PROPAGATION_UPSTREAMS: 'http://doh-internal.example.net/dns-query',
      }),
    ).toContain('DNS_PROPAGATION_UPSTREAMS');
  });

  it('rejects DoH URLs with credentials without echoing them', () => {
    const message = rejection({
      ...valid,
      DNS_DOH_URL: 'https://doh-user:DoHPassw0rdValue@dns.example.net/dns-query',
    });
    expect(message).toContain('DNS_DOH_URL');
    expect(message).not.toContain('DoHPassw0rdValue');
  });

  it.each([
    ['DNS_RESOLVER_MODE', 'dot'],
    ['DNS_SERVERS', 'dns.example.net'],
    ['DNS_SERVERS', '10.0.0.1:99999'],
    ['DNS_SERVERS', '[10.0.0.1]:53'],
    ['DNS_SERVERS', '::1:53x'],
    ['DNS_DOH_URL', 'not a url'],
    ['DNS_DOH_URL', 'ftp://dns.example.net/dns-query'],
    ['DNS_TIMEOUT_MS', '99'],
    ['DNS_TIMEOUT_MS', '10001'],
    ['DNS_TRIES', '0'],
    ['DNS_TRIES', '6'],
    ['DNS_CACHE_MAX_TTL_SECONDS', '3601'],
    ['DNS_CACHE_NEGATIVE_TTL_SECONDS', '901'],
    ['GATEWAY_MX_HOSTS', 'mx1.mail-gateway.test'],
    ['GATEWAY_MX_HOSTS', '70000:mx1.mail-gateway.test'],
    ['GATEWAY_MX_HOSTS', '10:mx_1.mail-gateway.test'],
    ['GATEWAY_MX_HOSTS', '10:localhost'],
    ['GATEWAY_MX_HOSTS', '10:mx1.mail-gateway.test,20:MX1.mail-gateway.test'],
    ['GATEWAY_MX_HOSTS', ','],
    ['GATEWAY_SPF_INCLUDE', 'not a name'],
    ['GATEWAY_SPF_INCLUDE', '10.0.0.1'],
    ['GATEWAY_DMARC_RUA', 'dmarc-reports@mail-gateway.test'],
    ['GATEWAY_DMARC_RUA', 'mailto:no-at-sign'],
    ['GATEWAY_DMARC_RUF', 'https://reports.mail-gateway.test'],
    ['DOMAIN_VERIFICATION_LABEL', 'emailgateway-verify'],
    ['DOMAIN_VERIFICATION_LABEL', '_Upper'],
    ['DOMAIN_VERIFICATION_TTL_DAYS', '0'],
    ['DOMAIN_VERIFICATION_TTL_DAYS', '31'],
    ['DOMAIN_RESERVED_SUFFIXES', 'ok.example.com,bad_name'],
    ['DOMAIN_BACKGROUND_JOBS_ENABLED', 'yes'],
    ['DOMAIN_JOBS_INTERVAL_SECONDS', '4'],
    ['DOMAIN_CHECK_BATCH_SIZE', '501'],
    ['DOMAIN_CHECK_CONCURRENCY', '33'],
    ['DOMAIN_CHECK_DEADLINE_MS', '999'],
    ['DOMAIN_CHECK_DEADLINE_MS', '60001'],
    ['DOMAIN_RETRY_BASE_SECONDS', '4'],
    ['DOMAIN_RETRY_MAX_SECONDS', '86401'],
    ['DOMAIN_RECHECK_INCOMPLETE_SECONDS', '59'],
    ['DOMAIN_RECHECK_INTERVAL_SECONDS', '3599'],
    ['DKIM_ROTATION_OVERLAP_DAYS', '91'],
  ])('rejects %s=%s without echoing the value', (key, value) => {
    const message = rejection({ ...valid, [key]: value });
    expect(message).toContain(key);
    expect(message).not.toContain(value);
  });

  it('requires the check deadline to cover every DNS try', () => {
    expect(
      rejection({
        ...valid,
        DNS_TIMEOUT_MS: '5000',
        DNS_TRIES: '3',
        DOMAIN_CHECK_DEADLINE_MS: '14999',
      }),
    ).toContain('DOMAIN_CHECK_DEADLINE_MS');
    expect(
      loadApiConfig({
        ...valid,
        DNS_TIMEOUT_MS: '5000',
        DNS_TRIES: '3',
        DOMAIN_CHECK_DEADLINE_MS: '15000',
      }).DOMAIN_CHECK_DEADLINE_MS,
    ).toBe(15000);
  });

  it('requires the retry cap to be at least the retry base', () => {
    expect(
      rejection({ ...valid, DOMAIN_RETRY_BASE_SECONDS: '600', DOMAIN_RETRY_MAX_SECONDS: '300' }),
    ).toContain('DOMAIN_RETRY_MAX_SECONDS');
  });

  it('allows disabling the DNS cache', () => {
    expect(
      loadApiConfig({ ...valid, DNS_CACHE_MAX_TTL_SECONDS: '0' }).DNS_CACHE_MAX_TTL_SECONDS,
    ).toBe(0);
  });
});

describe('loadApiConfig: SMTP gateway control plane (step 2.2 §5)', () => {
  it('applies the documented defaults and leaves the DKIM publisher unconfigured', () => {
    const cfg = loadApiConfig(valid);
    expect(cfg).toMatchObject({
      DKIM_SIGNING_SYNC_ENABLED: true,
      DKIM_SIGNING_SYNC_INTERVAL_SECONDS: 30,
      SMTP_CONNECTORS_MAX_PER_ORGANIZATION: 50,
      SMTP_CONNECTOR_ALLOW_NON_PUBLIC_NETWORKS: false,
      DOMAIN_RECIPIENTS_MAX_PER_DOMAIN: 100000,
    });
    expect(cfg.REDIS_DKIM_URL).toBeUndefined();
    expect(
      loadApiConfig({ ...valid, SMTP_CONNECTOR_ALLOW_NON_PUBLIC_NETWORKS: 'true' })
        .SMTP_CONNECTOR_ALLOW_NON_PUBLIC_NETWORKS,
    ).toBe(true);
  });

  it('treats an empty REDIS_DKIM_URL as not configured', () => {
    expect(loadApiConfig({ ...valid, REDIS_DKIM_URL: '  ' }).REDIS_DKIM_URL).toBeUndefined();
  });

  it('accepts redis:// and rediss:// URLs for the DKIM key store', () => {
    for (const url of [
      'redis://dkim-writer:pw@localhost:6391/0',
      'rediss://w:pw@redis-dkim:6379',
    ]) {
      expect(loadApiConfig({ ...valid, REDIS_DKIM_URL: url }).REDIS_DKIM_URL).toBe(url);
    }
  });

  it('rejects other DKIM key store URLs without echoing them', () => {
    const message = rejection({ ...valid, REDIS_DKIM_URL: 'http://user:s3cr3t@host' });
    expect(message).toContain('REDIS_DKIM_URL');
    expect(message).not.toContain('s3cr3t');
    expect(rejection({ ...valid, REDIS_DKIM_URL: 'not a url' })).toContain('REDIS_DKIM_URL');
  });

  it('can disable the periodic DKIM sync and enforces the interval floor', () => {
    expect(
      loadApiConfig({ ...valid, DKIM_SIGNING_SYNC_ENABLED: 'false' }).DKIM_SIGNING_SYNC_ENABLED,
    ).toBe(false);
    expect(rejection({ ...valid, DKIM_SIGNING_SYNC_INTERVAL_SECONDS: '4' })).toContain(
      'DKIM_SIGNING_SYNC_INTERVAL_SECONDS',
    );
    expect(
      loadApiConfig({ ...valid, DKIM_SIGNING_SYNC_INTERVAL_SECONDS: '5' })
        .DKIM_SIGNING_SYNC_INTERVAL_SECONDS,
    ).toBe(5);
  });

  it('requires positive connector and recipient caps', () => {
    expect(rejection({ ...valid, SMTP_CONNECTORS_MAX_PER_ORGANIZATION: '0' })).toContain(
      'SMTP_CONNECTORS_MAX_PER_ORGANIZATION',
    );
    expect(rejection({ ...valid, DOMAIN_RECIPIENTS_MAX_PER_DOMAIN: '0' })).toContain(
      'DOMAIN_RECIPIENTS_MAX_PER_DOMAIN',
    );
  });
});

describe('loadApiConfig: mail routing (step 2.3 R3, §5)', () => {
  it('defaults: public destinations only, no extra suffixes, 10 servers, the Postfix names', () => {
    const cfg = loadApiConfig(valid);
    expect(cfg.ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS).toBe(false);
    expect(cfg.ROUTING_DENIED_DESTINATION_SUFFIXES).toEqual([]);
    expect(cfg.ROUTING_MAX_DESTINATIONS_PER_DOMAIN).toBe(10);
    expect(cfg.ROUTING_ALLOWED_DESTINATION_PORTS).toEqual([25, 587, 2525]);
    expect(cfg.POSTFIX_MYHOSTNAME).toBe('mx.gateway.local');
    expect(cfg.POSTFIX_OUTBOUND_MYHOSTNAME).toBe('out.gateway.local');
    expect(cfg.POSTFIX_BOUNCE_DOMAIN).toBe('bounces.gateway.internal');
  });

  it('parses the flag, the suffixes (leading dot optional) and the gateway names', () => {
    const cfg = loadApiConfig({
      ...valid,
      ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS: 'true',
      ROUTING_DENIED_DESTINATION_SUFFIXES: '.test, Example ,corp.lan.',
      ROUTING_MAX_DESTINATIONS_PER_DOMAIN: '4',
      ROUTING_ALLOWED_DESTINATION_PORTS: '25, 2526',
      POSTFIX_MYHOSTNAME: 'MX.GW.example.',
      POSTFIX_OUTBOUND_MYHOSTNAME: 'out.gw.example',
      POSTFIX_BOUNCE_DOMAIN: 'bounces.gw.example',
    });
    expect(cfg.ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS).toBe(true);
    expect(cfg.ROUTING_DENIED_DESTINATION_SUFFIXES).toEqual(['test', 'example', 'corp.lan']);
    expect(cfg.ROUTING_MAX_DESTINATIONS_PER_DOMAIN).toBe(4);
    expect(cfg.ROUTING_ALLOWED_DESTINATION_PORTS).toEqual([25, 2526]);
    expect(cfg.POSTFIX_MYHOSTNAME).toBe('mx.gw.example');
  });

  it.each([
    ['ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS', 'maybe'],
    ['ROUTING_DENIED_DESTINATION_SUFFIXES', 'bad suffix'],
    ['ROUTING_MAX_DESTINATIONS_PER_DOMAIN', '0'],
    ['ROUTING_MAX_DESTINATIONS_PER_DOMAIN', '11'],
    ['ROUTING_ALLOWED_DESTINATION_PORTS', '25,abc'],
    ['ROUTING_ALLOWED_DESTINATION_PORTS', '25,10052'],
    ['POSTFIX_MYHOSTNAME', 'not a host'],
    ['POSTFIX_BOUNCE_DOMAIN', 'single'],
  ])('refuses %s=%s', (key, value) => {
    expect(rejection({ ...valid, [key]: value })).toContain(key);
  });
});

describe('loadApiConfig: dead-letter replay (step 3.2 Q9)', () => {
  it('has no ops broker by default and scans at most 10 000 dead letters', () => {
    const cfg = loadApiConfig(valid);
    expect(cfg.RABBITMQ_OPS_URL).toBeUndefined();
    expect(cfg.DEAD_LETTER_REPLAY_SCAN_MAX).toBe(10_000);
    expect(loadApiConfig({ ...valid, RABBITMQ_OPS_URL: '' }).RABBITMQ_OPS_URL).toBeUndefined();
  });

  it('reads the ops role URL list and the scan bound', () => {
    const cfg = loadApiConfig({
      ...valid,
      RABBITMQ_OPS_URL:
        'amqp://eg-ops:ops-secret@rmq1:5672/email-gateway,amqp://eg-ops:ops-secret@rmq2:5672/email-gateway',
      DEAD_LETTER_REPLAY_SCAN_MAX: '100000',
    });
    expect(cfg.RABBITMQ_OPS_URL).toHaveLength(2);
    expect(cfg.DEAD_LETTER_REPLAY_SCAN_MAX).toBe(100_000);
  });

  it('rejects a non-amqp URL without echoing it, and a scan bound outside 1..100 000', () => {
    const message = rejection({ ...valid, RABBITMQ_OPS_URL: 'http://eg-ops:ops-secret@rmq1' });
    expect(message).toContain('RABBITMQ_OPS_URL');
    expect(message).not.toContain('ops-secret');
    expect(rejection({ ...valid, DEAD_LETTER_REPLAY_SCAN_MAX: '0' })).toContain(
      'DEAD_LETTER_REPLAY_SCAN_MAX',
    );
    expect(rejection({ ...valid, DEAD_LETTER_REPLAY_SCAN_MAX: '100001' })).toContain(
      'DEAD_LETTER_REPLAY_SCAN_MAX',
    );
  });
});

describe('loadApiConfig: security scanning (step 4.1 S8, S13)', () => {
  it('defaults the Rspamd platform settings and leaves the controller unconfigured', () => {
    const cfg = loadApiConfig(valid);
    expect(rspamdPlatformSettingsOf(cfg)).toEqual({
      spamScore: 6,
      suspiciousScore: 4,
      scoreMin: 1,
      scoreMax: 15,
      phishingVerdict: 'suspicious',
      dmarcRejectVerdict: 'suspicious',
      authFailureVerdict: 'reason_only',
    });
    expect(cfg.RSPAMD_CONTROLLER_URL).toBeUndefined();
    expect(cfg.RSPAMD_CONTROLLER_ENABLE_PASSWORD).toBeUndefined();
    expect(cfg.SCAN_FUZZY_WEIGHT).toBe(10);
  });

  it('reads the platform settings and the controller', () => {
    const cfg = loadApiConfig({
      ...valid,
      SCAN_RSPAMD_SPAM_SCORE: '7.5',
      SCAN_RSPAMD_SUSPICIOUS_SCORE: '5',
      SCAN_RSPAMD_PHISHING_VERDICT: 'malicious',
      RSPAMD_CONTROLLER_URL: 'http://rspamd:11334',
      RSPAMD_CONTROLLER_ENABLE_PASSWORD: 'enable-secret',
      SCAN_FUZZY_WEIGHT: '25',
    });
    expect(rspamdPlatformSettingsOf(cfg)).toMatchObject({
      spamScore: 7.5,
      suspiciousScore: 5,
      phishingVerdict: 'malicious',
    });
    expect(cfg.RSPAMD_CONTROLLER_URL).toBe('http://rspamd:11334');
    expect(cfg.SCAN_FUZZY_WEIGHT).toBe(25);
  });

  it.each([
    [{ SCAN_RSPAMD_SUSPICIOUS_SCORE: '6' }, 'SCAN_RSPAMD_SUSPICIOUS_SCORE'],
    [{ SCAN_RSPAMD_SPAM_SCORE: '20' }, 'SCAN_RSPAMD_SPAM_SCORE'],
    [{ SCAN_RSPAMD_SCORE_MIN: '0' }, 'SCAN_RSPAMD_SCORE_MIN'],
    [{ SCAN_RSPAMD_PHISHING_VERDICT: 'reason_only' }, 'SCAN_RSPAMD_PHISHING_VERDICT'],
    [{ SCAN_RSPAMD_SPAM_SCORE: '6.123' }, 'SCAN_RSPAMD_SPAM_SCORE'],
    [{ RSPAMD_CONTROLLER_URL: 'ftp://rspamd' }, 'RSPAMD_CONTROLLER_URL'],
    [{ RSPAMD_CONTROLLER_URL: 'http://u:p@rspamd:11334' }, 'RSPAMD_CONTROLLER_URL'],
    [{ SCAN_FUZZY_WEIGHT: '0' }, 'SCAN_FUZZY_WEIGHT'],
  ])('refuses %j, naming the key', (env, key) => {
    const message = rejection({ ...valid, ...env });
    expect(message).toContain(key);
    expect(message).not.toContain('u:p');
  });
});

describe('loadApiConfig: attachment scanning (step 4.2 A8, A13)', () => {
  it('defaults the attachment platform settings and the rescan cap', () => {
    const cfg = loadApiConfig(valid);
    expect(attachmentPlatformSettingsOf(cfg)).toEqual({
      ...ATTACHMENT_PLATFORM_DEFAULTS,
      deniedTypes: [...ATTACHMENT_PLATFORM_DEFAULTS.deniedTypes],
    });
    expect(cfg.ATTACHMENT_RESCAN_MAX_MESSAGES).toBe(5000);
  });

  it('reads the ATTACHMENT_* keys as the email-worker does', () => {
    const cfg = loadApiConfig({
      ...valid,
      ATTACHMENT_MAX_BYTES: '10485760',
      ATTACHMENT_DENIED_TYPES: 'pe_executable,zip',
      ATTACHMENT_DENIED_TYPE_VERDICT: 'malicious',
      ATTACHMENT_RESCAN_MAX_MESSAGES: '20000',
    });
    expect(attachmentPlatformSettingsOf(cfg)).toMatchObject({
      maxAttachmentBytes: 10_485_760,
      deniedTypes: ['pe_executable', 'zip'],
      deniedTypeVerdict: 'malicious',
    });
    expect(cfg.ATTACHMENT_RESCAN_MAX_MESSAGES).toBe(20_000);
  });

  it.each([
    [{ ATTACHMENT_MAX_BYTES: '40000000' }, 'ATTACHMENT_MAX_BYTES'],
    [{ ATTACHMENT_DENIED_TYPES: 'no_such_type' }, 'ATTACHMENT_DENIED_TYPES'],
    [{ ATTACHMENT_DENIED_TYPES: 'unknown' }, 'ATTACHMENT_DENIED_TYPES'],
    [{ ATTACHMENT_ENCRYPTED_VERDICT: 'clean' }, 'ATTACHMENT_ENCRYPTED_VERDICT'],
    [
      { ATTACHMENT_MAX_ENTRY_BYTES: '2000', ATTACHMENT_MAX_DECOMPRESSED_BYTES: '1000' },
      'ATTACHMENT_MAX_ENTRY_BYTES',
    ],
    [{ ATTACHMENT_RESCAN_MAX_MESSAGES: '50001' }, 'ATTACHMENT_RESCAN_MAX_MESSAGES'],
  ])('refuses %j, naming the key', (env, key) => {
    expect(rejection({ ...valid, ...env })).toContain(key);
  });
});

describe('loadApiConfig: phishing and BEC (step 4.4 B13, B18)', () => {
  it('defaults the BEC platform settings and the per-tenant caps', () => {
    const cfg = loadApiConfig(valid);
    expect(becPlatformSettingsOf(cfg)).toEqual(BEC_PLATFORM_DEFAULTS);
    expect(cfg).toMatchObject({
      BEC_MAX_EXECUTIVES: 500,
      BEC_MAX_VENDORS: 2000,
      BEC_MAX_TRUSTED_SENDERS: 1000,
      BEC_SUPPRESSIONS_MAX_PER_TENANT: 200,
    });
  });

  it('reads the BEC_* keys as the email-worker does', () => {
    const cfg = loadApiConfig({
      ...valid,
      BEC_SUSPICIOUS_SCORE: '35',
      BEC_MALICIOUS_SCORE: '75',
      BEC_LLM_MODE: 'shadow',
      BEC_MAX_EXECUTIVES: '20',
    });
    expect(becPlatformSettingsOf(cfg)).toMatchObject({
      suspiciousScore: 35,
      maliciousScore: 75,
      llmMode: 'shadow',
    });
    expect(cfg.BEC_MAX_EXECUTIVES).toBe(20);
  });

  it.each([
    [{ BEC_SUSPICIOUS_SCORE: '10' }, 'BEC_SUSPICIOUS_SCORE'],
    [{ BEC_MALICIOUS_SCORE: '99' }, 'BEC_MALICIOUS_SCORE'],
    [{ BEC_LLM_MODE: 'always' }, 'BEC_LLM_MODE'],
    [{ BEC_AI_MALICIOUS_BAND: '20' }, 'BEC_AI_MALICIOUS_BAND'],
    [{ BEC_HISTORY_MAX_RETENTION_DAYS: '1000' }, 'BEC_HISTORY_MAX_RETENTION_DAYS'],
    [{ BEC_MAX_VENDORS: '0' }, 'BEC_MAX_VENDORS'],
  ])('refuses %o naming %s', (env, key) => {
    expect(rejection({ ...valid, ...env })).toContain(key);
  });
});

describe('loadApiConfig: data loss prevention (step 4.5 D16, D18, D21)', () => {
  it('defaults the DLP platform settings, pattern limits and per-tenant caps', () => {
    const cfg = loadApiConfig(valid);
    expect(dlpPlatformSettingsOf(cfg)).toEqual(DLP_PLATFORM_DEFAULTS);
    expect(cfg).toMatchObject({
      DLP_CUSTOM_PATTERN_MAX_LENGTH: 256,
      DLP_CUSTOM_PATTERN_PROBE_MAX_MS: 50,
      DLP_CUSTOM_SCAN_MAX_CHARS: 1_000_000,
      DLP_CUSTOM_PATTERNS_MAX_PER_TENANT: 50,
      DLP_DICTIONARIES_MAX_PER_TENANT: 20,
      DLP_DICTIONARY_MAX_TERMS: 1000,
      DLP_POLICIES_MAX_PER_TENANT: 20,
      DLP_RULES_MAX_PER_POLICY: 50,
      DLP_EXCEPTIONS_MAX_PER_TENANT: 500,
      DLP_EXCEPTION_MAX_DAYS: 365,
    });
    expect(cfg.DLP_EVIDENCE_KEY_PREVIOUS).toBeUndefined();
  });

  it('reads the DLP_* keys as the email-worker does', () => {
    const cfg = loadApiConfig({
      ...valid,
      DLP_CONFIDENCE_THRESHOLD: '0.7',
      DLP_DEFAULT_POLICY: 'allow',
      DLP_EVIDENCE_ENABLED: 'false',
      DLP_EVIDENCE_MAX_RETENTION_DAYS: '90',
      DLP_POLICIES_MAX_PER_TENANT: '5',
      DLP_EVIDENCE_KEY_PREVIOUS: hex64(),
    });
    expect(dlpPlatformSettingsOf(cfg)).toMatchObject({
      confidenceThreshold: 0.7,
      defaultPolicy: 'allow',
      evidenceEnabled: false,
      evidenceMaxRetentionDays: 90,
    });
    expect(cfg.DLP_POLICIES_MAX_PER_TENANT).toBe(5);
  });

  it('requires the evidence key and names it without printing the value', () => {
    const { DLP_EVIDENCE_KEY: _omit, ...withoutKey } = valid as Record<string, string>;
    expect(rejection(withoutKey)).toContain('DLP_EVIDENCE_KEY');
    const bad = 'not-a-key-XYZ-marker';
    const message = rejection({ ...valid, DLP_EVIDENCE_KEY: bad });
    expect(message).toContain('DLP_EVIDENCE_KEY');
    expect(message).not.toContain(bad);
    const same = hex64();
    const reused = rejection({ ...valid, DLP_EVIDENCE_KEY: same, DLP_EVIDENCE_KEY_PREVIOUS: same });
    expect(reused).toContain('DLP_EVIDENCE_KEY_PREVIOUS');
    expect(reused).not.toContain(same);
  });

  it.each([
    [{ DLP_CONFIDENCE_THRESHOLD: '0.3' }, 'DLP_CONFIDENCE_THRESHOLD'],
    [{ DLP_DEFAULT_POLICY: 'block' }, 'DLP_DEFAULT_POLICY'],
    [{ DLP_EVIDENCE_ENABLED: 'yes' }, 'DLP_EVIDENCE_ENABLED'],
    [{ DLP_EVIDENCE_MAX_RETENTION_DAYS: '365' }, 'DLP_EVIDENCE_MAX_RETENTION_DAYS'],
    [
      { DLP_EVIDENCE_DEFAULT_RETENTION_DAYS: '100', DLP_EVIDENCE_MAX_RETENTION_DAYS: '60' },
      'DLP_EVIDENCE_DEFAULT_RETENTION_DAYS',
    ],
    [{ DLP_CONTEXT_WINDOW_CHARS: '4' }, 'DLP_CONTEXT_WINDOW_CHARS'],
    [{ DLP_CUSTOM_PATTERN_MAX_LENGTH: '1000' }, 'DLP_CUSTOM_PATTERN_MAX_LENGTH'],
    [{ DLP_RULES_MAX_PER_POLICY: '0' }, 'DLP_RULES_MAX_PER_POLICY'],
    [{ DLP_EXCEPTION_MAX_DAYS: '0' }, 'DLP_EXCEPTION_MAX_DAYS'],
    [{ DLP_EVIDENCE_KEY_PREVIOUS: 'abc' }, 'DLP_EVIDENCE_KEY_PREVIOUS'],
  ])('refuses %o naming %s', (env, key) => {
    expect(rejection({ ...valid, ...env })).toContain(key);
  });
});

describe('loadApiConfig: sandbox (step 4.6 X17)', () => {
  it('defaults the sandbox platform settings and the expected backend (disabled)', () => {
    const cfg = loadApiConfig(valid);
    expect(sandboxPlatformSettingsOf(cfg)).toEqual(SANDBOX_PLATFORM_DEFAULTS);
    expect(cfg.SANDBOX_EXPECTED_BACKEND).toBe('disabled');
  });

  it('reads the SANDBOX_* platform keys as the email-worker does', () => {
    const cfg = loadApiConfig({
      ...valid,
      SANDBOX_TENANT_DEFAULT_ENABLED: 'true',
      SANDBOX_FILE_TYPES: 'pdf, script_shell',
      SANDBOX_MAX_SAMPLE_BYTES: '1048576',
      SANDBOX_BROWSER_ANALYSIS: 'false',
      SANDBOX_EXPECTED_BACKEND: 'static',
    });
    expect(sandboxPlatformSettingsOf(cfg)).toEqual({
      tenantDefaultEnabled: true,
      fileTypes: ['pdf', 'script_shell'],
      maxSampleBytes: 1_048_576,
      browserAnalysis: false,
    });
    expect(cfg.SANDBOX_EXPECTED_BACKEND).toBe('static');
  });

  it('accepts the local test runner only in APP_ENV local or ci', () => {
    expect(
      loadApiConfig({ ...valid, APP_ENV: 'local', SANDBOX_EXPECTED_BACKEND: 'hardened-container' })
        .SANDBOX_EXPECTED_BACKEND,
    ).toBe('hardened-container');
    expect(
      rejection({
        ...valid,
        APP_ENV: 'production',
        SANDBOX_EXPECTED_BACKEND: 'hardened-container',
      }),
    ).toContain('SANDBOX_EXPECTED_BACKEND');
  });

  it.each([
    [{ SANDBOX_TENANT_DEFAULT_ENABLED: 'yes' }, 'SANDBOX_TENANT_DEFAULT_ENABLED'],
    [{ SANDBOX_FILE_TYPES: 'pdf,not_a_type' }, 'SANDBOX_FILE_TYPES'],
    [{ SANDBOX_MAX_SAMPLE_BYTES: '0' }, 'SANDBOX_MAX_SAMPLE_BYTES'],
    [{ SANDBOX_MAX_SAMPLE_BYTES: String(64 * 1024 * 1024 + 1) }, 'SANDBOX_MAX_SAMPLE_BYTES'],
    [{ SANDBOX_BROWSER_ANALYSIS: '1' }, 'SANDBOX_BROWSER_ANALYSIS'],
    [{ SANDBOX_EXPECTED_BACKEND: 'vm' }, 'SANDBOX_EXPECTED_BACKEND'],
  ])('refuses %o naming %s', (env, key) => {
    expect(rejection({ ...valid, ...env })).toContain(key);
  });
});

describe('loadApiConfig: risk scoring (step 5.1 R16)', () => {
  it('defaults the platform profile and the version cap', () => {
    const cfg = loadApiConfig(valid);
    expect(cfg.RISK_PLATFORM_PROFILE).toBe('rsk-default/1');
    expect(cfg.RISK_PROFILE_MAX_VERSIONS).toBe(200);
  });

  it('reads RISK_PLATFORM_PROFILE and RISK_PROFILE_MAX_VERSIONS within bounds', () => {
    const cfg = loadApiConfig({
      ...valid,
      RISK_PLATFORM_PROFILE: 'rsk-default/1',
      RISK_PROFILE_MAX_VERSIONS: '10',
    });
    expect(cfg.RISK_PROFILE_MAX_VERSIONS).toBe(10);
    expect(
      loadApiConfig({ ...valid, RISK_PROFILE_MAX_VERSIONS: '1000' }).RISK_PROFILE_MAX_VERSIONS,
    ).toBe(1000);
  });

  it.each([
    [{ RISK_PLATFORM_PROFILE: 'rsk-default/2' }, 'RISK_PLATFORM_PROFILE'],
    [{ RISK_PLATFORM_PROFILE: 'rsk-custom' }, 'RISK_PLATFORM_PROFILE'],
    [{ RISK_PROFILE_MAX_VERSIONS: '9' }, 'RISK_PROFILE_MAX_VERSIONS'],
    [{ RISK_PROFILE_MAX_VERSIONS: '1001' }, 'RISK_PROFILE_MAX_VERSIONS'],
    [{ RISK_PROFILE_MAX_VERSIONS: 'many' }, 'RISK_PROFILE_MAX_VERSIONS'],
  ])('refuses %o naming %s', (env, key) => {
    expect(rejection({ ...valid, ...env })).toContain(key);
  });
});

describe('loadApiConfig: policy engine (step 5.2 §5)', () => {
  it('defaults the platform default and every bound', () => {
    const cfg = loadApiConfig(valid);
    expect(cfg.POLICY_PLATFORM_DEFAULT).toBe('pol-default/1');
    expect(cfg.POLICY_MAX_POLICIES).toBe(100);
    expect(cfg.POLICY_MAX_VERSIONS_PER_POLICY).toBe(200);
    expect(cfg.POLICY_MAX_ACTIVE_RULES).toBe(1000);
    expect(cfg.POLICY_HISTORY_MAX_RANGE_DAYS).toBe(31);
    expect(cfg.DEPARTMENT_MAX_PER_ORG).toBe(500);
    expect(cfg.DEPARTMENT_MAX_MEMBERS).toBe(5000);
  });

  it('reads every key at its lower and upper bound', () => {
    const low = loadApiConfig({
      ...valid,
      POLICY_PLATFORM_DEFAULT: 'pol-default/1',
      POLICY_MAX_POLICIES: '10',
      POLICY_MAX_VERSIONS_PER_POLICY: '10',
      POLICY_MAX_ACTIVE_RULES: '100',
      POLICY_HISTORY_MAX_RANGE_DAYS: '1',
      DEPARTMENT_MAX_PER_ORG: '10',
      DEPARTMENT_MAX_MEMBERS: '100',
    });
    expect([
      low.POLICY_MAX_POLICIES,
      low.POLICY_MAX_VERSIONS_PER_POLICY,
      low.POLICY_MAX_ACTIVE_RULES,
      low.POLICY_HISTORY_MAX_RANGE_DAYS,
      low.DEPARTMENT_MAX_PER_ORG,
      low.DEPARTMENT_MAX_MEMBERS,
    ]).toEqual([10, 10, 100, 1, 10, 100]);
    const high = loadApiConfig({
      ...valid,
      POLICY_MAX_POLICIES: '100',
      POLICY_MAX_VERSIONS_PER_POLICY: '1000',
      POLICY_MAX_ACTIVE_RULES: '5000',
      POLICY_HISTORY_MAX_RANGE_DAYS: '186',
      DEPARTMENT_MAX_PER_ORG: '5000',
      DEPARTMENT_MAX_MEMBERS: '50000',
    });
    expect([
      high.POLICY_MAX_POLICIES,
      high.POLICY_MAX_VERSIONS_PER_POLICY,
      high.POLICY_MAX_ACTIVE_RULES,
      high.POLICY_HISTORY_MAX_RANGE_DAYS,
      high.DEPARTMENT_MAX_PER_ORG,
      high.DEPARTMENT_MAX_MEMBERS,
    ]).toEqual([100, 1000, 5000, 186, 5000, 50000]);
  });

  it.each([
    [{ POLICY_PLATFORM_DEFAULT: 'pol-default/2' }, 'POLICY_PLATFORM_DEFAULT'],
    [{ POLICY_PLATFORM_DEFAULT: 'custom' }, 'POLICY_PLATFORM_DEFAULT'],
    [{ POLICY_MAX_POLICIES: '9' }, 'POLICY_MAX_POLICIES'],
    [{ POLICY_MAX_POLICIES: '101' }, 'POLICY_MAX_POLICIES'],
    [{ POLICY_MAX_VERSIONS_PER_POLICY: '9' }, 'POLICY_MAX_VERSIONS_PER_POLICY'],
    [{ POLICY_MAX_VERSIONS_PER_POLICY: '1001' }, 'POLICY_MAX_VERSIONS_PER_POLICY'],
    [{ POLICY_MAX_ACTIVE_RULES: '99' }, 'POLICY_MAX_ACTIVE_RULES'],
    [{ POLICY_MAX_ACTIVE_RULES: '5001' }, 'POLICY_MAX_ACTIVE_RULES'],
    [{ POLICY_HISTORY_MAX_RANGE_DAYS: '0' }, 'POLICY_HISTORY_MAX_RANGE_DAYS'],
    [{ POLICY_HISTORY_MAX_RANGE_DAYS: '187' }, 'POLICY_HISTORY_MAX_RANGE_DAYS'],
    [{ DEPARTMENT_MAX_PER_ORG: '9' }, 'DEPARTMENT_MAX_PER_ORG'],
    [{ DEPARTMENT_MAX_PER_ORG: '5001' }, 'DEPARTMENT_MAX_PER_ORG'],
    [{ DEPARTMENT_MAX_MEMBERS: '99' }, 'DEPARTMENT_MAX_MEMBERS'],
    [{ DEPARTMENT_MAX_MEMBERS: '50001' }, 'DEPARTMENT_MAX_MEMBERS'],
    [{ DEPARTMENT_MAX_MEMBERS: 'lots' }, 'DEPARTMENT_MAX_MEMBERS'],
  ])('refuses %o naming %s', (env, key) => {
    expect(rejection({ ...valid, ...env })).toContain(key);
  });
});

describe('loadApiConfig: policy builder (step 7.3 §3)', () => {
  it('defaults the sample size, the deadline and the per-principal sample dry-runs', () => {
    expect(loadApiConfig(valid)).toMatchObject({
      POLICY_DRY_RUN_SAMPLE_MAX: 50,
      POLICY_DRY_RUN_DEADLINE_MS: 10_000,
      POLICY_SAMPLE_DRY_RUNS_PER_MINUTE: 6,
    });
  });

  it('accepts the bounds', () => {
    for (const [key, value] of [
      ['POLICY_DRY_RUN_SAMPLE_MAX', '1'],
      ['POLICY_DRY_RUN_SAMPLE_MAX', '200'],
      ['POLICY_DRY_RUN_DEADLINE_MS', '1000'],
      ['POLICY_DRY_RUN_DEADLINE_MS', '30000'],
      ['POLICY_SAMPLE_DRY_RUNS_PER_MINUTE', '1'],
      ['POLICY_SAMPLE_DRY_RUNS_PER_MINUTE', '60'],
    ] as const) {
      expect(loadApiConfig({ ...valid, [key]: value })[key], `${key}=${value}`).toBe(Number(value));
    }
  });

  it.each([
    ['POLICY_DRY_RUN_SAMPLE_MAX', '0'],
    ['POLICY_DRY_RUN_SAMPLE_MAX', '201'],
    ['POLICY_DRY_RUN_SAMPLE_MAX', 'many'],
    ['POLICY_DRY_RUN_DEADLINE_MS', '999'],
    ['POLICY_DRY_RUN_DEADLINE_MS', '30001'],
    ['POLICY_DRY_RUN_DEADLINE_MS', '1.5'],
    ['POLICY_SAMPLE_DRY_RUNS_PER_MINUTE', '0'],
    ['POLICY_SAMPLE_DRY_RUNS_PER_MINUTE', '61'],
  ])('refuses %s=%s naming the key', (key, value) => {
    expect(rejection({ ...valid, [key]: value })).toContain(key);
  });
});

describe('loadApiConfig: quarantine (step 5.3 §5)', () => {
  it('defaults every bound and requires the download-token key', () => {
    const cfg = loadApiConfig(valid);
    expect(cfg).toMatchObject({
      QUARANTINE_MAX_HOLD_DAYS: 60,
      QUARANTINE_MAX_REVIEW_DAYS: 13,
      QUARANTINE_TX_TIMEOUT_MS: 120_000,
      QUARANTINE_RELEASE_MAX_VERDICT_AGE_HOURS: 72,
      QUARANTINE_RELEASE_SIGNATURE_MAX_LAG_HOURS: 24,
      QUARANTINE_MANUAL_FROM_REJECT_MAX_DAYS: 30,
      QUARANTINE_SEARCH_MAX_RANGE_DAYS: 62,
      QUARANTINE_SEARCH_MAX_PAGE_SIZE: 100,
      QUARANTINE_PREVIEW_MAX_BODY_BYTES: 262_144,
      QUARANTINE_PREVIEW_MAX_TEXT_CHARS: 100_000,
      QUARANTINE_PREVIEW_RATE_PER_MINUTE: 60,
      QUARANTINE_DOWNLOAD_TOKEN_TTL_SECONDS: 60,
      QUARANTINE_DOWNLOAD_MAX_BYTES: 26_214_400,
      QUARANTINE_DOWNLOAD_GRANTS_PER_HOUR: 20,
      QUARANTINE_BULK_MAX_ITEMS: 100,
      QUARANTINE_BULK_MAX_ITEMS_PER_MINUTE: 1000,
      QUARANTINE_BULK_REQUESTS_PER_MINUTE: 20,
      QUARANTINE_BULK_DEADLINE_MS: 25_000,
      LIFECYCLE_DEADLINE_QUARANTINED_HOURS: 2160,
      LIFECYCLE_DEADLINE_HELD_FOR_REVIEW_HOURS: 336,
    });
    const { QUARANTINE_DOWNLOAD_TOKEN_KEY: _omit, ...withoutKey } = valid as Record<string, string>;
    expect(rejection(withoutKey)).toContain('QUARANTINE_DOWNLOAD_TOKEN_KEY');
    const bad = 'short-key-MARKER';
    const message = rejection({ ...valid, QUARANTINE_DOWNLOAD_TOKEN_KEY: bad });
    expect(message).toContain('QUARANTINE_DOWNLOAD_TOKEN_KEY');
    expect(message).not.toContain(bad);
  });

  it('accepts every key at its bounds', () => {
    const low = loadApiConfig({
      ...valid,
      QUARANTINE_MAX_HOLD_DAYS: '7',
      QUARANTINE_MAX_REVIEW_DAYS: '1',
      QUARANTINE_TX_TIMEOUT_MS: '120000',
      QUARANTINE_SEARCH_MAX_RANGE_DAYS: '1',
      QUARANTINE_SEARCH_MAX_PAGE_SIZE: '10',
      QUARANTINE_PREVIEW_MAX_BODY_BYTES: '16384',
      QUARANTINE_DOWNLOAD_TOKEN_TTL_SECONDS: '10',
      QUARANTINE_BULK_MAX_ITEMS: '1',
      QUARANTINE_BULK_DEADLINE_MS: '5000',
    });
    expect(low.QUARANTINE_BULK_MAX_ITEMS).toBe(1);
    const high = loadApiConfig({
      ...valid,
      QUARANTINE_MAX_HOLD_DAYS: '80',
      QUARANTINE_TX_TIMEOUT_MS: '600000',
      QUARANTINE_SEARCH_MAX_PAGE_SIZE: '500',
      QUARANTINE_DOWNLOAD_MAX_BYTES: '52428800',
      QUARANTINE_BULK_MAX_ITEMS: '500',
      QUARANTINE_BULK_MAX_ITEMS_PER_MINUTE: '10000',
    });
    expect(high.QUARANTINE_MAX_HOLD_DAYS).toBe(80);
  });

  it('rejects out-of-range keys, a short transaction budget and hold/review days at the lifecycle deadline', () => {
    expect(rejection({ ...valid, QUARANTINE_TX_TIMEOUT_MS: '119999' })).toContain(
      'QUARANTINE_TX_TIMEOUT_MS',
    );
    expect(rejection({ ...valid, QUARANTINE_MAX_HOLD_DAYS: '81' })).toContain(
      'QUARANTINE_MAX_HOLD_DAYS',
    );
    expect(rejection({ ...valid, QUARANTINE_BULK_MAX_ITEMS: '501' })).toContain(
      'QUARANTINE_BULK_MAX_ITEMS',
    );
    expect(rejection({ ...valid, QUARANTINE_DOWNLOAD_TOKEN_TTL_SECONDS: '301' })).toContain(
      'QUARANTINE_DOWNLOAD_TOKEN_TTL_SECONDS',
    );
    expect(
      rejection({
        ...valid,
        QUARANTINE_MAX_HOLD_DAYS: '60',
        LIFECYCLE_DEADLINE_QUARANTINED_HOURS: '1440',
      }),
    ).toContain('QUARANTINE_MAX_HOLD_DAYS');
    expect(
      rejection({
        ...valid,
        QUARANTINE_MAX_REVIEW_DAYS: '13',
        LIFECYCLE_DEADLINE_HELD_FOR_REVIEW_HOURS: '312',
      }),
    ).toContain('QUARANTINE_MAX_REVIEW_DAYS');
  });
});

describe('loadApiConfig: REST API conventions (step 6.1 §3.7)', () => {
  /** `valid` without the generous test limits of TEST_DOMAIN_ENV, so the defaults show. */
  const base = Object.fromEntries(
    Object.entries(valid).filter(([key]) => !key.startsWith('API_RATE_')),
  ) as Record<string, string>;

  it('defaults every key and requires the cursor key', () => {
    const cfg = loadApiConfig(base);
    expect(cfg).toMatchObject({
      API_CURSOR_TTL_SECONDS: 86_400,
      API_RATE_PRINCIPAL_PER_MINUTE: 600,
      API_RATE_TENANT_DEFAULT_PER_MINUTE: 300,
      API_RATE_TENANT_MIN_PER_MINUTE: 10,
      API_RATE_TENANT_MAX_PER_MINUTE: 10_000,
      API_RATE_SENSITIVE_PER_MINUTE: 30,
      API_RATE_EXPENSIVE_PER_MINUTE: 60,
      API_RATE_LIMIT_CACHE_SECONDS: 60,
      API_IDEMPOTENCY_LEGACY_MODE: 'enforce',
      API_IDEMPOTENCY_PENDING_TTL_SECONDS: 300,
      API_LIST_SCAN_BUDGET_ROWS: 5000,
      API_MESSAGES_MAX_RANGE_DAYS: 31,
      API_AUDIT_MAX_RANGE_DAYS: 90,
      REPORTS_MAX_RANGE_DAYS: 31,
      REPORTS_CACHE_TTL_SECONDS: 60,
      REPORTS_QUERY_TIMEOUT_MS: 10_000,
      RECIPIENT_SUPPRESSIONS_MAX_MANUAL: 100_000,
    });
    expect(cfg.API_CURSOR_KEY).toBe(base.API_CURSOR_KEY);
    expect(cfg.API_CURSOR_KEY_PREVIOUS).toBeUndefined();
    const { API_CURSOR_KEY: _omit, ...withoutKey } = base;
    expect(rejection(withoutKey)).toContain('API_CURSOR_KEY');
  });

  it('names the cursor keys but never their values', () => {
    const bad = 'short-cursor-key-MARKER';
    const message = rejection({ ...base, API_CURSOR_KEY: bad });
    expect(message).toContain('API_CURSOR_KEY');
    expect(message).not.toContain(bad);
    const previous = rejection({ ...base, API_CURSOR_KEY_PREVIOUS: bad });
    expect(previous).toContain('API_CURSOR_KEY_PREVIOUS');
    expect(previous).not.toContain(bad);
  });

  it('accepts a previous cursor key (rotation) and an empty one', () => {
    const previous = hex64();
    expect(
      loadApiConfig({ ...base, API_CURSOR_KEY_PREVIOUS: previous }).API_CURSOR_KEY_PREVIOUS,
    ).toBe(previous);
    expect(loadApiConfig({ ...base, API_CURSOR_KEY_PREVIOUS: '' }).API_CURSOR_KEY_PREVIOUS).toBe(
      undefined,
    );
  });

  it('reads API_CURSOR_KEY from API_CURSOR_KEY_FILE', () => {
    const dir = mkdtempSync(join(tmpdir(), 'api-cursor-key-'));
    const file = join(dir, 'key');
    const key = hex64();
    writeFileSync(file, `${key}\n`);
    try {
      const { API_CURSOR_KEY: _omit, ...withoutKey } = base;
      expect(loadApiConfig({ ...withoutKey, API_CURSOR_KEY_FILE: file }).API_CURSOR_KEY).toBe(key);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('accepts every key at its bounds', () => {
    const low = loadApiConfig({
      ...base,
      API_CURSOR_TTL_SECONDS: '300',
      API_RATE_PRINCIPAL_PER_MINUTE: '10',
      API_RATE_TENANT_DEFAULT_PER_MINUTE: '10',
      API_RATE_TENANT_MIN_PER_MINUTE: '1',
      API_RATE_TENANT_MAX_PER_MINUTE: '10',
      API_RATE_SENSITIVE_PER_MINUTE: '1',
      API_RATE_EXPENSIVE_PER_MINUTE: '1',
      API_RATE_LIMIT_CACHE_SECONDS: '5',
      API_IDEMPOTENCY_LEGACY_MODE: 'warn',
      API_IDEMPOTENCY_PENDING_TTL_SECONDS: '30',
      API_LIST_SCAN_BUDGET_ROWS: '1000',
      API_MESSAGES_MAX_RANGE_DAYS: '1',
      API_AUDIT_MAX_RANGE_DAYS: '1',
      REPORTS_MAX_RANGE_DAYS: '1',
      // Step AI-6: the synchronous report window must fit in the report range.
      ASSISTANT_REPORT_SYNC_MAX_HOURS: '24',
      REPORTS_CACHE_TTL_SECONDS: '10',
      REPORTS_QUERY_TIMEOUT_MS: '1000',
      RECIPIENT_SUPPRESSIONS_MAX_MANUAL: '1',
    });
    expect(low.API_IDEMPOTENCY_LEGACY_MODE).toBe('warn');
    expect(low.API_RATE_TENANT_MIN_PER_MINUTE).toBe(1);
    const high = loadApiConfig({
      ...base,
      API_CURSOR_TTL_SECONDS: '604800',
      API_RATE_PRINCIPAL_PER_MINUTE: '10000',
      API_RATE_TENANT_DEFAULT_PER_MINUTE: '100000',
      API_RATE_TENANT_MIN_PER_MINUTE: '100000',
      API_RATE_TENANT_MAX_PER_MINUTE: '1000000',
      API_RATE_SENSITIVE_PER_MINUTE: '600',
      API_RATE_EXPENSIVE_PER_MINUTE: '600',
      API_RATE_LIMIT_CACHE_SECONDS: '300',
      API_IDEMPOTENCY_PENDING_TTL_SECONDS: '3600',
      API_LIST_SCAN_BUDGET_ROWS: '50000',
      API_MESSAGES_MAX_RANGE_DAYS: '92',
      API_AUDIT_MAX_RANGE_DAYS: '366',
      REPORTS_MAX_RANGE_DAYS: '92',
      REPORTS_CACHE_TTL_SECONDS: '900',
      REPORTS_QUERY_TIMEOUT_MS: '30000',
      RECIPIENT_SUPPRESSIONS_MAX_MANUAL: '1000000',
    });
    expect(high.API_RATE_TENANT_MAX_PER_MINUTE).toBe(1_000_000);
  });

  it.each([
    [{ API_CURSOR_TTL_SECONDS: '299' }, 'API_CURSOR_TTL_SECONDS'],
    [{ API_CURSOR_TTL_SECONDS: '604801' }, 'API_CURSOR_TTL_SECONDS'],
    [{ API_RATE_PRINCIPAL_PER_MINUTE: '9' }, 'API_RATE_PRINCIPAL_PER_MINUTE'],
    [{ API_RATE_PRINCIPAL_PER_MINUTE: '10001' }, 'API_RATE_PRINCIPAL_PER_MINUTE'],
    [{ API_RATE_TENANT_DEFAULT_PER_MINUTE: '9' }, 'API_RATE_TENANT_DEFAULT_PER_MINUTE'],
    [{ API_RATE_TENANT_DEFAULT_PER_MINUTE: '100001' }, 'API_RATE_TENANT_DEFAULT_PER_MINUTE'],
    [{ API_RATE_TENANT_MIN_PER_MINUTE: '0' }, 'API_RATE_TENANT_MIN_PER_MINUTE'],
    [{ API_RATE_TENANT_MAX_PER_MINUTE: '9' }, 'API_RATE_TENANT_MAX_PER_MINUTE'],
    [{ API_RATE_TENANT_MAX_PER_MINUTE: '1000001' }, 'API_RATE_TENANT_MAX_PER_MINUTE'],
    [{ API_RATE_SENSITIVE_PER_MINUTE: '0' }, 'API_RATE_SENSITIVE_PER_MINUTE'],
    [{ API_RATE_SENSITIVE_PER_MINUTE: '601' }, 'API_RATE_SENSITIVE_PER_MINUTE'],
    [{ API_RATE_EXPENSIVE_PER_MINUTE: '601' }, 'API_RATE_EXPENSIVE_PER_MINUTE'],
    [{ API_RATE_LIMIT_CACHE_SECONDS: '4' }, 'API_RATE_LIMIT_CACHE_SECONDS'],
    [{ API_RATE_LIMIT_CACHE_SECONDS: '301' }, 'API_RATE_LIMIT_CACHE_SECONDS'],
    [{ API_IDEMPOTENCY_LEGACY_MODE: 'off' }, 'API_IDEMPOTENCY_LEGACY_MODE'],
    [{ API_IDEMPOTENCY_PENDING_TTL_SECONDS: '29' }, 'API_IDEMPOTENCY_PENDING_TTL_SECONDS'],
    [{ API_IDEMPOTENCY_PENDING_TTL_SECONDS: '3601' }, 'API_IDEMPOTENCY_PENDING_TTL_SECONDS'],
    [{ API_LIST_SCAN_BUDGET_ROWS: '999' }, 'API_LIST_SCAN_BUDGET_ROWS'],
    [{ API_LIST_SCAN_BUDGET_ROWS: '50001' }, 'API_LIST_SCAN_BUDGET_ROWS'],
    [{ API_MESSAGES_MAX_RANGE_DAYS: '93' }, 'API_MESSAGES_MAX_RANGE_DAYS'],
    [{ API_AUDIT_MAX_RANGE_DAYS: '367' }, 'API_AUDIT_MAX_RANGE_DAYS'],
    [{ REPORTS_MAX_RANGE_DAYS: '0' }, 'REPORTS_MAX_RANGE_DAYS'],
    [{ REPORTS_CACHE_TTL_SECONDS: '901' }, 'REPORTS_CACHE_TTL_SECONDS'],
    [{ REPORTS_QUERY_TIMEOUT_MS: '999' }, 'REPORTS_QUERY_TIMEOUT_MS'],
    [{ REPORTS_QUERY_TIMEOUT_MS: '30001' }, 'REPORTS_QUERY_TIMEOUT_MS'],
    [{ RECIPIENT_SUPPRESSIONS_MAX_MANUAL: '0' }, 'RECIPIENT_SUPPRESSIONS_MAX_MANUAL'],
    [{ RECIPIENT_SUPPRESSIONS_MAX_MANUAL: '1000001' }, 'RECIPIENT_SUPPRESSIONS_MAX_MANUAL'],
  ])('refuses %o naming %s', (env, key) => {
    expect(rejection({ ...base, ...env })).toContain(key);
  });

  it('requires tenant min <= default <= max', () => {
    expect(
      rejection({
        ...base,
        API_RATE_TENANT_MIN_PER_MINUTE: '500',
        API_RATE_TENANT_DEFAULT_PER_MINUTE: '300',
      }),
    ).toContain('API_RATE_TENANT_MIN_PER_MINUTE');
    expect(
      rejection({
        ...base,
        API_RATE_TENANT_DEFAULT_PER_MINUTE: '3000',
        API_RATE_TENANT_MAX_PER_MINUTE: '2000',
      }),
    ).toContain('API_RATE_TENANT_MAX_PER_MINUTE');
  });
});

describe('loadApiConfig: webhooks and notifications (step 6.2 §4.4)', () => {
  it('defaults every key and requires the secret encryption key', () => {
    const cfg = loadApiConfig(valid);
    expect(cfg).toMatchObject({
      WEBHOOK_ALLOWED_PORTS: [443],
      WEBHOOK_ALLOW_HTTP: false,
      WEBHOOK_MAX_SUBSCRIPTIONS_PER_ORG: 10,
      WEBHOOK_SECRET_OVERLAP_HOURS_DEFAULT: 24,
      WEBHOOK_HISTORY_MAX_RANGE_DAYS: 31,
      WEBHOOK_REPLAY_MAX_RANGE_HOURS: 72,
      WEBHOOK_REPLAY_MAX_PER_DELIVERY: 10,
      WEBHOOK_REPLAY_REQUESTS_PER_HOUR: 10,
      WEBHOOK_TEST_REQUESTS_PER_MINUTE: 6,
    });
    expect(cfg.WEBHOOK_SECRET_ENCRYPTION_KEY).toBe(TEST_DOMAIN_ENV.WEBHOOK_SECRET_ENCRYPTION_KEY);
    expect(cfg.WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS).toBeUndefined();
    expect(cfg.URL_CLICK_BASE_URL).toBeUndefined();
    const { WEBHOOK_SECRET_ENCRYPTION_KEY: _omit, ...withoutKey } = valid as Record<string, string>;
    expect(rejection(withoutKey)).toContain('WEBHOOK_SECRET_ENCRYPTION_KEY');
  });

  it('names the cipher keys but never their values; the previous key must differ', () => {
    const bad = 'short-webhook-key-MARKER';
    const message = rejection({ ...valid, WEBHOOK_SECRET_ENCRYPTION_KEY: bad });
    expect(message).toContain('WEBHOOK_SECRET_ENCRYPTION_KEY');
    expect(message).not.toContain(bad);
    const previous = rejection({ ...valid, WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS: bad });
    expect(previous).toContain('WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS');
    expect(previous).not.toContain(bad);
    const same = rejection({
      ...valid,
      WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS:
        TEST_DOMAIN_ENV.WEBHOOK_SECRET_ENCRYPTION_KEY!.toUpperCase(),
    });
    expect(same).toContain('WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS');
    expect(same).not.toContain(TEST_DOMAIN_ENV.WEBHOOK_SECRET_ENCRYPTION_KEY!);
    const other = hex64();
    expect(
      loadApiConfig({ ...valid, WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS: other })
        .WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS,
    ).toBe(other);
    expect(
      loadApiConfig({ ...valid, WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS: '' })
        .WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS,
    ).toBeUndefined();
  });

  it('reads WEBHOOK_SECRET_ENCRYPTION_KEY from WEBHOOK_SECRET_ENCRYPTION_KEY_FILE', () => {
    const dir = mkdtempSync(join(tmpdir(), 'api-webhook-key-'));
    const file = join(dir, 'key');
    const key = hex64();
    writeFileSync(file, `${key}\n`);
    try {
      const { WEBHOOK_SECRET_ENCRYPTION_KEY: _omit, ...withoutKey } = valid as Record<
        string,
        string
      >;
      expect(
        loadApiConfig({ ...withoutKey, WEBHOOK_SECRET_ENCRYPTION_KEY_FILE: file })
          .WEBHOOK_SECRET_ENCRYPTION_KEY,
      ).toBe(key);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('parses the port list and refuses plain http outside APP_ENV local/ci', () => {
    expect(
      loadApiConfig({ ...valid, WEBHOOK_ALLOWED_PORTS: '443, 80,443,8443' }).WEBHOOK_ALLOWED_PORTS,
    ).toEqual([443, 80, 8443]);
    for (const ports of ['0', '65536', 'https', '443,,x', ' ']) {
      expect(rejection({ ...valid, WEBHOOK_ALLOWED_PORTS: ports }), ports).toContain(
        'WEBHOOK_ALLOWED_PORTS',
      );
    }
    for (const appEnv of ['local', 'ci']) {
      expect(
        loadApiConfig({ ...valid, APP_ENV: appEnv, WEBHOOK_ALLOW_HTTP: 'true' }).WEBHOOK_ALLOW_HTTP,
      ).toBe(true);
    }
    for (const appEnv of ['staging', 'production']) {
      expect(
        rejection({
          ...valid,
          APP_ENV: appEnv,
          PORTAL_PUBLIC_URL: 'https://portal.example.com',
          WEBHOOK_ALLOW_HTTP: 'true',
        }),
      ).toContain('WEBHOOK_ALLOW_HTTP');
    }
  });

  it('accepts the click-service base URL and refuses a non-URL', () => {
    expect(
      loadApiConfig({ ...valid, URL_CLICK_BASE_URL: 'https://click.gateway.example' })
        .URL_CLICK_BASE_URL,
    ).toBe('https://click.gateway.example');
    expect(rejection({ ...valid, URL_CLICK_BASE_URL: 'not a url' })).toContain(
      'URL_CLICK_BASE_URL',
    );
  });

  it('accepts every key at its bounds and refuses values outside them', () => {
    const low = loadApiConfig({
      ...valid,
      WEBHOOK_MAX_SUBSCRIPTIONS_PER_ORG: '1',
      WEBHOOK_SECRET_OVERLAP_HOURS_DEFAULT: '0',
      WEBHOOK_HISTORY_MAX_RANGE_DAYS: '1',
      WEBHOOK_REPLAY_MAX_RANGE_HOURS: '1',
      WEBHOOK_REPLAY_MAX_PER_DELIVERY: '1',
      WEBHOOK_REPLAY_REQUESTS_PER_HOUR: '1',
      WEBHOOK_TEST_REQUESTS_PER_MINUTE: '1',
    });
    expect(low.WEBHOOK_SECRET_OVERLAP_HOURS_DEFAULT).toBe(0);
    const high = loadApiConfig({
      ...valid,
      WEBHOOK_MAX_SUBSCRIPTIONS_PER_ORG: '100',
      WEBHOOK_SECRET_OVERLAP_HOURS_DEFAULT: '168',
      WEBHOOK_HISTORY_MAX_RANGE_DAYS: '62',
      WEBHOOK_REPLAY_MAX_RANGE_HOURS: '168',
      WEBHOOK_REPLAY_MAX_PER_DELIVERY: '50',
      WEBHOOK_REPLAY_REQUESTS_PER_HOUR: '100',
      WEBHOOK_TEST_REQUESTS_PER_MINUTE: '60',
    });
    expect(high.WEBHOOK_HISTORY_MAX_RANGE_DAYS).toBe(62);
    for (const [key, value] of [
      ['WEBHOOK_MAX_SUBSCRIPTIONS_PER_ORG', '0'],
      ['WEBHOOK_MAX_SUBSCRIPTIONS_PER_ORG', '101'],
      ['WEBHOOK_SECRET_OVERLAP_HOURS_DEFAULT', '169'],
      ['WEBHOOK_HISTORY_MAX_RANGE_DAYS', '63'],
      ['WEBHOOK_REPLAY_MAX_RANGE_HOURS', '0'],
      ['WEBHOOK_REPLAY_MAX_RANGE_HOURS', '169'],
      ['WEBHOOK_REPLAY_MAX_PER_DELIVERY', '51'],
      ['WEBHOOK_REPLAY_REQUESTS_PER_HOUR', '101'],
      ['WEBHOOK_TEST_REQUESTS_PER_MINUTE', '61'],
      ['WEBHOOK_ALLOW_HTTP', 'yes'],
    ] as const) {
      expect(rejection({ ...valid, [key]: value }), `${key}=${value}`).toContain(key);
    }
  });
});

describe('loadApiConfig: admin portal trusted forwarder (step 7.1 §3.5, ADR-0060)', () => {
  it('is off by default and when empty', () => {
    expect(loadApiConfig(valid).API_TRUSTED_FORWARDER_TOKEN).toBeUndefined();
    expect(
      loadApiConfig({ ...valid, API_TRUSTED_FORWARDER_TOKEN: '' }).API_TRUSTED_FORWARDER_TOKEN,
    ).toBeUndefined();
  });

  it('accepts 32 to 256 characters and names the key, never the value, otherwise', () => {
    for (const length of [32, 48, 256]) {
      const token = 'a'.repeat(length);
      expect(
        loadApiConfig({ ...valid, API_TRUSTED_FORWARDER_TOKEN: token }).API_TRUSTED_FORWARDER_TOKEN,
      ).toBe(token);
    }
    for (const bad of ['short-forwarder-MARKER', `MARKER${'b'.repeat(251)}`]) {
      const message = rejection({ ...valid, API_TRUSTED_FORWARDER_TOKEN: bad });
      expect(message).toContain('API_TRUSTED_FORWARDER_TOKEN');
      expect(message).not.toContain('MARKER');
    }
  });

  it('reads API_TRUSTED_FORWARDER_TOKEN from API_TRUSTED_FORWARDER_TOKEN_FILE', () => {
    const dir = mkdtempSync(join(tmpdir(), 'api-forwarder-token-'));
    const file = join(dir, 'token');
    const token = randomBytes(24).toString('hex');
    writeFileSync(file, `${token}\n`);
    try {
      expect(
        loadApiConfig({ ...valid, API_TRUSTED_FORWARDER_TOKEN_FILE: file })
          .API_TRUSTED_FORWARDER_TOKEN,
      ).toBe(token);
      // An explicit value wins over the file (the shared `_FILE` rule).
      const explicit = 'c'.repeat(40);
      expect(
        loadApiConfig({
          ...valid,
          API_TRUSTED_FORWARDER_TOKEN: explicit,
          API_TRUSTED_FORWARDER_TOKEN_FILE: file,
        }).API_TRUSTED_FORWARDER_TOKEN,
      ).toBe(explicit);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('loadApiConfig: email explorer and details (step 7.2 §2 E16)', () => {
  it('defaults the search cap, the search timeout, the saved views per user and the reveal limit', () => {
    expect(loadApiConfig(valid)).toMatchObject({
      API_MESSAGES_SEARCH_MAX_MATCHES: 5000,
      API_MESSAGES_SEARCH_TIMEOUT_MS: 5000,
      SAVED_VIEWS_MAX_PER_USER: 50,
      API_MESSAGES_REVEAL_PER_MINUTE: 30,
    });
  });

  it('accepts the bounds', () => {
    for (const [key, value] of [
      ['API_MESSAGES_SEARCH_MAX_MATCHES', '500'],
      ['API_MESSAGES_SEARCH_MAX_MATCHES', '50000'],
      ['API_MESSAGES_SEARCH_TIMEOUT_MS', '1000'],
      ['API_MESSAGES_SEARCH_TIMEOUT_MS', '30000'],
      ['SAVED_VIEWS_MAX_PER_USER', '1'],
      ['SAVED_VIEWS_MAX_PER_USER', '200'],
      ['API_MESSAGES_REVEAL_PER_MINUTE', '1'],
      ['API_MESSAGES_REVEAL_PER_MINUTE', '600'],
    ] as const) {
      expect(loadApiConfig({ ...valid, [key]: value })[key], `${key}=${value}`).toBe(Number(value));
    }
  });

  it.each([
    ['API_MESSAGES_SEARCH_MAX_MATCHES', '499'],
    ['API_MESSAGES_SEARCH_MAX_MATCHES', '50001'],
    ['API_MESSAGES_SEARCH_MAX_MATCHES', 'many'],
    ['API_MESSAGES_SEARCH_TIMEOUT_MS', '999'],
    ['API_MESSAGES_SEARCH_TIMEOUT_MS', '30001'],
    ['SAVED_VIEWS_MAX_PER_USER', '0'],
    ['SAVED_VIEWS_MAX_PER_USER', '201'],
    ['SAVED_VIEWS_MAX_PER_USER', '1.5'],
    ['API_MESSAGES_REVEAL_PER_MINUTE', '0'],
    ['API_MESSAGES_REVEAL_PER_MINUTE', '601'],
    ['API_MESSAGES_REVEAL_PER_MINUTE', 'lots'],
  ])('refuses %s=%s naming the key', (key, value) => {
    expect(rejection({ ...valid, [key]: value })).toContain(key);
  });

  describe('archive keys (step 8.1 §4.8)', () => {
    it('parses the archive defaults and leaves search optional', () => {
      const cfg = loadApiConfig(valid);
      expect(cfg.ARCHIVE_SEARCH_URL).toBeUndefined();
      expect(cfg).toMatchObject({
        ARCHIVE_ROOT_KEY_ID: 'r1',
        ARCHIVE_DOWNLOAD_TOKEN_TTL_SECONDS: 60,
        ARCHIVE_DOWNLOAD_GRANTS_PER_HOUR: 20,
        ARCHIVE_SEARCH_MAX_RANGE_DAYS: 366,
        ARCHIVE_CASE_SEARCH_MAX_RANGE_DAYS: 3650,
        ARCHIVE_REVIEW_MAX_ITEMS: 500,
        ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY_ID: 'es1',
        ARCHIVE_OBJECT_LOCK: 'auto',
      });
    });

    it('refuses a missing download token key, a bad signing public key and bad bounds', () => {
      expect(rejection({ ...valid, ARCHIVE_DOWNLOAD_TOKEN_KEY: undefined })).toContain(
        'ARCHIVE_DOWNLOAD_TOKEN_KEY',
      );
      const bad = rejection({ ...valid, ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY: 'EXAMPLE-NOT-A-KEY' });
      expect(bad).toContain('ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY');
      expect(bad).not.toContain('EXAMPLE-NOT-A-KEY');
      expect(rejection({ ...valid, ARCHIVE_DOWNLOAD_TOKEN_TTL_SECONDS: '5' })).toContain(
        'ARCHIVE_DOWNLOAD_TOKEN_TTL_SECONDS',
      );
      expect(rejection({ ...valid, ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY_ID: 'Bad' })).toContain(
        'ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY_ID',
      );
      expect(
        rejection({
          ...valid,
          ARCHIVE_EXPORT_SIGNING_PREVIOUS_PUBLIC_KEYS: `es1:${TEST_DOMAIN_ENV.ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY}`,
        }),
      ).toContain('ARCHIVE_EXPORT_SIGNING_PREVIOUS_PUBLIC_KEYS');
    });

    it('refuses the day-length test seam outside local/ci and credentials in the search URL', () => {
      expect(
        rejection({ ...valid, APP_ENV: 'production', ARCHIVE_TEST_DAY_SECONDS: '5' }),
      ).toContain('ARCHIVE_TEST_DAY_SECONDS');
      expect(
        rejection({ ...valid, ARCHIVE_SEARCH_URL: 'http://u:p@search.example:9200' }),
      ).toContain('ARCHIVE_SEARCH_URL');
      expect(
        rejection({ ...valid, ARCHIVE_ROOT_KEY_PREVIOUS: TEST_DOMAIN_ENV.ARCHIVE_ROOT_KEY }),
      ).toContain('ARCHIVE_ROOT_KEY_PREVIOUS');
    });
  });

  describe('account takeover keys (step 8.4 §4.2)', () => {
    it('parses the ATO defaults', () => {
      expect(loadApiConfig(valid)).toMatchObject({
        API_ATO_OVERVIEW_CACHE_SECONDS: 60,
        API_ATO_REPORT_MAX_ITEMS: 500,
        ATO_APPROVAL_TTL_HOURS: 24,
        ATO_AUTOMATED_RESPONSES_ENABLED: true,
        ATO_MAX_AUTOMATED_RESPONSES_PER_ORG_PER_HOUR: 10,
        ATO_MAX_ACTIVE_RESTRICTIONS_PER_ORG: 500,
      });
      expect(
        loadApiConfig({
          ...valid,
          API_ATO_OVERVIEW_CACHE_SECONDS: '5',
          API_ATO_REPORT_MAX_ITEMS: '5000',
          ATO_APPROVAL_TTL_HOURS: '168',
          ATO_AUTOMATED_RESPONSES_ENABLED: 'false',
          ATO_MAX_AUTOMATED_RESPONSES_PER_ORG_PER_HOUR: '0',
          ATO_MAX_ACTIVE_RESTRICTIONS_PER_ORG: '1',
        }),
      ).toMatchObject({
        API_ATO_OVERVIEW_CACHE_SECONDS: 5,
        API_ATO_REPORT_MAX_ITEMS: 5000,
        ATO_APPROVAL_TTL_HOURS: 168,
        ATO_AUTOMATED_RESPONSES_ENABLED: false,
        ATO_MAX_AUTOMATED_RESPONSES_PER_ORG_PER_HOUR: 0,
        ATO_MAX_ACTIVE_RESTRICTIONS_PER_ORG: 1,
      });
    });

    it.each([
      ['API_ATO_OVERVIEW_CACHE_SECONDS', '0'],
      ['API_ATO_OVERVIEW_CACHE_SECONDS', '3601'],
      ['API_ATO_REPORT_MAX_ITEMS', '0'],
      ['API_ATO_REPORT_MAX_ITEMS', '5001'],
      ['ATO_APPROVAL_TTL_HOURS', '0'],
      ['ATO_APPROVAL_TTL_HOURS', '169'],
      ['ATO_AUTOMATED_RESPONSES_ENABLED', 'yes'],
      ['ATO_MAX_AUTOMATED_RESPONSES_PER_ORG_PER_HOUR', '101'],
      ['ATO_MAX_ACTIVE_RESTRICTIONS_PER_ORG', '0'],
      ['ATO_MAX_ACTIVE_RESTRICTIONS_PER_ORG', '501'],
    ])('refuses %s=%s naming the key', (key, value) => {
      expect(rejection({ ...valid, [key]: value })).toContain(key);
    });
  });

  describe('identity-provider keys (step 8.5 §4.2)', () => {
    it('parses the defaults and explicit values', () => {
      expect(loadApiConfig(valid)).toMatchObject({
        ATO_IDP_MAX_INTEGRATIONS_PER_ORG: 5,
        ATO_IDP_BACKFILL_MAX_DAYS: 30,
        ATO_IDP_HEALTH_INTERVAL_SECONDS: 900,
      });
      expect(
        loadApiConfig({
          ...valid,
          ATO_IDP_MAX_INTEGRATIONS_PER_ORG: '1',
          ATO_IDP_BACKFILL_MAX_DAYS: '0',
          ATO_IDP_HEALTH_INTERVAL_SECONDS: '60',
        }),
      ).toMatchObject({
        ATO_IDP_MAX_INTEGRATIONS_PER_ORG: 1,
        ATO_IDP_BACKFILL_MAX_DAYS: 0,
        ATO_IDP_HEALTH_INTERVAL_SECONDS: 60,
      });
    });

    it.each([
      ['ATO_IDP_MAX_INTEGRATIONS_PER_ORG', '0'],
      ['ATO_IDP_MAX_INTEGRATIONS_PER_ORG', '51'],
      ['ATO_IDP_BACKFILL_MAX_DAYS', '-1'],
      ['ATO_IDP_BACKFILL_MAX_DAYS', '31'],
      ['ATO_IDP_HEALTH_INTERVAL_SECONDS', '59'],
      ['ATO_IDP_HEALTH_INTERVAL_SECONDS', '86401'],
    ])('refuses %s=%s naming the key', (key, value) => {
      expect(rejection({ ...valid, [key]: value })).toContain(key);
    });
  });
});

describe('loadApiConfig: Microsoft 365 and Google Workspace connections (step 8.2 §4.4)', () => {
  it('defaults the endpoints, lifetimes, bounds and probe domain', () => {
    const cfg = loadApiConfig(valid);
    expect(cfg).toMatchObject({
      PROVIDER_M365_LOGIN_URL: 'https://login.microsoftonline.com',
      PROVIDER_M365_GRAPH_URL: 'https://graph.microsoft.com',
      PROVIDER_GOOGLE_TOKEN_URL: 'https://oauth2.googleapis.com/token',
      PROVIDER_ALLOW_HTTP_ENDPOINTS: false,
      PROVIDER_CONSENT_STATE_TTL_SECONDS: 600,
      PROVIDER_IMPACT_TOKEN_TTL_SECONDS: 900,
      PROVIDER_MAX_CONNECTIONS_PER_ORG: 10,
      PROVIDER_MAX_DOMAINS_PER_CONNECTION: 500,
      PROVIDER_PROBE_DOMAIN: 'probe.mail-gateway.test',
      PROVIDER_PROBE_TTL_SECONDS: 86_400,
    });
    expect(cfg.PROVIDER_M365_MAILFLOW_APP_CLIENT_ID).toBeUndefined();
    expect(cfg.GATEWAY_RELAY_HOSTS).toEqual(['out1.mail-gateway.test', 'out2.mail-gateway.test']);
    expect(cfg.GATEWAY_EGRESS_NETWORKS).toEqual(['192.0.2.10/32', '2001:db8::10/128']);
  });

  it('requires the three keys and names them, never their values', () => {
    for (const key of [
      'PROVIDER_CREDENTIAL_ENCRYPTION_KEY',
      'PROVIDER_IMPACT_TOKEN_KEY',
      'PROVIDER_ROUTE_TOKEN_KEY',
    ]) {
      expect(rejection({ ...valid, [key]: undefined })).toContain(key);
      const short = 'ab'.repeat(16);
      const message = rejection({ ...valid, [key]: short });
      expect(message).toContain(key);
      expect(message).not.toContain(short);
    }
    expect(
      rejection({
        ...valid,
        PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS:
          TEST_DOMAIN_ENV.PROVIDER_CREDENTIAL_ENCRYPTION_KEY,
      }),
    ).toContain('PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS');
  });

  it('refuses http endpoints unless the local/ci test seam allows them', () => {
    const http = { PROVIDER_M365_LOGIN_URL: 'http://provider-fake:8480/m365/login' };
    expect(rejection({ ...valid, ...http })).toContain('PROVIDER_M365_LOGIN_URL');
    expect(
      loadApiConfig({ ...valid, ...http, PROVIDER_ALLOW_HTTP_ENDPOINTS: 'true', APP_ENV: 'local' })
        .PROVIDER_M365_LOGIN_URL,
    ).toBe('http://provider-fake:8480/m365/login');
    expect(
      rejection({ ...valid, PROVIDER_ALLOW_HTTP_ENDPOINTS: 'true', APP_ENV: 'production' }),
    ).toContain('PROVIDER_ALLOW_HTTP_ENDPOINTS');
  });

  it('validates the client ids, the gateway values and the probe domain', () => {
    expect(rejection({ ...valid, PROVIDER_M365_MAILFLOW_APP_CLIENT_ID: 'not-a-guid' })).toContain(
      'PROVIDER_M365_MAILFLOW_APP_CLIENT_ID',
    );
    expect(rejection({ ...valid, PROVIDER_GOOGLE_MAILFLOW_SA_CLIENT_ID: 'abc' })).toContain(
      'PROVIDER_GOOGLE_MAILFLOW_SA_CLIENT_ID',
    );
    expect(rejection({ ...valid, GATEWAY_EGRESS_NETWORKS: '192.0.2.10/33' })).toContain(
      'GATEWAY_EGRESS_NETWORKS',
    );
    expect(rejection({ ...valid, GATEWAY_RELAY_HOSTS: 'bad host' })).toContain(
      'GATEWAY_RELAY_HOSTS',
    );
    expect(rejection({ ...valid, PROVIDER_PROBE_DOMAIN: 'localhost' })).toContain(
      'PROVIDER_PROBE_DOMAIN',
    );
    expect(rejection({ ...valid, GATEWAY_RELAY_TLS_NAME: undefined })).toContain(
      'GATEWAY_RELAY_TLS_NAME',
    );
  });
});

describe('loadApiConfig: journal intake (step 8.6 §4.4)', () => {
  it('reads the intake domain and defaults the limits', () => {
    const cfg = loadApiConfig(valid);
    expect(cfg).toMatchObject({
      JOURNAL_INTAKE_DOMAIN: 'journal.gateway.test',
      JOURNAL_INTAKE_MAX_MESSAGE_BYTES: 52_428_800,
      JOURNAL_INTAKE_ROTATION_OVERLAP_DAYS: 7,
      JOURNAL_INTAKE_MAX_SOURCES_PER_ORG: 20,
    });
  });

  it('turns intake off with an empty domain (no secret needed)', () => {
    const cfg = loadApiConfig({
      ...valid,
      JOURNAL_INTAKE_DOMAIN: '',
      JOURNAL_INTAKE_ADDRESS_SECRET: '',
    });
    expect(cfg.JOURNAL_INTAKE_DOMAIN).toBeUndefined();
    expect(cfg.JOURNAL_INTAKE_ADDRESS_SECRET).toBeUndefined();
  });

  it('requires the address secret with the domain and never echoes it', () => {
    expect(rejection({ ...valid, JOURNAL_INTAKE_ADDRESS_SECRET: undefined })).toContain(
      'JOURNAL_INTAKE_ADDRESS_SECRET',
    );
    const short = 'cd'.repeat(16);
    const message = rejection({ ...valid, JOURNAL_INTAKE_ADDRESS_SECRET: short });
    expect(message).toContain('JOURNAL_INTAKE_ADDRESS_SECRET');
    expect(message).not.toContain(short);
  });

  it.each([
    ['JOURNAL_INTAKE_DOMAIN', 'localhost'],
    ['JOURNAL_INTAKE_MAX_MESSAGE_BYTES', '10'],
    ['JOURNAL_INTAKE_ROTATION_OVERLAP_DAYS', '91'],
    ['JOURNAL_INTAKE_MAX_SOURCES_PER_ORG', '0'],
  ])('refuses %s=%s naming the key', (key, value) => {
    expect(rejection({ ...valid, [key]: value })).toContain(key);
  });
});

describe('loadApiConfig: AI assistant (step AI-1 D6, D11)', () => {
  // Synthetic, deliberately not secret-shaped placeholder credentials.
  const KEY = 'placeholder-assistant-credential-MARKER';

  it('is off by default with the fake provider and the documented defaults', () => {
    const cfg = loadApiConfig(valid);
    expect(cfg).toMatchObject({
      ASSISTANT_ENABLED: false,
      ASSISTANT_PROVIDER: 'fake',
      ASSISTANT_MODEL: 'claude-opus-5-5',
      ASSISTANT_EFFORT: 'low',
      ASSISTANT_REFUSAL_FALLBACK: 'default',
      ASSISTANT_OPENAI_BASE_URL: 'https://api.openai.com/v1',
      ASSISTANT_AZURE_OPENAI_API_VERSION: '2024-10-21',
      ASSISTANT_TIMEOUT_MS: 30_000,
      ASSISTANT_TURN_DEADLINE_MS: 90_000,
      ASSISTANT_MAX_OUTPUT_TOKENS: 4096,
      ASSISTANT_MAX_TOOL_ROUNDS: 6,
      ASSISTANT_MAX_TOOL_CALLS_PER_TURN: 12,
      ASSISTANT_TOOL_TIMEOUT_MS: 15_000,
      ASSISTANT_TOOL_RESULT_MAX_BYTES: 12_288,
      ASSISTANT_TOOL_RESULT_MAX_ROWS: 25,
      ASSISTANT_CONTEXT_MAX_TOKENS: 60_000,
      ASSISTANT_USER_MESSAGE_MAX_CHARS: 4000,
      ASSISTANT_TURNS_PER_USER_PER_MINUTE: 6,
      ASSISTANT_MAX_CONCURRENT_TURNS: 20,
      ASSISTANT_TENANT_DAILY_TOKENS_DEFAULT: 1_000_000,
      ASSISTANT_TENANT_DAILY_TOKENS_MAX: 5_000_000,
      ASSISTANT_PLATFORM_DAILY_TOKENS: 0,
      ASSISTANT_RETENTION_DEFAULT_DAYS: 30,
      ASSISTANT_EXECUTION_RETENTION_DAYS: 400,
      ASSISTANT_MAX_CONVERSATIONS_PER_USER: 500,
      ASSISTANT_BACKGROUND_JOBS_ENABLED: true,
      ASSISTANT_BREAKER_THRESHOLD: 5,
      ASSISTANT_BREAKER_RESET_MS: 60_000,
      ASSISTANT_CONFIRMATION_TTL_SECONDS: 300,
      ASSISTANT_MAX_PENDING_CONFIRMATIONS: 5,
      ASSISTANT_REAUTH_WINDOW_SECONDS: 300,
      // Step AI-R §4.2.
      ASSISTANT_REPORTS_ENABLED: true,
      ASSISTANT_REPORT_EMAIL_ENABLED: true,
      ASSISTANT_REPORTS_PER_USER_PER_DAY: 30,
      ASSISTANT_REPORT_EMAILS_PER_USER_PER_DAY: 10,
      ASSISTANT_REPORT_EMAILS_PER_TENANT_PER_DAY: 50,
      ASSISTANT_REPORT_MAX_HTML_BYTES: 524_288,
    });
    for (const key of [
      'ASSISTANT_ANTHROPIC_API_KEY',
      'ASSISTANT_ANTHROPIC_BASE_URL',
      'ASSISTANT_OPENAI_API_KEY',
      'ASSISTANT_AZURE_OPENAI_ENDPOINT',
      'ASSISTANT_AZURE_OPENAI_API_KEY',
      'ASSISTANT_AZURE_OPENAI_DEPLOYMENT',
      'ASSISTANT_LOOPBACK_URL',
      'ASSISTANT_MODEL_PRICES',
    ] as const) {
      expect(cfg[key], key).toBeUndefined();
    }
  });

  it('treats the empty keys of .env.example as unset (enabled with the fake provider locally)', () => {
    const cfg = loadApiConfig({
      ...valid,
      ASSISTANT_ENABLED: 'true',
      ASSISTANT_PROVIDER: 'fake',
      ASSISTANT_ANTHROPIC_API_KEY: '',
      ASSISTANT_ANTHROPIC_BASE_URL: '',
      ASSISTANT_OPENAI_API_KEY: '',
      ASSISTANT_AZURE_OPENAI_ENDPOINT: '',
      ASSISTANT_AZURE_OPENAI_API_KEY: '',
      ASSISTANT_AZURE_OPENAI_DEPLOYMENT: '',
      ASSISTANT_LOOPBACK_URL: '',
      ASSISTANT_MODEL_PRICES: '',
    });
    expect(cfg.ASSISTANT_ENABLED).toBe(true);
    expect(cfg.ASSISTANT_PROVIDER).toBe('fake');
    expect(cfg.ASSISTANT_LOOPBACK_URL).toBeUndefined();
  });

  it('refuses the fake provider when NODE_ENV=production and the assistant is enabled', () => {
    const message = rejection({
      ...valid,
      NODE_ENV: 'production',
      ASSISTANT_ENABLED: 'true',
      ASSISTANT_PROVIDER: 'fake',
    });
    expect(message).toContain('ASSISTANT_PROVIDER');
    expect(message).toContain('NODE_ENV=production');
    // Off (the default): a production deployment needs no provider configuration at all.
    expect(loadApiConfig({ ...valid, NODE_ENV: 'production' }).ASSISTANT_PROVIDER).toBe('fake');
    expect(
      loadApiConfig({
        ...valid,
        NODE_ENV: 'production',
        ASSISTANT_ENABLED: 'true',
        ASSISTANT_PROVIDER: 'anthropic',
        ASSISTANT_ANTHROPIC_API_KEY: KEY,
      }).ASSISTANT_PROVIDER,
    ).toBe('anthropic');
  });

  it.each([
    ['anthropic', {}, ['ASSISTANT_ANTHROPIC_API_KEY']],
    ['openai', {}, ['ASSISTANT_OPENAI_API_KEY']],
    [
      'azure_openai',
      {},
      [
        'ASSISTANT_AZURE_OPENAI_ENDPOINT',
        'ASSISTANT_AZURE_OPENAI_API_KEY',
        'ASSISTANT_AZURE_OPENAI_DEPLOYMENT',
      ],
    ],
    [
      'azure_openai',
      {
        ASSISTANT_AZURE_OPENAI_ENDPOINT: 'https://example-resource.openai.azure.test',
        ASSISTANT_AZURE_OPENAI_API_KEY: KEY,
      },
      ['ASSISTANT_AZURE_OPENAI_DEPLOYMENT'],
    ],
  ] as const)(
    'requires the credentials of provider %s when enabled, naming the keys',
    (provider, extra, keys) => {
      const env = { ...valid, ASSISTANT_ENABLED: 'true', ASSISTANT_PROVIDER: provider, ...extra };
      const message = rejection(env);
      for (const key of keys) expect(message).toContain(key);
      expect(message).not.toContain('MARKER');
      // Disabled: the provider may stay unconfigured (no request is ever made).
      expect(loadApiConfig({ ...env, ASSISTANT_ENABLED: 'false' }).ASSISTANT_PROVIDER).toBe(
        provider,
      );
    },
  );

  it('accepts each provider with its credentials', () => {
    expect(
      loadApiConfig({
        ...valid,
        ASSISTANT_ENABLED: 'true',
        ASSISTANT_PROVIDER: 'anthropic',
        ASSISTANT_ANTHROPIC_API_KEY: KEY,
        ASSISTANT_ANTHROPIC_BASE_URL: 'https://llm-proxy.example.test',
        ASSISTANT_MODEL: 'claude-sonnet-5-5',
        ASSISTANT_EFFORT: 'medium',
        ASSISTANT_REFUSAL_FALLBACK: 'off',
      }),
    ).toMatchObject({
      ASSISTANT_ANTHROPIC_API_KEY: KEY,
      ASSISTANT_MODEL: 'claude-sonnet-5-5',
      ASSISTANT_EFFORT: 'medium',
      ASSISTANT_REFUSAL_FALLBACK: 'off',
    });
    expect(
      loadApiConfig({
        ...valid,
        ASSISTANT_ENABLED: 'true',
        ASSISTANT_PROVIDER: 'openai',
        ASSISTANT_OPENAI_API_KEY: KEY,
        ASSISTANT_MODEL: 'example-model-1',
      }).ASSISTANT_OPENAI_API_KEY,
    ).toBe(KEY);
    expect(
      loadApiConfig({
        ...valid,
        ASSISTANT_ENABLED: 'true',
        ASSISTANT_PROVIDER: 'azure_openai',
        ASSISTANT_AZURE_OPENAI_ENDPOINT: 'https://example-resource.openai.azure.test',
        ASSISTANT_AZURE_OPENAI_API_KEY: KEY,
        ASSISTANT_AZURE_OPENAI_DEPLOYMENT: 'chat-prod',
        ASSISTANT_AZURE_OPENAI_API_VERSION: '2025-01-01-preview',
      }),
    ).toMatchObject({
      ASSISTANT_AZURE_OPENAI_DEPLOYMENT: 'chat-prod',
      ASSISTANT_AZURE_OPENAI_API_VERSION: '2025-01-01-preview',
    });
  });

  it('reads the provider credentials from <KEY>_FILE', () => {
    const dir = mkdtempSync(join(tmpdir(), 'api-assistant-key-'));
    const file = join(dir, 'key');
    const fromFile = `placeholder-${randomBytes(12).toString('hex')}`;
    writeFileSync(file, `${fromFile}\n`);
    try {
      for (const [provider, key] of [
        ['anthropic', 'ASSISTANT_ANTHROPIC_API_KEY'],
        ['openai', 'ASSISTANT_OPENAI_API_KEY'],
      ] as const) {
        const cfg = loadApiConfig({
          ...valid,
          ASSISTANT_ENABLED: 'true',
          ASSISTANT_PROVIDER: provider,
          [`${key}_FILE`]: file,
        });
        expect(cfg[key]).toBe(fromFile);
      }
      expect(
        loadApiConfig({
          ...valid,
          ASSISTANT_ENABLED: 'true',
          ASSISTANT_PROVIDER: 'azure_openai',
          ASSISTANT_AZURE_OPENAI_ENDPOINT: 'https://example-resource.openai.azure.test',
          ASSISTANT_AZURE_OPENAI_DEPLOYMENT: 'chat-prod',
          ASSISTANT_AZURE_OPENAI_API_KEY_FILE: file,
        }).ASSISTANT_AZURE_OPENAI_API_KEY,
      ).toBe(fromFile);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('names a malformed credential, never its value', () => {
    for (const bad of ['short', 'has MARKER spaces in it']) {
      const message = rejection({ ...valid, ASSISTANT_OPENAI_API_KEY: bad });
      expect(message).toContain('ASSISTANT_OPENAI_API_KEY');
      expect(message).not.toContain(bad);
    }
  });

  it('allows http provider endpoints only in APP_ENV local/ci', () => {
    const env = {
      ...valid,
      ASSISTANT_OPENAI_BASE_URL: 'http://llm-fake.test:8080/v1',
      ASSISTANT_ANTHROPIC_BASE_URL: 'http://llm-fake.test:8081',
      ASSISTANT_AZURE_OPENAI_ENDPOINT: 'http://llm-fake.test:8082',
    };
    expect(loadApiConfig({ ...env, APP_ENV: 'ci' }).ASSISTANT_OPENAI_BASE_URL).toBe(
      'http://llm-fake.test:8080/v1',
    );
    const message = rejection({ ...env, APP_ENV: 'staging' });
    for (const key of [
      'ASSISTANT_OPENAI_BASE_URL',
      'ASSISTANT_ANTHROPIC_BASE_URL',
      'ASSISTANT_AZURE_OPENAI_ENDPOINT',
    ]) {
      expect(message).toContain(key);
    }
    expect(rejection({ ...valid, ASSISTANT_OPENAI_BASE_URL: 'ftp://llm.test' })).toContain(
      'ASSISTANT_OPENAI_BASE_URL',
    );
    // The loopback URL is internal: http is fine everywhere.
    expect(
      loadApiConfig({
        ...valid,
        APP_ENV: 'staging',
        PORTAL_PUBLIC_URL: 'https://admin.example.test',
        ASSISTANT_LOOPBACK_URL: 'http://api:3000',
      }).ASSISTANT_LOOPBACK_URL,
    ).toBe('http://api:3000');
    expect(rejection({ ...valid, ASSISTANT_LOOPBACK_URL: 'not a url' })).toContain(
      'ASSISTANT_LOOPBACK_URL',
    );
  });

  it('requires the tenant default budget <= the tenant maximum', () => {
    expect(
      rejection({
        ...valid,
        ASSISTANT_TENANT_DAILY_TOKENS_DEFAULT: '6000000',
        ASSISTANT_TENANT_DAILY_TOKENS_MAX: '5000000',
      }),
    ).toContain('ASSISTANT_TENANT_DAILY_TOKENS_DEFAULT');
    expect(
      loadApiConfig({
        ...valid,
        ASSISTANT_TENANT_DAILY_TOKENS_DEFAULT: '5000000',
        ASSISTANT_TENANT_DAILY_TOKENS_MAX: '5000000',
      }).ASSISTANT_TENANT_DAILY_TOKENS_DEFAULT,
    ).toBe(5_000_000);
  });

  it('requires the provider and tool timeouts below the turn deadline', () => {
    const message = rejection({
      ...valid,
      ASSISTANT_TURN_DEADLINE_MS: '20000',
      ASSISTANT_TIMEOUT_MS: '20000',
      ASSISTANT_TOOL_TIMEOUT_MS: '25000',
    });
    expect(message).toContain('ASSISTANT_TIMEOUT_MS');
    expect(message).toContain('ASSISTANT_TOOL_TIMEOUT_MS');
  });

  it('parses and validates ASSISTANT_MODEL_PRICES, never echoing the value', () => {
    const prices = loadApiConfig({
      ...valid,
      ASSISTANT_MODEL_PRICES: JSON.stringify({
        'example-model-1': { inputPerMTokMicros: 1_250_000, outputPerMTokMicros: 10_000_000 },
        'claude-opus-5-5': {
          inputPerMTokMicros: 4_000_000,
          outputPerMTokMicros: 20_000_000,
          cacheReadPerMTokMicros: 200_000,
          cacheWritePerMTokMicros: 5_000_000,
        },
      }),
    }).ASSISTANT_MODEL_PRICES;
    expect(prices?.['example-model-1']).toEqual({
      inputPerMTokMicros: 1_250_000,
      outputPerMTokMicros: 10_000_000,
    });
    expect(prices?.['claude-opus-5-5']?.cacheReadPerMTokMicros).toBe(200_000);
    for (const bad of [
      '{MARKER',
      '["MARKER"]',
      JSON.stringify({ 'bad model MARKER': { inputPerMTokMicros: 1, outputPerMTokMicros: 1 } }),
      JSON.stringify({ m: { inputPerMTokMicros: 1 } }),
      JSON.stringify({ m: { inputPerMTokMicros: -1, outputPerMTokMicros: 1 } }),
      JSON.stringify({ m: { inputPerMTokMicros: 1.5, outputPerMTokMicros: 1 } }),
      JSON.stringify({ m: { inputPerMTokMicros: 1, outputPerMTokMicros: 1, MARKER: 1 } }),
    ]) {
      const message = rejection({ ...valid, ASSISTANT_MODEL_PRICES: bad });
      expect(message, bad).toContain('ASSISTANT_MODEL_PRICES');
      expect(message, bad).not.toContain('MARKER');
    }
  });

  it('accepts every bounded key at its bounds', () => {
    const bounds: Record<string, [number, number]> = {
      ASSISTANT_TIMEOUT_MS: [5000, 120_000],
      ASSISTANT_TURN_DEADLINE_MS: [10_000, 300_000],
      ASSISTANT_MAX_OUTPUT_TOKENS: [256, 16_000],
      ASSISTANT_MAX_TOOL_ROUNDS: [1, 10],
      ASSISTANT_MAX_TOOL_CALLS_PER_TURN: [1, 30],
      ASSISTANT_TOOL_TIMEOUT_MS: [1000, 60_000],
      ASSISTANT_TOOL_RESULT_MAX_BYTES: [2048, 65_536],
      ASSISTANT_TOOL_RESULT_MAX_ROWS: [1, 100],
      ASSISTANT_CONTEXT_MAX_TOKENS: [8000, 400_000],
      ASSISTANT_USER_MESSAGE_MAX_CHARS: [100, 16_000],
      ASSISTANT_TURNS_PER_USER_PER_MINUTE: [1, 120],
      ASSISTANT_MAX_CONCURRENT_TURNS: [1, 500],
      ASSISTANT_RETENTION_DEFAULT_DAYS: [1, 365],
      ASSISTANT_EXECUTION_RETENTION_DAYS: [30, 3650],
      ASSISTANT_MAX_CONVERSATIONS_PER_USER: [1, 10_000],
      ASSISTANT_CONFIRMATION_TTL_SECONDS: [60, 900],
      ASSISTANT_MAX_PENDING_CONFIRMATIONS: [1, 20],
      ASSISTANT_REAUTH_WINDOW_SECONDS: [0, 1800],
      ASSISTANT_BREAKER_THRESHOLD: [1, 100],
      ASSISTANT_BREAKER_RESET_MS: [1000, 3_600_000],
      // Step AI-R §4.2.
      ASSISTANT_REPORTS_PER_USER_PER_DAY: [1, 1000],
      ASSISTANT_REPORT_EMAILS_PER_USER_PER_DAY: [1, 500],
      ASSISTANT_REPORT_EMAILS_PER_TENANT_PER_DAY: [1, 10_000],
      ASSISTANT_REPORT_MAX_HTML_BYTES: [65_536, 2_097_152],
    };
    // The deadline must stay above both timeouts while the others move.
    const roomy = { ASSISTANT_TURN_DEADLINE_MS: '300000' };
    for (const [key, [min, max]] of Object.entries(bounds)) {
      const base = key === 'ASSISTANT_TURN_DEADLINE_MS' ? {} : roomy;
      const timeouts =
        key === 'ASSISTANT_TURN_DEADLINE_MS'
          ? { ASSISTANT_TIMEOUT_MS: '5000', ASSISTANT_TOOL_TIMEOUT_MS: '1000' }
          : {};
      for (const value of [min, max]) {
        const cfg = loadApiConfig({ ...valid, ...base, ...timeouts, [key]: String(value) });
        expect(cfg[key as keyof typeof cfg], `${key}=${value}`).toBe(value);
      }
      expect(rejection({ ...valid, ...base, ...timeouts, [key]: String(min - 1) })).toContain(key);
      expect(rejection({ ...valid, ...base, ...timeouts, [key]: String(max + 1) })).toContain(key);
    }
    expect(loadApiConfig({ ...valid, ASSISTANT_PLATFORM_DAILY_TOKENS: '0' })).toMatchObject({
      ASSISTANT_PLATFORM_DAILY_TOKENS: 0,
    });
    expect(rejection({ ...valid, ASSISTANT_PLATFORM_DAILY_TOKENS: '-1' })).toContain(
      'ASSISTANT_PLATFORM_DAILY_TOKENS',
    );
  });

  it('switches the report tools off with ASSISTANT_REPORTS_ENABLED / ASSISTANT_REPORT_EMAIL_ENABLED (step AI-R D1)', () => {
    expect(
      loadApiConfig({
        ...valid,
        ASSISTANT_REPORTS_ENABLED: 'false',
        ASSISTANT_REPORT_EMAIL_ENABLED: 'false',
      }),
    ).toMatchObject({ ASSISTANT_REPORTS_ENABLED: false, ASSISTANT_REPORT_EMAIL_ENABLED: false });
  });

  it.each([
    ['ASSISTANT_PROVIDER', 'gemini'],
    ['ASSISTANT_EFFORT', 'max'],
    ['ASSISTANT_REFUSAL_FALLBACK', 'none'],
    ['ASSISTANT_ENABLED', 'yes'],
    ['ASSISTANT_BACKGROUND_JOBS_ENABLED', 'maybe'],
    ['ASSISTANT_MODEL', 'model with spaces'],
    ['ASSISTANT_AZURE_OPENAI_DEPLOYMENT', 'bad/deployment'],
    ['ASSISTANT_AZURE_OPENAI_API_VERSION', 'latest'],
    ['ASSISTANT_REPORTS_ENABLED', 'sometimes'],
    ['ASSISTANT_REPORT_EMAIL_ENABLED', 'on-demand'],
    ['ASSISTANT_REPORT_MAX_HTML_BYTES', '512k'],
  ])('refuses %s=%s naming the key', (key, value) => {
    expect(rejection({ ...valid, [key]: value })).toContain(key);
  });
});

describe('loadApiConfig: AI assistant hardening (step AI-6 §4.3)', () => {
  // Synthetic, deliberately not secret-shaped placeholder credentials.
  const KEY = 'placeholder-assistant-credential-MARKER';
  const AMQP = 'amqp://eg-assistant:placeholder-MARKER@rabbitmq:5672/email-gateway';

  it('has the documented defaults (no fallback, tenant keys off, jobs on, consumer off)', () => {
    const cfg = loadApiConfig(valid);
    expect(cfg).toMatchObject({
      ASSISTANT_FALLBACK_PROVIDER: 'none',
      ASSISTANT_TENANT_KEYS_ENABLED: false,
      ASSISTANT_TENANT_KEY_PROVIDERS: ['anthropic', 'openai'],
      ASSISTANT_TENANT_KEY_MODELS: ['claude-opus-5-5', 'claude-sonnet-5-5'],
      ASSISTANT_TENANT_KEY_VALIDATION_TIMEOUT_MS: 10_000,
      ASSISTANT_PSEUDONYMS_MAX_PER_CONVERSATION: 5000,
      ASSISTANT_SEARCH_SCAN_MAX_MESSAGES: 20_000,
      ASSISTANT_SEARCH_TIMEOUT_MS: 3000,
      ASSISTANT_REPORT_JOBS_ENABLED: true,
      ASSISTANT_REPORT_SYNC_MAX_HOURS: 168,
      ASSISTANT_REPORT_JOB_TTL_SECONDS: 1800,
      ASSISTANT_REPORT_JOBS_CONSUMER: false,
      ASSISTANT_REPORT_JOB_CONCURRENCY: 2,
      ARCHIVE_EXPORT_TTL_HOURS: 168,
    });
    for (const key of [
      'ASSISTANT_FALLBACK_MODEL',
      'ASSISTANT_TENANT_KEY_ENCRYPTION_KEY',
      'ASSISTANT_TENANT_KEY_ENCRYPTION_KEY_PREVIOUS',
      'RABBITMQ_ASSISTANT_URL',
    ] as const) {
      expect(cfg[key], key).toBeUndefined();
    }
  });

  it('treats the empty keys of .env.example as unset', () => {
    const cfg = loadApiConfig({
      ...valid,
      ASSISTANT_FALLBACK_MODEL: '',
      ASSISTANT_TENANT_KEY_ENCRYPTION_KEY: '',
      ASSISTANT_TENANT_KEY_ENCRYPTION_KEY_PREVIOUS: '',
      RABBITMQ_ASSISTANT_URL: '',
    });
    expect(cfg.ASSISTANT_FALLBACK_MODEL).toBeUndefined();
    expect(cfg.RABBITMQ_ASSISTANT_URL).toBeUndefined();
  });

  it('accepts a secondary provider of another family, or of the same family with another model', () => {
    expect(
      loadApiConfig({
        ...valid,
        ASSISTANT_ENABLED: 'true',
        ASSISTANT_PROVIDER: 'anthropic',
        ASSISTANT_ANTHROPIC_API_KEY: KEY,
        ASSISTANT_FALLBACK_PROVIDER: 'openai',
        ASSISTANT_OPENAI_API_KEY: KEY,
        ASSISTANT_FALLBACK_MODEL: 'example-model-1',
      }),
    ).toMatchObject({
      ASSISTANT_FALLBACK_PROVIDER: 'openai',
      ASSISTANT_FALLBACK_MODEL: 'example-model-1',
    });
    expect(
      loadApiConfig({
        ...valid,
        ASSISTANT_ENABLED: 'true',
        ASSISTANT_PROVIDER: 'anthropic',
        ASSISTANT_ANTHROPIC_API_KEY: KEY,
        ASSISTANT_FALLBACK_PROVIDER: 'anthropic',
        ASSISTANT_FALLBACK_MODEL: 'claude-sonnet-5-5',
      }).ASSISTANT_FALLBACK_MODEL,
    ).toBe('claude-sonnet-5-5');
    // fake as the secondary is fine outside production (tests, local development).
    expect(
      loadApiConfig({
        ...valid,
        ASSISTANT_ENABLED: 'true',
        ASSISTANT_PROVIDER: 'anthropic',
        ASSISTANT_ANTHROPIC_API_KEY: KEY,
        ASSISTANT_FALLBACK_PROVIDER: 'fake',
      }).ASSISTANT_FALLBACK_PROVIDER,
    ).toBe('fake');
    expect(
      loadApiConfig({
        ...valid,
        ASSISTANT_ENABLED: 'true',
        ASSISTANT_FALLBACK_PROVIDER: 'fake',
        ASSISTANT_FALLBACK_MODEL: 'fake-secondary',
      }).ASSISTANT_FALLBACK_MODEL,
    ).toBe('fake-secondary');
  });

  it('refuses a secondary equal to the primary unless the model differs', () => {
    for (const extra of [{}, { ASSISTANT_FALLBACK_MODEL: 'claude-opus-5-5' }]) {
      const message = rejection({
        ...valid,
        ASSISTANT_PROVIDER: 'anthropic',
        ASSISTANT_MODEL: 'claude-opus-5-5',
        ASSISTANT_FALLBACK_PROVIDER: 'anthropic',
        ...extra,
      });
      expect(message).toContain('ASSISTANT_FALLBACK_PROVIDER');
    }
    expect(
      rejection({ ...valid, ASSISTANT_PROVIDER: 'fake', ASSISTANT_FALLBACK_PROVIDER: 'fake' }),
    ).toContain('ASSISTANT_FALLBACK_PROVIDER');
  });

  it('requires ASSISTANT_FALLBACK_MODEL for an anthropic or openai secondary', () => {
    for (const provider of ['anthropic', 'openai']) {
      expect(rejection({ ...valid, ASSISTANT_FALLBACK_PROVIDER: provider })).toContain(
        'ASSISTANT_FALLBACK_MODEL',
      );
    }
    expect(
      rejection({
        ...valid,
        ASSISTANT_FALLBACK_PROVIDER: 'openai',
        ASSISTANT_FALLBACK_MODEL: 'model with spaces',
      }),
    ).toContain('ASSISTANT_FALLBACK_MODEL');
  });

  it('refuses a fake secondary in production while the assistant is enabled', () => {
    const env = {
      ...valid,
      NODE_ENV: 'production',
      ASSISTANT_PROVIDER: 'anthropic',
      ASSISTANT_ANTHROPIC_API_KEY: KEY,
      ASSISTANT_FALLBACK_PROVIDER: 'fake',
    };
    const message = rejection({ ...env, ASSISTANT_ENABLED: 'true' });
    expect(message).toContain('ASSISTANT_FALLBACK_PROVIDER');
    expect(message).toContain('NODE_ENV=production');
    expect(loadApiConfig(env).ASSISTANT_FALLBACK_PROVIDER).toBe('fake');
  });

  it.each([
    ['anthropic', ['ASSISTANT_ANTHROPIC_API_KEY']],
    ['openai', ['ASSISTANT_OPENAI_API_KEY']],
    [
      'azure_openai',
      [
        'ASSISTANT_AZURE_OPENAI_ENDPOINT',
        'ASSISTANT_AZURE_OPENAI_API_KEY',
        'ASSISTANT_AZURE_OPENAI_DEPLOYMENT',
      ],
    ],
  ] as const)(
    'requires the credentials of secondary provider %s when enabled',
    (provider, keys) => {
      const env = {
        ...valid,
        ASSISTANT_ENABLED: 'true',
        ASSISTANT_PROVIDER: 'fake',
        ASSISTANT_FALLBACK_PROVIDER: provider,
        ASSISTANT_FALLBACK_MODEL: 'example-model-1',
      };
      const message = rejection(env);
      for (const key of keys) expect(message).toContain(key);
      expect(message).not.toContain('MARKER');
      expect(
        loadApiConfig({ ...env, ASSISTANT_ENABLED: 'false' }).ASSISTANT_FALLBACK_PROVIDER,
      ).toBe(provider);
    },
  );

  it('requires the tenant-key encryption key when tenant keys are enabled, never echoing it', () => {
    expect(rejection({ ...valid, ASSISTANT_TENANT_KEYS_ENABLED: 'true' })).toContain(
      'ASSISTANT_TENANT_KEY_ENCRYPTION_KEY',
    );
    const key = hex64();
    expect(
      loadApiConfig({
        ...valid,
        ASSISTANT_TENANT_KEYS_ENABLED: 'true',
        ASSISTANT_TENANT_KEY_ENCRYPTION_KEY: key,
        ASSISTANT_TENANT_KEY_ENCRYPTION_KEY_PREVIOUS: hex64(),
      }),
    ).toMatchObject({
      ASSISTANT_TENANT_KEYS_ENABLED: true,
      ASSISTANT_TENANT_KEY_ENCRYPTION_KEY: key,
    });
    const short = 'ab'.repeat(16);
    const message = rejection({ ...valid, ASSISTANT_TENANT_KEY_ENCRYPTION_KEY: short });
    expect(message).toContain('ASSISTANT_TENANT_KEY_ENCRYPTION_KEY');
    expect(message).not.toContain(short);
    const same = rejection({
      ...valid,
      ASSISTANT_TENANT_KEY_ENCRYPTION_KEY: key,
      ASSISTANT_TENANT_KEY_ENCRYPTION_KEY_PREVIOUS: key.toUpperCase(),
    });
    expect(same).toContain('ASSISTANT_TENANT_KEY_ENCRYPTION_KEY_PREVIOUS');
    expect(same).not.toContain(key);
  });

  it('reads the tenant-key encryption keys and the RabbitMQ URL from <KEY>_FILE', () => {
    const dir = mkdtempSync(join(tmpdir(), 'api-assistant-ai6-'));
    const keyFile = join(dir, 'key');
    const previousFile = join(dir, 'previous');
    const urlFile = join(dir, 'url');
    const key = hex64();
    const previous = hex64();
    writeFileSync(keyFile, `${key}\n`);
    writeFileSync(previousFile, `${previous}\n`);
    writeFileSync(urlFile, `${AMQP}\n`);
    try {
      expect(
        loadApiConfig({
          ...valid,
          ASSISTANT_TENANT_KEYS_ENABLED: 'true',
          ASSISTANT_TENANT_KEY_ENCRYPTION_KEY_FILE: keyFile,
          ASSISTANT_TENANT_KEY_ENCRYPTION_KEY_PREVIOUS_FILE: previousFile,
          ASSISTANT_REPORT_JOBS_CONSUMER: 'true',
          RABBITMQ_ASSISTANT_URL_FILE: urlFile,
        }),
      ).toMatchObject({
        ASSISTANT_TENANT_KEY_ENCRYPTION_KEY: key,
        ASSISTANT_TENANT_KEY_ENCRYPTION_KEY_PREVIOUS: previous,
        RABBITMQ_ASSISTANT_URL: [AMQP],
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('parses the tenant-key provider and model lists', () => {
    expect(
      loadApiConfig({
        ...valid,
        ASSISTANT_TENANT_KEY_PROVIDERS: ' openai , openai ',
        ASSISTANT_TENANT_KEY_MODELS: 'claude-sonnet-5-5, example-model-1',
      }),
    ).toMatchObject({
      ASSISTANT_TENANT_KEY_PROVIDERS: ['openai'],
      ASSISTANT_TENANT_KEY_MODELS: ['claude-sonnet-5-5', 'example-model-1'],
    });
    for (const bad of ['azure_openai', 'anthropic,MARKER', ' , ']) {
      const message = rejection({ ...valid, ASSISTANT_TENANT_KEY_PROVIDERS: bad });
      expect(message, bad).toContain('ASSISTANT_TENANT_KEY_PROVIDERS');
      expect(message, bad).not.toContain('MARKER');
    }
    for (const bad of ['bad model MARKER', ',', 'x'.repeat(65)]) {
      const message = rejection({ ...valid, ASSISTANT_TENANT_KEY_MODELS: bad });
      expect(message, bad).toContain('ASSISTANT_TENANT_KEY_MODELS');
      expect(message, bad).not.toContain('MARKER');
    }
  });

  it('keeps the synchronous report window within REPORTS_MAX_RANGE_DAYS', () => {
    expect(
      rejection({ ...valid, REPORTS_MAX_RANGE_DAYS: '7', ASSISTANT_REPORT_SYNC_MAX_HOURS: '169' }),
    ).toContain('ASSISTANT_REPORT_SYNC_MAX_HOURS');
    expect(
      loadApiConfig({
        ...valid,
        REPORTS_MAX_RANGE_DAYS: '7',
        ASSISTANT_REPORT_SYNC_MAX_HOURS: '168',
      }).ASSISTANT_REPORT_SYNC_MAX_HOURS,
    ).toBe(168);
  });

  it('requires RABBITMQ_ASSISTANT_URL for the report job consumer, never echoing it', () => {
    expect(rejection({ ...valid, ASSISTANT_REPORT_JOBS_CONSUMER: 'true' })).toContain(
      'RABBITMQ_ASSISTANT_URL',
    );
    expect(
      loadApiConfig({
        ...valid,
        ASSISTANT_REPORT_JOBS_CONSUMER: 'true',
        RABBITMQ_ASSISTANT_URL: AMQP,
      }).RABBITMQ_ASSISTANT_URL,
    ).toEqual([AMQP]);
    const bad = 'http://eg-assistant:placeholder-MARKER@rabbitmq';
    const message = rejection({ ...valid, RABBITMQ_ASSISTANT_URL: bad });
    expect(message).toContain('RABBITMQ_ASSISTANT_URL');
    expect(message).not.toContain('MARKER');
  });

  it('accepts every bounded key at its bounds', () => {
    const bounds: Record<string, [number, number]> = {
      ASSISTANT_TENANT_KEY_VALIDATION_TIMEOUT_MS: [1000, 30_000],
      ASSISTANT_PSEUDONYMS_MAX_PER_CONVERSATION: [100, 50_000],
      ASSISTANT_SEARCH_SCAN_MAX_MESSAGES: [1000, 200_000],
      ASSISTANT_SEARCH_TIMEOUT_MS: [500, 10_000],
      ASSISTANT_REPORT_SYNC_MAX_HOURS: [24, 744],
      ASSISTANT_REPORT_JOB_TTL_SECONDS: [300, 7200],
      ASSISTANT_REPORT_JOB_CONCURRENCY: [1, 8],
      ARCHIVE_EXPORT_TTL_HOURS: [1, 8760],
    };
    for (const [key, [min, max]] of Object.entries(bounds)) {
      for (const value of [min, max]) {
        const cfg = loadApiConfig({ ...valid, [key]: String(value) });
        expect(cfg[key as keyof typeof cfg], `${key}=${value}`).toBe(value);
      }
      expect(rejection({ ...valid, [key]: String(min - 1) })).toContain(key);
      expect(rejection({ ...valid, [key]: String(max + 1) })).toContain(key);
    }
  });

  it.each([
    ['ASSISTANT_FALLBACK_PROVIDER', 'gemini'],
    ['ASSISTANT_TENANT_KEYS_ENABLED', 'yes'],
    ['ASSISTANT_REPORT_JOBS_ENABLED', 'sometimes'],
    ['ASSISTANT_REPORT_JOBS_CONSUMER', 'maybe'],
    ['ARCHIVE_EXPORT_TTL_HOURS', 'a-week'],
  ])('refuses %s=%s naming the key', (key, value) => {
    expect(rejection({ ...valid, [key]: value })).toContain(key);
  });
});

describe('loadApiConfig: API-mode protection (step API-1 D16)', () => {
  it('defaults: 1200 callbacks per minute and IP, notify unavailable, no mailbox apps', () => {
    const cfg = loadApiConfig(valid);
    expect(cfg.API_MODE_NOTIFICATION_RATE_PER_MINUTE).toBe(1200);
    expect(cfg.API_MODE_GRAPH_NOTIFICATION_URL).toBeUndefined();
    expect(cfg.PROVIDER_M365_MAILBOX_APP_CLIENT_ID).toBeUndefined();
    expect(cfg.PROVIDER_GOOGLE_MAILBOX_SA_CLIENT_ID).toBeUndefined();
  });

  it('reads the notification URL (presence) and the mailbox-access client ids', () => {
    const cfg = loadApiConfig({
      ...valid,
      APP_ENV: 'local',
      API_MODE_NOTIFICATION_RATE_PER_MINUTE: '30',
      API_MODE_GRAPH_NOTIFICATION_URL: 'http://api:3000/api/v1/provider-notifications/graph',
      PROVIDER_M365_MAILBOX_APP_CLIENT_ID: '11111111-2222-3333-4444-555555555555',
      PROVIDER_GOOGLE_MAILBOX_SA_CLIENT_ID: '123456789012345678901',
    });
    expect(cfg.API_MODE_NOTIFICATION_RATE_PER_MINUTE).toBe(30);
    expect(cfg.API_MODE_GRAPH_NOTIFICATION_URL).toBe(
      'http://api:3000/api/v1/provider-notifications/graph',
    );
    expect(cfg.PROVIDER_M365_MAILBOX_APP_CLIENT_ID).toBe('11111111-2222-3333-4444-555555555555');
  });

  it('refuses an http notification URL outside local/ci and malformed client ids', () => {
    expect(
      rejection({
        ...valid,
        APP_ENV: 'production',
        API_MODE_GRAPH_NOTIFICATION_URL: 'http://api.example/api/v1/provider-notifications/graph',
      }),
    ).toMatch(/API_MODE_GRAPH_NOTIFICATION_URL/);
    expect(rejection({ ...valid, PROVIDER_M365_MAILBOX_APP_CLIENT_ID: 'not-a-guid' })).toMatch(
      /PROVIDER_M365_MAILBOX_APP_CLIENT_ID/,
    );
    expect(rejection({ ...valid, API_MODE_NOTIFICATION_RATE_PER_MINUTE: '0' })).toMatch(
      /API_MODE_NOTIFICATION_RATE_PER_MINUTE/,
    );
  });
});
