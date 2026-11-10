import { randomBytes } from 'node:crypto';
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
