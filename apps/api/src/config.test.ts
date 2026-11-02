import { randomBytes } from 'node:crypto';
import { ConfigValidationError } from '@email-gateway/config';
import { describe, expect, it } from 'vitest';
import { loadApiConfig } from './config';

const hex64 = () => randomBytes(32).toString('hex');

const valid = {
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
