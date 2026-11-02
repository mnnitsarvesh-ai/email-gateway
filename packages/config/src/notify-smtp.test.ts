import { describe, expect, it } from 'vitest';
import { ConfigValidationError, loadConfig } from './load-config';
import { isSenderAddress, notifySmtpConfigSchema } from './schemas';

const relay = {
  NOTIFY_SMTP_HOST: 'smtp.example.com',
  NOTIFY_SMTP_FROM: 'Gateway <no-reply@example.com>',
};

function issues(env: Record<string, string>): string {
  try {
    loadConfig(notifySmtpConfigSchema, env);
  } catch (err) {
    expect(err).toBeInstanceOf(ConfigValidationError);
    return (err as Error).message;
  }
  return expect.fail('expected ConfigValidationError');
}

describe('notifySmtpConfigSchema', () => {
  it('has no relay by default, with submission defaults (587, STARTTLS)', () => {
    expect(loadConfig(notifySmtpConfigSchema, {})).toEqual({
      APP_ENV: 'local',
      NOTIFY_SMTP_PORT: 587,
      NOTIFY_SMTP_SECURE: 'starttls',
    });
  });

  it('treats the empty keys of .env.example as unset', () => {
    const cfg = loadConfig(notifySmtpConfigSchema, {
      NOTIFY_SMTP_HOST: '',
      NOTIFY_SMTP_PORT: '587',
      NOTIFY_SMTP_SECURE: 'starttls',
      NOTIFY_SMTP_USER: '',
      NOTIFY_SMTP_PASSWORD: '',
      NOTIFY_SMTP_FROM: '',
    });
    expect(cfg.NOTIFY_SMTP_HOST).toBeUndefined();
  });

  it('parses an authenticated relay', () => {
    const cfg = loadConfig(notifySmtpConfigSchema, {
      ...relay,
      APP_ENV: 'production',
      NOTIFY_SMTP_PORT: '465',
      NOTIFY_SMTP_SECURE: 'tls',
      NOTIFY_SMTP_USER: 'mailer',
      NOTIFY_SMTP_PASSWORD: 'TopSecretRelayPassword',
    });
    expect(cfg).toMatchObject({ NOTIFY_SMTP_PORT: 465, NOTIFY_SMTP_SECURE: 'tls' });
  });

  it('requires a sender when a relay host is set', () => {
    expect(issues({ NOTIFY_SMTP_HOST: 'smtp.example.com' })).toContain('NOTIFY_SMTP_FROM');
  });

  it('requires user and password together, never echoing the password', () => {
    const message = issues({ ...relay, NOTIFY_SMTP_PASSWORD: 'TopSecretRelayPassword' });
    expect(message).toContain('NOTIFY_SMTP_USER');
    expect(message).not.toContain('TopSecretRelayPassword');
  });

  it.each(['local', 'ci'])('accepts plaintext SMTP when APP_ENV=%s', (appEnv) => {
    const cfg = loadConfig(notifySmtpConfigSchema, {
      ...relay,
      APP_ENV: appEnv,
      NOTIFY_SMTP_SECURE: 'none',
    });
    expect(cfg.NOTIFY_SMTP_SECURE).toBe('none');
  });

  it.each(['staging', 'production'])('rejects plaintext SMTP when APP_ENV=%s', (appEnv) => {
    expect(issues({ ...relay, APP_ENV: appEnv, NOTIFY_SMTP_SECURE: 'none' })).toContain(
      'NOTIFY_SMTP_SECURE',
    );
  });

  it.each([
    ['NOTIFY_SMTP_SECURE', 'ssl'],
    ['NOTIFY_SMTP_PORT', '0'],
    ['NOTIFY_SMTP_PORT', '70000'],
    ['NOTIFY_SMTP_FROM', 'not-an-address'],
  ])('rejects %s=%s', (key, value) => {
    expect(issues({ ...relay, [key]: value })).toContain(key);
  });
});

describe('isSenderAddress', () => {
  it.each(['no-reply@example.com', 'Gateway <no-reply@example.com>', '<a@b.example>'])(
    'accepts %s',
    (value) => expect(isSenderAddress(value)).toBe(true),
  );

  it.each([
    'Gateway',
    'Gateway <not-an-email>',
    'a@b.example\r\nBcc: x@y.example',
    'Gateway <a@b.example> trailing',
  ])('rejects %j', (value) => expect(isSenderAddress(value)).toBe(false));
});
