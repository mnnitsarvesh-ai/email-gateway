import { Logger } from '@nestjs/common';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { maskEmail } from './email-sender';
import { devLinksAllowed, LogEmailSender } from './log-email-sender';
import { buildPortalLink, passwordResetEmail } from './templates';

const token = 'egt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const email = passwordResetEmail({
  to: 'alice@gateway.test',
  link: buildPortalLink('reset-password', token, 'http://localhost:3001'),
  expiresAt: new Date('2026-11-02T12:00:00Z'),
});

function logged(config: ConstructorParameters<typeof LogEmailSender>[0]): Record<string, unknown> {
  const spy = vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
  void new LogEmailSender(config).send(email);
  expect(spy).toHaveBeenCalledTimes(1);
  return spy.mock.calls[0]![0] as Record<string, unknown>;
}

describe('LogEmailSender', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('logs kind, masked recipient and subject, with the dev link locally', () => {
    const entry = logged({ NODE_ENV: 'development', APP_ENV: 'local' });
    expect(entry).toMatchObject({
      kind: 'password_reset',
      to: 'a***@gateway.test',
      subject: email.subject,
      devLink: `http://localhost:3001/auth/reset-password#token=${token}`,
    });
    expect(JSON.stringify(entry)).not.toContain('alice@');
    expect(entry).not.toHaveProperty('text');
  });

  it('includes the dev link in CI', () => {
    expect(logged({ NODE_ENV: 'test', APP_ENV: 'ci' })).toHaveProperty('devLink');
  });

  it.each([
    { NODE_ENV: 'production', APP_ENV: 'local' },
    { NODE_ENV: 'production', APP_ENV: 'production' },
    { NODE_ENV: 'development', APP_ENV: 'staging' },
  ] as const)('never logs the token for %o', (config) => {
    expect(devLinksAllowed(config)).toBe(false);
    expect(JSON.stringify(logged(config))).not.toContain(token);
  });
});

describe('maskEmail', () => {
  it('keeps the first character and the domain', () => {
    expect(maskEmail('alice@example.com')).toBe('a***@example.com');
    expect(maskEmail('not-an-email')).toBe('***');
  });
});
