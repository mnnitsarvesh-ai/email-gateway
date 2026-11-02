import { describe, expect, it, vi } from 'vitest';
import { loadApiConfig } from '../config';
import { createEmailSender } from './email-sender.factory';
import { LogEmailSender } from './log-email-sender';
import { SmtpEmailSender } from './smtp-email-sender';

const env = {
  DATABASE_URL: 'mysql://u:p@mysql:3306/db',
  REDIS_URL: 'redis://redis:6379',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'mail',
  S3_BUCKET_ARCHIVE: 'archive',
  AUTH_JWT_SECRET: 'j'.repeat(64),
  AUTH_TOKEN_PEPPER: 'p'.repeat(64),
  DATA_ENCRYPTION_KEY: 'a'.repeat(64),
};

const logger = () => ({ log: vi.fn(), warn: vi.fn() });

describe('createEmailSender', () => {
  it('uses SMTP iff NOTIFY_SMTP_HOST is set, naming the transport but never the relay', () => {
    const log = logger();
    const sender = createEmailSender(
      loadApiConfig({
        ...env,
        NOTIFY_SMTP_HOST: 'relay.example.com',
        NOTIFY_SMTP_FROM: 'no-reply@example.com',
        NOTIFY_SMTP_USER: 'relay-user',
        NOTIFY_SMTP_PASSWORD: 'RelaySecret-Value',
      }),
      log,
    );
    expect(sender).toBeInstanceOf(SmtpEmailSender);
    expect(sender.transport).toBe('smtp');
    (sender as SmtpEmailSender).close();
    const output = JSON.stringify(log.log.mock.calls);
    expect(output).toContain('smtp');
    for (const secret of ['relay.example.com', 'relay-user', 'RelaySecret-Value']) {
      expect(output).not.toContain(secret);
    }
    expect(log.warn).not.toHaveBeenCalled();
  });

  it('falls back to the log transport without a relay', () => {
    const log = logger();
    const sender = createEmailSender(loadApiConfig(env), log);
    expect(sender).toBeInstanceOf(LogEmailSender);
    expect(log.log).toHaveBeenCalledWith(expect.objectContaining({ transport: 'log' }));
    expect(log.warn).not.toHaveBeenCalled();
  });

  it('warns when production has no relay', () => {
    const log = logger();
    createEmailSender(
      loadApiConfig({
        ...env,
        NODE_ENV: 'production',
        APP_ENV: 'production',
        PORTAL_PUBLIC_URL: 'https://portal.example.com',
      }),
      log,
    );
    expect(log.warn).toHaveBeenCalledTimes(1);
  });
});
