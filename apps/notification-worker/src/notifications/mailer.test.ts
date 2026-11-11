import { describe, expect, it } from 'vitest';
import { createNoticeMailer, relayTransportOptions } from './mailer';

const base = {
  NOTIFY_SMTP_HOST: 'relay.example',
  NOTIFY_SMTP_PORT: 587,
  NOTIFY_SMTP_SECURE: 'starttls' as const,
  NOTIFY_SMTP_USER: undefined,
  NOTIFY_SMTP_PASSWORD: undefined,
  NOTIFY_SMTP_CA_PATH: undefined,
};

describe('relay transport (same options as the api SmtpEmailSender)', () => {
  it('requires STARTTLS, verifies certificates and disables file and URL access', () => {
    const o = relayTransportOptions(base);
    expect(o).toMatchObject({
      host: 'relay.example',
      port: 587,
      secure: false,
      requireTLS: true,
      ignoreTLS: false,
      disableFileAccess: true,
      disableUrlAccess: true,
      tls: { rejectUnauthorized: true, minVersion: 'TLSv1.2', servername: 'relay.example' },
    });
    expect(o.auth).toBeUndefined();
    expect(relayTransportOptions({ ...base, NOTIFY_SMTP_SECURE: 'tls' })).toMatchObject({
      secure: true,
    });
    expect(relayTransportOptions({ ...base, NOTIFY_SMTP_SECURE: 'none' })).toMatchObject({
      ignoreTLS: true,
      requireTLS: false,
    });
    expect(
      relayTransportOptions({ ...base, NOTIFY_SMTP_USER: 'u', NOTIFY_SMTP_PASSWORD: 'p' }).auth,
    ).toEqual({ user: 'u', pass: 'p' });
  });

  it('is disabled without NOTIFY_SMTP_HOST', () => {
    const mailer = createNoticeMailer({
      NOTIFY_SMTP_PORT: 25,
      NOTIFY_SMTP_SECURE: 'none',
      NOTIFY_SMTP_FROM: undefined,
    });
    expect(mailer.configured).toBe(false);
    expect(mailer.from).toBeNull();
    const smtp = createNoticeMailer({ ...base, NOTIFY_SMTP_FROM: 'no-reply@gw.example' });
    expect(smtp.configured).toBe(true);
    smtp.close();
  });
});
