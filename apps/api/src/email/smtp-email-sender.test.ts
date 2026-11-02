import { Logger } from '@nestjs/common';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  EmailDeliveryError,
  SMTP_CONNECTION_TIMEOUT_MS,
  SMTP_SOCKET_TIMEOUT_MS,
  SmtpEmailSender,
  type SmtpEmailSenderOptions,
  smtpTransportOptions,
} from './smtp-email-sender';

const base: SmtpEmailSenderOptions = {
  NOTIFY_SMTP_HOST: 'smtp.example.com',
  NOTIFY_SMTP_PORT: 587,
  NOTIFY_SMTP_SECURE: 'starttls',
  NOTIFY_SMTP_USER: 'mailer',
  NOTIFY_SMTP_PASSWORD: 'RelayPassword-Value',
  NOTIFY_SMTP_FROM: 'Gateway <no-reply@example.com>',
};

describe('smtpTransportOptions', () => {
  it('maps starttls to a required upgrade', () => {
    expect(smtpTransportOptions(base)).toMatchObject({
      host: 'smtp.example.com',
      port: 587,
      secure: false,
      requireTLS: true,
      ignoreTLS: false,
      auth: { user: 'mailer', pass: 'RelayPassword-Value' },
    });
  });

  it('maps tls to implicit TLS', () => {
    expect(
      smtpTransportOptions({ ...base, NOTIFY_SMTP_SECURE: 'tls', NOTIFY_SMTP_PORT: 465 }),
    ).toMatchObject({
      secure: true,
      requireTLS: false,
      ignoreTLS: false,
    });
  });

  it('maps none to plaintext without opportunistic STARTTLS', () => {
    expect(smtpTransportOptions({ ...base, NOTIFY_SMTP_SECURE: 'none' })).toMatchObject({
      secure: false,
      requireTLS: false,
      ignoreTLS: true,
    });
  });

  it.each(['tls', 'starttls', 'none'] as const)(
    'keeps certificate verification on (%s)',
    (mode) => {
      const options = smtpTransportOptions({ ...base, NOTIFY_SMTP_SECURE: mode });
      expect(options.tls).toMatchObject({ rejectUnauthorized: true });
      expect(options.connectionTimeout).toBe(SMTP_CONNECTION_TIMEOUT_MS);
      expect(options.socketTimeout).toBe(SMTP_SOCKET_TIMEOUT_MS);
    },
  );

  it('trusts the system CAs only by default', () => {
    expect(smtpTransportOptions(base).tls).not.toHaveProperty('ca');
  });

  it('adds a pinned relay certificate without disabling verification', () => {
    const pinned = '-----BEGIN CERTIFICATE-----\nMIIBpinned\n-----END CERTIFICATE-----\n';
    const tls = smtpTransportOptions(base, pinned).tls as {
      ca: string[];
      rejectUnauthorized: boolean;
    };
    expect(tls.rejectUnauthorized).toBe(true);
    expect(tls.ca).toContain(pinned);
    // System CAs stay trusted, so a later switch to a publicly signed certificate keeps working.
    expect(tls.ca.length).toBeGreaterThan(1);
  });

  it('omits auth without credentials', () => {
    const { NOTIFY_SMTP_USER: _u, NOTIFY_SMTP_PASSWORD: _p, ...anonymous } = base;
    expect(smtpTransportOptions(anonymous)).not.toHaveProperty('auth');
  });
});

describe('SmtpEmailSender', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const email = {
    kind: 'invitation' as const,
    to: 'bob@example.org',
    subject: 'Invitation',
    text: 'Open http://localhost/auth/accept-invitation#token=egt_secret',
  };

  function sender(sendMail: (mail: unknown) => Promise<unknown>) {
    const s = new SmtpEmailSender(base);
    (s as unknown as { transporter: { sendMail: typeof sendMail } }).transporter.sendMail =
      sendMail;
    return s;
  }

  it('sends plain text from NOTIFY_SMTP_FROM', async () => {
    vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
    const sendMail = vi.fn().mockResolvedValue({ accepted: [email.to] });
    await sender(sendMail).send(email);
    expect(sendMail).toHaveBeenCalledWith(
      expect.objectContaining({
        from: 'Gateway <no-reply@example.com>',
        to: 'bob@example.org',
        subject: 'Invitation',
        text: email.text,
      }),
    );
  });

  it('logs only the SMTP reply code on failure and throws a detail-free error', async () => {
    const errors = vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
    const failure = Object.assign(
      new Error('550 mailbox bob@example.org unavailable, auth mailer'),
      {
        responseCode: 550,
        code: 'EENVELOPE',
        response: '550 mailbox unavailable',
      },
    );
    const error = await sender(() => Promise.reject(failure))
      .send(email)
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(EmailDeliveryError);
    expect((error as EmailDeliveryError).responseCode).toBe(550);
    const logged = JSON.stringify(errors.mock.calls);
    expect(logged).toContain('550');
    expect(logged).not.toContain('egt_secret');
    expect(logged).not.toContain('RelayPassword-Value');
    expect(logged).not.toContain('bob@example.org');
  });

  it('requires a sender address', () => {
    expect(() => new SmtpEmailSender({ ...base, NOTIFY_SMTP_FROM: undefined })).toThrow();
  });
});
