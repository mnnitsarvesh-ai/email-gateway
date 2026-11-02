import { readFileSync } from 'node:fs';
import { rootCertificates as tlsRootCertificates } from 'node:tls';
import { Logger, type OnModuleDestroy } from '@nestjs/common';
import { createTransport, type Transporter } from 'nodemailer';
import type SMTPTransport from 'nodemailer/lib/smtp-transport';
import type { NotifySmtpConfig } from '@email-gateway/config';
import { EmailSender, maskEmail, type OutboundEmail } from './email-sender';

export type SmtpEmailSenderOptions = Pick<
  NotifySmtpConfig,
  | 'NOTIFY_SMTP_PORT'
  | 'NOTIFY_SMTP_SECURE'
  | 'NOTIFY_SMTP_USER'
  | 'NOTIFY_SMTP_PASSWORD'
  | 'NOTIFY_SMTP_FROM'
  | 'NOTIFY_SMTP_CA_PATH'
> & { NOTIFY_SMTP_HOST: string };

export const SMTP_CONNECTION_TIMEOUT_MS = 10_000;
export const SMTP_SOCKET_TIMEOUT_MS = 20_000;

/**
 * nodemailer transport options for the relay (D13). `tls`: implicit TLS. `starttls`: the upgrade
 * is required. `none`: plaintext and no opportunistic upgrade (local Postfix; the config schema
 * allows it only when APP_ENV is local or ci). Certificate verification is never disabled.
 */
export function smtpTransportOptions(
  options: SmtpEmailSenderOptions,
  /** PEM certificates to trust in addition to the system CAs (from NOTIFY_SMTP_CA_PATH). */
  extraCa?: string,
): SMTPTransport.Options {
  const secure = options.NOTIFY_SMTP_SECURE;
  return {
    host: options.NOTIFY_SMTP_HOST,
    port: options.NOTIFY_SMTP_PORT,
    secure: secure === 'tls',
    requireTLS: secure === 'starttls',
    ignoreTLS: secure === 'none',
    tls: {
      rejectUnauthorized: true,
      minVersion: 'TLSv1.2',
      servername: options.NOTIFY_SMTP_HOST,
      ...(extraCa && { ca: [...tlsRootCertificates, extraCa] }),
    },
    connectionTimeout: SMTP_CONNECTION_TIMEOUT_MS,
    greetingTimeout: SMTP_CONNECTION_TIMEOUT_MS,
    socketTimeout: SMTP_SOCKET_TIMEOUT_MS,
    ...(options.NOTIFY_SMTP_USER &&
      options.NOTIFY_SMTP_PASSWORD && {
        auth: { user: options.NOTIFY_SMTP_USER, pass: options.NOTIFY_SMTP_PASSWORD },
      }),
    disableFileAccess: true,
    disableUrlAccess: true,
  };
}

/** The SMTP reply code of a nodemailer error, if any (never its message: it may echo data). */
function smtpFailure(err: unknown): { responseCode?: number; errorCode?: string } {
  if (err === null || typeof err !== 'object') return {};
  const e = err as { responseCode?: unknown; code?: unknown };
  return {
    ...(typeof e.responseCode === 'number' && { responseCode: e.responseCode }),
    ...(typeof e.code === 'string' && { errorCode: e.code }),
  };
}

/** Error thrown by `send`; carries the SMTP reply code only. */
export class EmailDeliveryError extends Error {
  constructor(readonly responseCode?: number) {
    super(`Email delivery failed${responseCode ? ` (SMTP ${responseCode})` : ''}`);
    this.name = 'EmailDeliveryError';
  }
}

/** Submits plain-text email through the NOTIFY_SMTP_* relay. */
export class SmtpEmailSender extends EmailSender implements OnModuleDestroy {
  readonly transport = 'smtp' as const;
  private readonly logger = new Logger('EmailSender');
  private readonly transporter: Transporter<SMTPTransport.SentMessageInfo>;
  private readonly from: string;

  constructor(options: SmtpEmailSenderOptions) {
    super();
    if (!options.NOTIFY_SMTP_FROM) throw new Error('NOTIFY_SMTP_FROM is required for SMTP');
    this.from = options.NOTIFY_SMTP_FROM;
    const extraCa = options.NOTIFY_SMTP_CA_PATH
      ? readFileSync(options.NOTIFY_SMTP_CA_PATH, 'utf8')
      : undefined;
    this.transporter = createTransport(smtpTransportOptions(options, extraCa));
  }

  async send(email: OutboundEmail): Promise<void> {
    try {
      await this.transporter.sendMail({
        from: this.from,
        to: email.to,
        subject: email.subject,
        text: email.text,
        headers: { 'Auto-Submitted': 'auto-generated' },
      });
      this.logger.log({ message: 'Email sent', kind: email.kind, to: maskEmail(email.to) });
    } catch (err) {
      const failure = smtpFailure(err);
      this.logger.error({
        message: 'Email delivery failed',
        kind: email.kind,
        to: maskEmail(email.to),
        ...failure,
      });
      throw new EmailDeliveryError(failure.responseCode);
    }
  }

  close(): void {
    this.transporter.close();
  }

  onModuleDestroy(): void {
    this.close();
  }
}
