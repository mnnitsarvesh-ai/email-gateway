import { readFileSync } from 'node:fs';
import { rootCertificates as tlsRootCertificates } from 'node:tls';
import type { NotifySmtpConfig } from '@email-gateway/config';
import { createTransport, type Transporter } from 'nodemailer';
import type SMTPTransport from 'nodemailer/lib/smtp-transport';

export const SMTP_CONNECTION_TIMEOUT_MS = 10_000;
export const SMTP_SOCKET_TIMEOUT_MS = 20_000;

export type RelayOptions = Pick<
  NotifySmtpConfig,
  | 'NOTIFY_SMTP_PORT'
  | 'NOTIFY_SMTP_SECURE'
  | 'NOTIFY_SMTP_USER'
  | 'NOTIFY_SMTP_PASSWORD'
  | 'NOTIFY_SMTP_CA_PATH'
> & { NOTIFY_SMTP_HOST: string };

/**
 * nodemailer transport options for the `NOTIFY_SMTP_*` relay, the same as the api's
 * `smtpTransportOptions` (apps/api/src/email/smtp-email-sender.ts; apps never import each other,
 * so the pure helper is copied and its unit test pins the same behaviour). `tls`: implicit TLS;
 * `starttls`: the upgrade is required; `none`: plaintext without opportunistic upgrade (the
 * config schema allows it only when APP_ENV is local or ci). Certificates are always verified.
 */
export function relayTransportOptions(
  options: RelayOptions,
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

export interface NoticeMail {
  /** Envelope and Bcc recipients (no To header: recipients never see each other). */
  recipients: readonly string[];
  subject: string;
  text: string;
  /** Deterministic `<policy-notice.<eventId>@<domain>>`. */
  messageId: string;
}

/** A relay failure: retryable (the consumer retries, then dead-letters). Reply code only. */
export class NoticeSendError extends Error {
  override readonly name = 'NoticeSendError';
  readonly code = 'smtp_send_failed';
  constructor(readonly responseCode?: number) {
    super(`notice delivery failed${responseCode ? ` (SMTP ${responseCode})` : ''}`);
  }
}

/** Sends plain-text notices; `configured = false` without NOTIFY_SMTP_HOST (nothing is sent). */
export interface NoticeMailer {
  readonly configured: boolean;
  readonly from: string | null;
  send(mail: NoticeMail): Promise<void>;
  close(): void;
}

/** The nodemailer implementation over the relay. */
export class SmtpNoticeMailer implements NoticeMailer {
  readonly configured = true;
  readonly from: string;
  private readonly transporter: Transporter<SMTPTransport.SentMessageInfo>;

  constructor(options: RelayOptions & { NOTIFY_SMTP_FROM?: string | undefined }) {
    if (!options.NOTIFY_SMTP_FROM) throw new Error('NOTIFY_SMTP_FROM is required for SMTP');
    this.from = options.NOTIFY_SMTP_FROM;
    const extraCa = options.NOTIFY_SMTP_CA_PATH
      ? readFileSync(options.NOTIFY_SMTP_CA_PATH, 'utf8')
      : undefined;
    this.transporter = createTransport(relayTransportOptions(options, extraCa));
  }

  async send(mail: NoticeMail): Promise<void> {
    try {
      await this.transporter.sendMail({
        from: this.from,
        bcc: [...mail.recipients],
        subject: mail.subject,
        text: mail.text,
        messageId: mail.messageId,
        headers: { 'Auto-Submitted': 'auto-generated', 'X-Auto-Response-Suppress': 'All' },
      });
    } catch (err) {
      const code =
        err !== null &&
        typeof err === 'object' &&
        typeof (err as { responseCode?: unknown }).responseCode === 'number'
          ? (err as { responseCode: number }).responseCode
          : undefined;
      throw new NoticeSendError(code);
    }
  }

  close(): void {
    this.transporter.close();
  }
}

/** No relay configured (`NOTIFY_SMTP_HOST` unset): notices are counted `disabled`. */
export class DisabledNoticeMailer implements NoticeMailer {
  readonly configured = false;
  readonly from = null;
  send(): Promise<void> {
    return Promise.reject(new Error('no relay configured'));
  }
  close(): void {}
}

export function createNoticeMailer(
  cfg: Partial<RelayOptions> &
    Pick<NotifySmtpConfig, 'NOTIFY_SMTP_PORT' | 'NOTIFY_SMTP_SECURE' | 'NOTIFY_SMTP_FROM'>,
): NoticeMailer {
  if (!cfg.NOTIFY_SMTP_HOST) return new DisabledNoticeMailer();
  return new SmtpNoticeMailer({ ...cfg, NOTIFY_SMTP_HOST: cfg.NOTIFY_SMTP_HOST });
}
