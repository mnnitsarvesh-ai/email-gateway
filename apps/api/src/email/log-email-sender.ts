import { Logger } from '@nestjs/common';
import type { ApiConfig } from '../config';
import { EmailSender, maskEmail, type OutboundEmail } from './email-sender';

export type LogEmailSenderConfig = Pick<ApiConfig, 'NODE_ENV' | 'APP_ENV'>;

/** The token-bearing link may be logged only by a non-production process in local or CI. */
export function devLinksAllowed(config: LogEmailSenderConfig): boolean {
  return (
    config.NODE_ENV !== 'production' && (config.APP_ENV === 'local' || config.APP_ENV === 'ci')
  );
}

/**
 * Fallback when no relay is configured: logs that an email would be sent. Emails are then not
 * delivered (a documented limitation, see docs/deployment/README.md). In production mode the
 * token never appears in the log.
 */
export class LogEmailSender extends EmailSender {
  readonly transport = 'log' as const;
  private readonly logger = new Logger('EmailSender');
  private readonly includeDevLink: boolean;

  constructor(config: LogEmailSenderConfig) {
    super();
    this.includeDevLink = devLinksAllowed(config);
  }

  send(email: OutboundEmail): Promise<void> {
    this.logger.log({
      message: 'Email not delivered (no SMTP relay configured)',
      kind: email.kind,
      to: maskEmail(email.to),
      subject: email.subject,
      ...(this.includeDevLink && email.devLink !== undefined && { devLink: email.devLink }),
    });
    return Promise.resolve();
  }
}
