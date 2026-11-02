import { Logger, type Provider } from '@nestjs/common';
import { API_CONFIG } from '../api-config.token';
import type { ApiConfig } from '../config';
import { EmailSender } from './email-sender';
import { LogEmailSender } from './log-email-sender';
import { SmtpEmailSender } from './smtp-email-sender';

type LoggerLike = Pick<Logger, 'log' | 'warn'>;

/**
 * SMTP iff NOTIFY_SMTP_HOST is set, otherwise the log transport (D13). Logs one line naming the
 * transport (never the relay's host or credentials) and warns when production has no relay.
 */
export function createEmailSender(
  config: Readonly<ApiConfig>,
  logger: LoggerLike = new Logger('EmailSender'),
): EmailSender {
  if (config.NOTIFY_SMTP_HOST) {
    const sender = new SmtpEmailSender({ ...config, NOTIFY_SMTP_HOST: config.NOTIFY_SMTP_HOST });
    logger.log({
      message: 'Transactional email transport: smtp',
      transport: 'smtp',
      tlsMode: config.NOTIFY_SMTP_SECURE,
    });
    return sender;
  }
  logger.log({ message: 'Transactional email transport: log', transport: 'log' });
  if (config.NODE_ENV === 'production') {
    logger.warn({
      message:
        'NOTIFY_SMTP_HOST is not set: invitation, password reset and verification emails are ' +
        'logged without their links and NOT delivered',
      transport: 'log',
    });
  }
  return new LogEmailSender(config);
}

export const emailSenderProvider: Provider = {
  provide: EmailSender,
  useFactory: (config: Readonly<ApiConfig>) => createEmailSender(config),
  inject: [API_CONFIG],
};
