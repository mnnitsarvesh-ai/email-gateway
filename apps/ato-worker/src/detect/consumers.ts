import { type HandleOutcome, NonRetryableError } from '@email-gateway/common';
import { type EventEnvelope, EventTypes } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import type { AtoEventResult, AtoEventSource, AtoMetrics } from '../metrics/ato-metrics';
import { errorFields } from '../shared/errors';
import type { AccountChangeHandler } from './account-change.handler';
import type { LoginHandler } from './login.handler';
import type { MailHandler } from './mail.handler';
import type { SmtpHandler } from './smtp.handler';

/** Queues, ledgers and accepted types of the detect role (topology v13, D3). */
export const EVENTS_QUEUE = 'ato.events';
export const MAIL_QUEUE = 'ato.mail';
export const RESPONSES_QUEUE = 'ato.responses';
export const EVENTS_CONSUMER = 'ato-worker.events';
export const MAIL_CONSUMER = 'ato-worker.mail';
export const RESPONSES_CONSUMER = 'ato-worker.respond';
export const EVENTS_EVENT_TYPES = [
  EventTypes.AuthLoginRecorded,
  EventTypes.AuthAccountChanged,
  EventTypes.SmtpAuthRecorded,
  EventTypes.SmtpSubmissionRecorded,
] as const;
export const MAIL_EVENT_TYPES = [EventTypes.MessageScanned] as const;
export const RESPONSES_EVENT_TYPES = [EventTypes.AtoResponseRequested] as const;

const SOURCE_OF: Readonly<Record<string, AtoEventSource>> = {
  [EventTypes.AuthLoginRecorded]: 'portal_login',
  [EventTypes.AuthAccountChanged]: 'account_change',
  [EventTypes.SmtpAuthRecorded]: 'smtp_auth',
  [EventTypes.SmtpSubmissionRecorded]: 'smtp_submission',
  [EventTypes.MessageScanned]: 'outbound_message',
};

/** Shared result accounting of the two detect consumers. */
abstract class DetectConsumer {
  constructor(
    protected readonly metrics: AtoMetrics | null,
    protected readonly logger: Logger,
    protected readonly organizationIds?: readonly bigint[],
  ) {}

  protected abstract dispatch(event: EventEnvelope<unknown>): Promise<AtoEventResult | 'counted'>;

  readonly handle = async (event: EventEnvelope<unknown>): Promise<HandleOutcome> => {
    const source = SOURCE_OF[event.eventType] ?? 'portal_login';
    if (
      this.organizationIds !== undefined &&
      !this.organizationIds.includes(BigInt(event.organizationId))
    ) {
      // Integration suites restrict the worker to their own organizations.
      return 'handled';
    }
    try {
      const result = await this.dispatch(event);
      if (result !== 'counted') this.metrics?.events.inc({ source, result });
      return result === 'duplicate' ? 'duplicate' : 'handled';
    } catch (error) {
      this.metrics?.events.inc({ source, result: 'error' });
      if (!(error instanceof NonRetryableError)) {
        this.logger.warn(
          { eventId: event.eventId, eventType: event.eventType, ...errorFields(error) },
          'ato event not processed; retried',
        );
      }
      throw error;
    }
  };
}

/** `ato.events` (ledger `ato-worker.events`): logins, account changes, SMTP telemetry. */
export class AtoEventsConsumer extends DetectConsumer {
  constructor(
    private readonly handlers: {
      login: LoginHandler;
      accountChange: AccountChangeHandler;
      smtp: SmtpHandler;
    },
    metrics: AtoMetrics | null,
    logger: Logger,
    organizationIds?: readonly bigint[],
  ) {
    super(metrics, logger, organizationIds);
  }

  protected dispatch(event: EventEnvelope<unknown>): Promise<AtoEventResult | 'counted'> {
    switch (event.eventType) {
      case EventTypes.AuthLoginRecorded:
        return this.handlers.login.handle(event);
      case EventTypes.AuthAccountChanged:
        return this.handlers.accountChange.handle(event);
      case EventTypes.SmtpAuthRecorded:
        return this.handlers.smtp.handleAuth(event);
      case EventTypes.SmtpSubmissionRecorded:
        return this.handlers.smtp.handleSubmission(event);
      default:
        throw new NonRetryableError('unexpected_event_type');
    }
  }
}

/** `ato.mail` (lossy, ledger `ato-worker.mail` keyed by `atoMailKey`): outbound/internal rounds. */
export class AtoMailConsumer extends DetectConsumer {
  constructor(
    private readonly mail: MailHandler,
    metrics: AtoMetrics | null,
    logger: Logger,
    organizationIds?: readonly bigint[],
  ) {
    super(metrics, logger, organizationIds);
  }

  protected dispatch(event: EventEnvelope<unknown>): Promise<AtoEventResult> {
    if (event.eventType !== EventTypes.MessageScanned) {
      return Promise.reject(new NonRetryableError('unexpected_event_type'));
    }
    return this.mail.handle(event);
  }
}
