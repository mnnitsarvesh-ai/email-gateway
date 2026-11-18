import { isKeyOfOrganization } from '@email-gateway/archive';
import { type HandleOutcome, NonRetryableError } from '@email-gateway/common';
import { type PrismaClient, processOnce } from '@email-gateway/database';
import {
  type EventEnvelope,
  EventTypes,
  messageArchiveRequestedV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import type { ArchiveMetrics } from '../metrics/archive-metrics';
import { orgAllowed } from '../shared/db';
import { errorFields } from '../shared/errors';
import { upsertIntents } from './intents';
import type { OrgContextCache } from './org-context';

/** The ledger consumer of `email.archive` (topology v12, A26). */
export const ARCHIVE_CONSUMER = 'archive-worker.archive';
export const ARCHIVE_QUEUE = 'email.archive';
export const ARCHIVE_EVENT_TYPES = [EventTypes.MessageArchiveRequested] as const;

export type ArchiveRequestResult = 'intent' | 'duplicate' | 'unknown' | 'foreign' | 'invalid';

/**
 * Source 2, the `email.archive` consumer (A2): `mail.message.archive_requested.v1` (strictly
 * parsed) → the message is re-read on the writer by its partition key `(id, received_at)`; the
 * organization and `received_at` must echo the envelope and the event's `emlS3Key` must be the
 * row's original key under `org/<organizationId>/eml/`. Then, in one writer transaction under the
 * ledger (`processOnce`, `archive-worker.archive`), the intent is upserted with the policy source
 * and `next_check_at = now`. An unknown or foreign message is acked with a counter (no intent).
 * Duplicates are no-ops. Retries follow the topology (`hold`, 10 × 2 s–60 s).
 */
export class ArchiveRequestConsumer {
  private readonly consumer: string;
  private readonly now: () => Date;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly orgs: OrgContextCache,
    private readonly options: {
      metrics: ArchiveMetrics;
      logger: Logger;
      consumer?: string;
      organizationIds?: readonly bigint[];
      now?: () => Date;
    },
  ) {
    this.consumer = options.consumer ?? ARCHIVE_CONSUMER;
    this.now = options.now ?? (() => new Date());
  }

  readonly handle = async (event: EventEnvelope<unknown>): Promise<HandleOutcome> => {
    try {
      const result = await this.process(event);
      this.options.metrics.consumerEvents.inc({ result });
      return result === 'duplicate' ? 'duplicate' : 'handled';
    } catch (error) {
      if (error instanceof NonRetryableError) {
        this.options.metrics.consumerEvents.inc({ result: 'invalid' });
        throw error;
      }
      this.options.metrics.consumerEvents.inc({ result: 'error' });
      this.options.logger.warn(
        { eventId: event.eventId, ...errorFields(error) },
        'archive request not processed; retried',
      );
      throw error;
    }
  };

  async process(event: EventEnvelope<unknown>): Promise<ArchiveRequestResult> {
    if (event.eventType !== EventTypes.MessageArchiveRequested) {
      throw new NonRetryableError('unexpected_event_type');
    }
    const parsed = messageArchiveRequestedV1.safeParse(event.payload);
    if (!parsed.success) throw new NonRetryableError('payload_invalid');
    const payload = parsed.data;
    const organizationId = BigInt(event.organizationId);
    if (!orgAllowed(organizationId, this.options.organizationIds)) return 'foreign';
    const messageId = BigInt(payload.messageId);
    const receivedAt = new Date(payload.receivedAt);
    const message = await this.prisma.emailMessage.findUnique({
      where: { id_receivedAt: { id: messageId, receivedAt } },
      select: {
        id: true,
        receivedAt: true,
        organizationId: true,
        direction: true,
        emlObjectKey: true,
      },
    });
    if (message === null) return 'unknown';
    if (
      message.organizationId !== organizationId ||
      message.id !== messageId ||
      message.receivedAt.getTime() !== receivedAt.getTime() ||
      message.emlObjectKey !== payload.emlS3Key ||
      !isKeyOfOrganization(message.emlObjectKey, organizationId, 'eml')
    ) {
      this.options.logger.warn(
        { eventId: event.eventId },
        'archive request does not echo its message row; acked without an intent',
      );
      return 'foreign';
    }
    const ctx = await this.orgs.get(organizationId);
    const now = this.now();
    const outcome = await processOnce(this.prisma, this.consumer, event.eventId, (tx) =>
      upsertIntents(tx, [
        {
          organizationId,
          messageId,
          receivedAt,
          direction: message.direction,
          journal: false,
          policy: true,
          policyRuleRef: payload.ruleRef,
          settingsGeneration: ctx.generation,
          nextCheckAt: now,
        },
      ]),
    );
    return outcome.status === 'duplicate' ? 'duplicate' : 'intent';
  }
}
