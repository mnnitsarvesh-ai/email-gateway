import type { Prisma } from '@email-gateway/database';
import { transitionKeyHash } from './keys';
import type { MessageState } from './states';
import type { LifecycleReasonCode } from './transitions';

export interface InitialLifecycleInput {
  messageId: bigint;
  receivedAt: Date;
  organizationId: bigint;
  /** Event id of the `mail.message.received.v1` outbox row (history `event_id`). */
  causationEventId: string;
  /** e.g. `lmtp:<queueId>`. */
  correlationId: string;
  /** Deployable, `smtp-adapter`. */
  service: string;
  /** Commit time: `status_changed_at`, `occurred_at` and `changed_at` of both rows. */
  at: Date;
}

export interface InitialLifecycle {
  /** Spread into the `emailMessage.create` of the SMTP commit. */
  messageFields: {
    status: Extract<MessageState, 'persisted'>;
    version: 1;
    lifecycleRound: 0;
    statusReason: Extract<LifecycleReasonCode, 'committed'>;
    statusChangedAt: Date;
  };
  /** E1 (`NULL → received`, version 0) and E2 (`received → persisted`, version 1). */
  historyRows: Prisma.EmailMessageStatusHistoryCreateManyInput[];
}

/** Transition keys of the creation rows (L5.3). */
export const initialTransitionKeys = (messageId: bigint) => ({
  received: `ingest:${messageId.toString()}:received`,
  persisted: `ingest:${messageId.toString()}:persisted`,
});

/**
 * The lifecycle of a message created by the SMTP commit (step 3.3 L5.2, edges E1 and E2), pure:
 * the row is born `persisted` (version 1, round 0, reason `committed`) with two history rows.
 * No `email_events` row (the `received` event is the timeline entry) and no `state_changed`
 * outbox row (`mail.message.received.v1` notifies `persisted`).
 */
export function initialLifecycle(input: InitialLifecycleInput): InitialLifecycle {
  const keys = initialTransitionKeys(input.messageId);
  const common = {
    receivedAt: input.receivedAt,
    messageId: input.messageId,
    organizationId: input.organizationId,
    lifecycleRound: 0,
    actorRole: 'ingestion',
    actorService: input.service,
    actorType: 'system',
    actorId: null,
    eventId: input.causationEventId,
    correlationId: input.correlationId,
    stateEventId: null,
    occurredAt: input.at,
    changedAt: input.at,
  } as const;
  return {
    messageFields: {
      status: 'persisted',
      version: 1,
      lifecycleRound: 0,
      statusReason: 'committed',
      statusChangedAt: input.at,
    },
    historyRows: [
      {
        ...common,
        version: 0,
        fromStatus: null,
        toStatus: 'received',
        reasonCode: 'smtp_accepted',
        transitionKey: transitionKeyHash(keys.received),
      },
      {
        ...common,
        version: 1,
        fromStatus: 'received',
        toStatus: 'persisted',
        reasonCode: 'committed',
        transitionKey: transitionKeyHash(keys.persisted),
      },
    ],
  };
}

/**
 * Writes the two creation history rows of `initialLifecycle` in the caller's (SMTP commit)
 * transaction: one `createMany`, no lock, no read. The only way a creator writes history rows
 * (one-door rule, L5.9).
 */
export async function writeInitialHistory(
  tx: Prisma.TransactionClient,
  init: InitialLifecycle,
): Promise<void> {
  await tx.emailMessageStatusHistory.createMany({ data: init.historyRows });
}
