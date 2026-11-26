import { NonRetryableError, uuidv7 } from '@email-gateway/common';
import type { MessageVerdict, Prisma } from '@email-gateway/database';
import {
  EventTypes,
  type MessageCopyScannedV1,
  messageCopyScannedV1,
} from '@email-gateway/event-contracts';
import {
  COPY_INGEST_SOURCES,
  type MessageIngestSourceValue,
} from '@email-gateway/message-lifecycle';

/** A non-gateway copy's ingest source (step API-1 D7.7): `journal_intake` or `mailbox_api`. */
export type CopyIngestSource = MessageCopyScannedV1['ingestSource'];

/**
 * True for an ingest source whose messages are copies (step API-1 D7.7, ADR-0098): never
 * delivered, never toward the policy engine, terminal state `journaled`. A missing value is a
 * gateway message (rows written before step 8.6).
 */
export function isCopySource(
  source: MessageIngestSourceValue | null | undefined,
): source is CopyIngestSource {
  return source !== null && source !== undefined && COPY_INGEST_SOURCES.includes(source);
}

/** What one `mail.message.copy_scanned.v1` row says (step API-1 D8). */
export interface CopyScannedInput {
  message: { id: bigint; receivedAt: Date; organizationId: bigint };
  ingestSource: CopyIngestSource;
  lifecycleRound: number;
  /** `email_scans.id` of the round; null for `parse_failed`. */
  scanId: bigint | null;
  outcome: MessageCopyScannedV1['outcome'];
  verdict: MessageVerdict | null;
  riskScore: number | null;
  completedAt: Date;
  correlationId: string;
}

/**
 * Writes the `mail.message.copy_scanned.v1` outbox row of a copy in the caller's transaction
 * (step API-1 D8, contracts §36): `aggregate_type = 'message'`, `aggregate_id` = the message
 * public id (`message_identities.public_id`, same organization). The payload is validated first;
 * a contract violation or a missing identity throws `NonRetryableError` and rolls the caller's
 * transaction back (never half a finalization). Returns the outbox event id.
 */
export async function writeCopyScannedOutbox(
  tx: Prisma.TransactionClient,
  input: CopyScannedInput,
): Promise<string> {
  const { message } = input;
  const identity = await tx.messageIdentity.findUnique({
    where: { id: message.id },
    select: { publicId: true, organizationId: true },
  });
  if (identity === null || identity.organizationId !== message.organizationId) {
    throw new NonRetryableError('copy_scanned_identity_missing');
  }
  const parsed = messageCopyScannedV1.safeParse({
    messageId: message.id.toString(),
    messagePublicId: identity.publicId,
    receivedAt: message.receivedAt.toISOString(),
    ingestSource: input.ingestSource,
    lifecycleRound: input.lifecycleRound,
    scanId: input.scanId === null ? null : input.scanId.toString(),
    outcome: input.outcome,
    verdict: input.verdict,
    riskScore: input.riskScore,
    completedAt: input.completedAt.toISOString(),
  } satisfies Record<keyof MessageCopyScannedV1, unknown>);
  if (!parsed.success) throw new NonRetryableError('copy_scanned_payload_invalid');
  const eventId = uuidv7(input.completedAt.getTime());
  await tx.messageOutbox.create({
    data: {
      eventId,
      organizationId: message.organizationId,
      eventType: EventTypes.MessageCopyScanned,
      aggregateType: 'message',
      aggregateId: identity.publicId,
      correlationId: input.correlationId,
      payload: parsed.data,
    },
    select: { id: true },
  });
  return eventId;
}
