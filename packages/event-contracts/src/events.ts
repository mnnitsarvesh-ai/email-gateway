import { z } from 'zod';
import { decimalIdSchema } from './envelope';

const direction = z.enum(['inbound', 'outbound', 'internal']);
const s3Key = z
  .string()
  .regex(/^org\/[1-9][0-9]{0,19}\//, 'S3 keys are organization-prefixed (org/{organizationId}/)');

/**
 * Message events identify the message by its registry id (`message_identities.id`, a decimal
 * string) and always carry `receivedAt`, the partition key of every message table, so consumers
 * can prune to one partition (ADR-0014). Consumers de-duplicate through `message_idempotency`.
 */

/** Published by ingestion after the EML is in S3 and the message row is committed. */
export const messageReceivedV1 = z.object({
  messageId: decimalIdSchema,
  receivedAt: z.iso.datetime(),
  direction,
  emlS3Key: s3Key,
  sizeBytes: z.number().int().nonnegative(),
  envelopeFrom: z.string().max(320),
  recipientCount: z.number().int().positive(),
});
export type MessageReceivedV1 = z.infer<typeof messageReceivedV1>;

/** Published by the email worker once all required security stages report or time out. */
export const messageScannedV1 = z.object({
  messageId: decimalIdSchema,
  receivedAt: z.iso.datetime(),
  /** `email_scans.id` values produced for this message. */
  scanIds: z.array(decimalIdSchema),
  timedOutStages: z.array(z.string()),
});
export type MessageScannedV1 = z.infer<typeof messageScannedV1>;

/** Published by the policy engine with the final action for the message. */
export const policyDecidedV1 = z.object({
  messageId: decimalIdSchema,
  receivedAt: z.iso.datetime(),
  action: z.enum(['deliver', 'tag', 'quarantine', 'discard']),
  /** `policy_versions.id` values that matched. */
  matchedPolicyVersionIds: z.array(decimalIdSchema),
  archive: z.boolean(),
});
export type PolicyDecidedV1 = z.infer<typeof policyDecidedV1>;

export const EventTypes = {
  MessageReceived: 'mail.message.received.v1',
  MessageScanned: 'mail.message.scanned.v1',
  PolicyDecided: 'mail.policy.decided.v1',
} as const;
