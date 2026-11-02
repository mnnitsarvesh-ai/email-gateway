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

/**
 * Published (through `message_outbox`, `aggregate_type = 'domain'`) whenever a domain changes
 * lifecycle status (step 2.1 D3/D15): verified, failed (claim superseded, verification expired),
 * activated, suspended, resumed, deleted, verification restarted. Written in the transaction of
 * the transition, so it is emitted once per transition, never per DNS check. Consumers: the
 * smtp-adapter's tenant-resolution cache (2.2) and notifications (6.2). The envelope's
 * `organizationId` is the owning organization.
 */
export const domainStatusChangedV1 = z.object({
  domainId: decimalIdSchema,
  domainPublicId: z.uuid(),
  /** Normalized ASCII (punycode) name, as stored. */
  name: z.string().min(1).max(253),
  /** `null` for the first status of a new domain. */
  previousStatus: z.string().min(1).nullable(),
  status: z.string().min(1),
  /** E.g. `claimed_by_another_organization`, `verification_expired` or a suspension reason. */
  reason: z.string().max(512).nullable(),
  changedAt: z.iso.datetime(),
});
export type DomainStatusChangedV1 = z.infer<typeof domainStatusChangedV1>;

export const EventTypes = {
  MessageReceived: 'mail.message.received.v1',
  MessageScanned: 'mail.message.scanned.v1',
  PolicyDecided: 'mail.policy.decided.v1',
  DomainStatusChanged: 'domain.status.changed.v1',
} as const;
