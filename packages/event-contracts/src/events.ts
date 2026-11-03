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

/** `email_deliveries.status` values (DeliveryStatus enum, step 2.3 R9.1). */
export const DELIVERY_STATUSES = [
  'pending',
  'in_progress',
  'queued',
  'deferred',
  'delivered',
  'bounced',
  'expired',
  'failed',
  'suppressed',
  'unknown',
] as const;
export const deliveryStatusSchema = z.enum(DELIVERY_STATUSES);
export type DeliveryStatusValue = z.infer<typeof deliveryStatusSchema>;

const seq = z.number().int().min(0).max(65_535);

/**
 * The trigger of delivery (step 2.3 R5): the approved subset of a message's recipients. Written
 * through `message_outbox` (`aggregate_type = 'message'`, `aggregate_id` = decimal message id) by
 * the policy engine (5.x), the quarantine release (5.3/6.1) or the development-only pass-through
 * of the delivery-worker. The envelope `eventId` is the approval id; the envelope
 * `organizationId` is the message's organization. `(recipientId, deliverySeq)` is unique per
 * delivery (`email_deliveries`), so a duplicate approval never plans twice.
 */
export const deliveryApprovedV1 = z.object({
  messageId: decimalIdSchema,
  receivedAt: z.iso.datetime(),
  /** 0 = initial delivery; releases use 1, 2, … */
  deliverySeq: seq,
  source: z.enum(['policy', 'quarantine_release', 'dev_passthrough']),
  /** The object to deliver (policy may later produce a modified copy). */
  emlS3Key: s3Key,
  recipients: z
    .array(z.object({ recipientId: decimalIdSchema, rcptSeq: seq }))
    .min(1)
    .max(1000)
    .refine(
      (recipients) => new Set(recipients.map((r) => r.recipientId)).size === recipients.length,
      { message: 'Duplicate recipientId' },
    ),
  approvedAt: z.iso.datetime(),
});
export type DeliveryApprovedV1 = z.infer<typeof deliveryApprovedV1>;

/**
 * One applied per-recipient delivery status transition (step 2.3 R9.1), written by the shared
 * recorder (`@email-gateway/mail-routing`) in the transaction of the transition
 * (`aggregate_type = 'message'`, `correlation_id = 'delivery:<deliveryId>'`). Ids and codes only:
 * never an address or message content.
 */
export const deliveryStatusChangedV1 = z.object({
  messageId: decimalIdSchema,
  receivedAt: z.iso.datetime(),
  deliveryId: decimalIdSchema,
  recipientId: decimalIdSchema,
  rcptSeq: seq,
  deliverySeq: seq,
  direction,
  /** `null` for the first status of a new delivery row. */
  previousStatus: deliveryStatusSchema.nullable(),
  status: deliveryStatusSchema,
  occurredAt: z.iso.datetime(),
  attemptCount: z.number().int().nonnegative(),
  smtpCode: z.number().int().min(200).max(599).optional(),
  enhancedStatus: z
    .string()
    .regex(/^[245]\.\d{1,3}\.\d{1,3}$/)
    .optional(),
  errorClass: z
    .string()
    .regex(/^[a-z0-9_]{1,32}$/)
    .optional(),
  queueId: z
    .string()
    .regex(/^[A-Za-z0-9]{1,32}$/)
    .optional(),
});
export type DeliveryStatusChangedV1 = z.infer<typeof deliveryStatusChangedV1>;

/**
 * Published (through `message_outbox`, `aggregate_type = 'domain'`) by the api on every change of
 * a domain's destination servers (step 2.3 R2). The smtp-adapter's outbox-tail invalidator
 * deletes the domain's route key and the TLS keys of `hosts` (old and new). The envelope's
 * `organizationId` is the owning organization.
 */
export const domainRoutingChangedV1 = z.object({
  domainId: decimalIdSchema,
  domainPublicId: z.uuid(),
  /** Normalized ASCII (punycode) name, as stored. */
  name: z.string().min(1).max(253),
  /**
   * Destination hosts before and after the change (normalized, de-duplicated): at most
   * 2 × ROUTING_MAX_DESTINATIONS_PER_DOMAIN (10), because a replacement names both sets.
   */
  hosts: z.array(z.string().min(1).max(253)).max(20),
  changedAt: z.iso.datetime(),
});
export type DomainRoutingChangedV1 = z.infer<typeof domainRoutingChangedV1>;

export const EventTypes = {
  MessageReceived: 'mail.message.received.v1',
  MessageScanned: 'mail.message.scanned.v1',
  PolicyDecided: 'mail.policy.decided.v1',
  DomainStatusChanged: 'domain.status.changed.v1',
  DeliveryApproved: 'mail.delivery.approved.v1',
  DeliveryStatusChanged: 'mail.delivery.status_changed.v1',
  DomainRoutingChanged: 'domain.routing.changed.v1',
} as const;
