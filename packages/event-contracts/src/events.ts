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

/**
 * MIME limit names (step 3.1 M5), as carried in `limitsExceeded` and stored in
 * `email_message_parses.limits_exceeded`. `@email-gateway/mime-parser` keeps its own copy (it does
 * not depend on this package); an email-worker unit test asserts the two lists are equal.
 */
export const MIME_LIMIT_NAMES = [
  'message_size',
  'nesting_depth',
  'part_count',
  'header_count',
  'header_line_length',
  'header_block_size',
  'attachment_count',
  'attachment_size',
  'body_size',
  'decoded_ratio',
  'total_decoded_size',
  'parse_timeout',
] as const;
export const mimeLimitNameSchema = z.enum(MIME_LIMIT_NAMES);
export type MimeLimitName = z.infer<typeof mimeLimitNameSchema>;

/**
 * Final parse statuses carried by `mail.message.parsed.v1` (step 3.1 M13). `parsing` is never
 * published, and `parse_failed` is carried by `mail.message.parse_failed.v1`.
 */
export const MESSAGE_PARSE_STATUSES = [
  'parsed',
  'parsed_with_defects',
  'parse_limit_exceeded',
] as const;
export const messageParseStatusSchema = z.enum(MESSAGE_PARSE_STATUSES);
export type MessageParseStatusValue = z.infer<typeof messageParseStatusSchema>;

/** `parse_failed` reasons (step 3.1 M3), stored in `email_message_parses.failure_reason`. */
export const PARSE_FAILURE_REASONS = [
  'eml_missing',
  'eml_key_mismatch',
  'integrity_mismatch',
  'max_attempts_exceeded',
  'parser_error',
] as const;
export const parseFailureReasonSchema = z.enum(PARSE_FAILURE_REASONS);
export type ParseFailureReason = z.infer<typeof parseFailureReasonSchema>;

const sha256Hex = z.string().regex(/^[0-9a-f]{64}$/, 'Expected a lower-case hex SHA-256');
/** A defect or attachment flag code: snake_case, never free text. */
const code = z.string().regex(/^[a-z0-9_]{1,48}$/, 'Expected a snake_case code');
const unique = <T>(values: readonly T[]) => new Set(values).size === values.length;
const parserVersion = z.string().min(1).max(32);
const count = z.number().int().nonnegative();
/** A stored body: `s3Key` is null when the body exceeded `body_size` and was not stored. */
const storedBody = z
  .object({ s3Key: s3Key.nullable(), sha256: sha256Hex, sizeBytes: count })
  .nullable();

/**
 * Published by the email-worker's MIME ingestion stage (step 3.1 M14) for the final statuses
 * `parsed`, `parsed_with_defects` and `parse_limit_exceeded`. Written through `message_outbox`
 * in the transaction that finalizes `email_message_parses` (`aggregate_type = 'message'`,
 * `aggregate_id` = decimal message id, `correlation_id` copied from the
 * `mail.message.received.v1` event). The envelope's `organizationId` is the message's
 * organization.
 *
 * Ids, keys, hashes, codes and counts only: never an address, the subject, a filename or a
 * header value. Consumers (scanning 4.x, lifecycle 3.3) read `email_attachments` and
 * `email_message_parses` from the writer.
 *
 * Consistency (M5, M6): `parse_limit_exceeded` iff `limitsExceeded` is non-empty;
 * `parsed_with_defects` has at least one defect; `parsed` has neither.
 */
export const messageParsedV1 = z
  .object({
    messageId: decimalIdSchema,
    receivedAt: z.iso.datetime(),
    direction,
    emlS3Key: s3Key,
    parseStatus: messageParseStatusSchema,
    parserVersion,
    /** Every limit hit, in order (M5). */
    limitsExceeded: z
      .array(mimeLimitNameSchema)
      .max(16)
      .refine(unique, { message: 'Duplicate limit name' }),
    /** `MIME_DEFECT_CODES` (M6, M7). */
    defects: z.array(code).max(64),
    textBody: storedBody,
    htmlBody: storedBody,
    attachmentCount: count,
    /** Attachments with at least one flag. */
    flaggedAttachmentCount: count,
    /** Union of `ATTACHMENT_FLAGS` over all attachments (M9, M10). */
    attachmentFlags: z.array(code).max(64).refine(unique, { message: 'Duplicate attachment flag' }),
    partCount: count,
    maxDepth: count,
    headerCount: count,
  })
  .superRefine((payload, ctx) => {
    const limited = payload.limitsExceeded.length > 0;
    if (limited !== (payload.parseStatus === 'parse_limit_exceeded')) {
      ctx.addIssue({
        code: 'custom',
        path: ['limitsExceeded'],
        message: 'parse_limit_exceeded requires limitsExceeded, and only it may carry them',
      });
    }
    if (payload.parseStatus === 'parsed_with_defects' && payload.defects.length === 0) {
      ctx.addIssue({
        code: 'custom',
        path: ['defects'],
        message: 'parsed_with_defects requires at least one defect',
      });
    }
    if (payload.parseStatus === 'parsed' && payload.defects.length > 0) {
      ctx.addIssue({ code: 'custom', path: ['defects'], message: 'parsed carries no defects' });
    }
    if (payload.flaggedAttachmentCount > payload.attachmentCount) {
      ctx.addIssue({
        code: 'custom',
        path: ['flaggedAttachmentCount'],
        message: 'flaggedAttachmentCount exceeds attachmentCount',
      });
    }
  });
export type MessageParsedV1 = z.infer<typeof messageParsedV1>;

/**
 * Published by the email-worker's MIME ingestion stage (step 3.1 M14) when a message ends
 * `parse_failed`: the EML is missing or not under the organization's prefix, its bytes do not
 * match the ingested SHA-256 and size, the poison-message guard tripped, or the parser failed.
 * Written through `message_outbox` like `mail.message.parsed.v1` (`aggregate_type = 'message'`,
 * correlation id copied from the received event). Ids, keys and codes only.
 */
export const messageParseFailedV1 = z.object({
  messageId: decimalIdSchema,
  receivedAt: z.iso.datetime(),
  direction,
  /**
   * The message's `eml_object_key`; null when that key is not organization-prefixed at all (an
   * `eml_key_mismatch` whose key cannot be carried in an event, so the failure still publishes).
   */
  emlS3Key: s3Key.nullable(),
  reason: parseFailureReasonSchema,
  /** Attempts started, including the failing one. */
  attempts: z.number().int().min(1),
  parserVersion,
});
export type MessageParseFailedV1 = z.infer<typeof messageParseFailedV1>;

export const EventTypes = {
  MessageReceived: 'mail.message.received.v1',
  MessageScanned: 'mail.message.scanned.v1',
  PolicyDecided: 'mail.policy.decided.v1',
  DomainStatusChanged: 'domain.status.changed.v1',
  DeliveryApproved: 'mail.delivery.approved.v1',
  DeliveryStatusChanged: 'mail.delivery.status_changed.v1',
  DomainRoutingChanged: 'domain.routing.changed.v1',
  MessageParsed: 'mail.message.parsed.v1',
  MessageParseFailed: 'mail.message.parse_failed.v1',
} as const;
