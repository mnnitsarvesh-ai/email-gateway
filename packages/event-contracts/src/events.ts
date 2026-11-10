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

/**
 * Standardized scan verdicts (step 4.1 S6, S7; ADR-0026), lower-case. Mirrors `SCAN_VERDICTS` of
 * `@email-gateway/security-contracts` (event-contracts has no dependency on it; the email-worker,
 * which depends on both, asserts that the lists are equal).
 */
export const SCAN_VERDICT_VALUES = [
  'clean',
  'spam',
  'suspicious',
  'malicious',
  'unknown',
  'timeout',
  'error',
] as const;
/** Per-engine outcomes: the verdicts plus `skipped` (mirrors `ENGINE_OUTCOMES`). */
export const ENGINE_OUTCOME_VALUES = [...SCAN_VERDICT_VALUES, 'skipped'] as const;
const scanVerdict = z.enum(SCAN_VERDICT_VALUES);
const engineOutcome = z.enum(ENGINE_OUTCOME_VALUES);
const FAILURE_VERDICTS: readonly string[] = ['timeout', 'error'];
/** Dotted reason code (`spam.score`, `auth.dmarc_reject`), mirrors `REASON_CODE_PATTERN`. */
const scanReasonCode = z
  .string()
  .max(64)
  .regex(/^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/, 'Expected a dotted lower-case reason code');

/**
 * Published by the email-worker scan stage (step 4.1 S5, S6) when a scan round completes: every
 * required engine of the round has a final result (or the round deadline finalized it). Written
 * through `message_outbox` (`aggregate_type = 'message'`, correlation copied from the triggering
 * `mail.message.parsed.v1` / `mail.message.rescan_requested.v1`) in the transaction that completes
 * the `email_scans` row and applies E6 (`scanned`) or E7 (`scan_failed`). Not written when the
 * round was superseded (stale transition). Bound to `email.policy.evaluate` (policy, 5.2) and the
 * `email.analytics` firehose; the dev pass-through reads it from the outbox.
 *
 * v1 was redefined in place by step 4.1: the step 3.2 placeholder (`scanIds`, `timedOutStages`)
 * never had a producer or a consumer.
 *
 * Content rules (§2.0 invariant 2): ids, the S3 key, codes, counts and times only. No symbol, no
 * symbol option, no address, no URL, no score: the object is strict, so a producer cannot add
 * such a field (a new field needs a new version). Consistency: `outcome = scanned` ⇒ no required
 * engine ended `timeout`/`error` and the verdict is not a failure; `outcome = scan_failed` ⇒ at
 * least one required engine ended `timeout`/`error`. Engine names are unique.
 */
export const messageScannedV1 = z
  .strictObject({
    messageId: decimalIdSchema,
    receivedAt: z.iso.datetime(),
    direction,
    emlS3Key: s3Key,
    lifecycleRound: z.number().int().min(0).max(65_535),
    /** `email_scans.id` of the round. */
    scanId: decimalIdSchema,
    scanKind: z.enum(['initial', 'rescan']),
    outcome: z.enum(['scanned', 'scan_failed']),
    /** Aggregate verdict of the round (`email_scans.scan_verdict`). */
    verdict: scanVerdict,
    engines: z
      .array(
        z.strictObject({
          engine: z.string().regex(/^[a-z][a-z0-9_]{0,31}$/, 'Expected an engine name'),
          required: z.boolean(),
          outcome: engineOutcome,
          /** Attempts of this engine in the round, the final one included. */
          attempts: z.number().int().min(1).max(65_535),
        }),
      )
      .min(1)
      .max(16),
    /** Union of the final results' reason codes (`email_scans.reason_codes`), at most 32. */
    reasonCodes: z.array(scanReasonCode).max(32),
    completedAt: z.iso.datetime(),
  })
  .superRefine((payload, ctx) => {
    const names = payload.engines.map((e) => e.engine);
    if (new Set(names).size !== names.length) {
      ctx.addIssue({ code: 'custom', path: ['engines'], message: 'Duplicate engine' });
    }
    if (new Set(payload.reasonCodes).size !== payload.reasonCodes.length) {
      ctx.addIssue({ code: 'custom', path: ['reasonCodes'], message: 'Duplicate reason code' });
    }
    const requiredFailure = payload.engines.some(
      (e) => e.required && FAILURE_VERDICTS.includes(e.outcome),
    );
    if (payload.outcome === 'scanned') {
      if (requiredFailure) {
        ctx.addIssue({
          code: 'custom',
          path: ['engines'],
          message: 'scanned requires every required engine to have a definite outcome',
        });
      }
      if (FAILURE_VERDICTS.includes(payload.verdict)) {
        ctx.addIssue({
          code: 'custom',
          path: ['verdict'],
          message: 'scanned cannot carry a timeout or error verdict',
        });
      }
    } else if (!requiredFailure) {
      ctx.addIssue({
        code: 'custom',
        path: ['outcome'],
        message: 'scan_failed requires at least one required engine with timeout or error',
      });
    }
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
  /**
   * Lifecycle round the approval belongs to (step 3.3 L7, L8.4; ADR-0025). Optional and
   * non-breaking: absent = 0. Written by the dev pass-through and the release from step 3.3 on;
   * the policy engine (5.2) must write it. The planner never plans an approval of another round.
   */
  lifecycleRound: z.number().int().min(0).max(65_535).optional(),
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

/**
 * Message lifecycle states (step 3.3 L2, ADR-0025), in rank/enum order: the values of
 * `email_messages.status` (Prisma `MessageStatus`). Defined once here (no dependency on the
 * lifecycle package); `@email-gateway/message-lifecycle` re-exports it and asserts that its
 * transition table and the Prisma enum use exactly these values.
 */
export const MESSAGE_STATES = [
  'received',
  'persisted',
  'scanning',
  'scanned',
  'scan_failed',
  'policy_evaluated',
  'approved',
  'quarantined',
  'held_for_review',
  'rejected',
  'delivery_pending',
  'delivery_retry',
  'delivered',
  'archived',
  'expired',
] as const;
export const messageStateSchema = z.enum(MESSAGE_STATES);
export type MessageStateValue = z.infer<typeof messageStateSchema>;

/**
 * Who applies a lifecycle transition (step 3.3 L3): ingestion (smtp-adapter), scanner (4.x),
 * policy (5.2), dev_passthrough (delivery-worker, local/ci only), delivery (planner and the shared
 * recorder), operator (api), quarantine (5.3), archive (8.1), sweeper (event-relay expiry) and
 * recovery (event-relay lifecycle check).
 */
export const ACTOR_ROLES = [
  'ingestion',
  'scanner',
  'policy',
  'dev_passthrough',
  'delivery',
  'operator',
  'quarantine',
  'archive',
  'sweeper',
  'recovery',
] as const;
export const actorRoleSchema = z.enum(ACTOR_ROLES);
export type ActorRoleValue = z.infer<typeof actorRoleSchema>;

const lifecycleRound = z.number().int().min(0).max(65_535);

/**
 * One applied message lifecycle transition (step 3.3 L5.1, L7), written by the transition service
 * of `@email-gateway/message-lifecycle` in the transaction of the transition, for every applied
 * transition except creation (`received`, `persisted`: `mail.message.received.v1` is the
 * notification of `persisted`). Through `message_outbox` (`aggregate_type = 'message'`,
 * `event_id` = `email_message_status_history.state_event_id`, `correlation_id` from the request or
 * `message:<id>`). Ids, states, codes and times only: no actor id, no address, no content.
 */
export const messageStateChangedV1 = z.object({
  messageId: decimalIdSchema,
  receivedAt: z.iso.datetime(),
  direction,
  /** `null` only for a transition out of creation (never published today). */
  previousState: messageStateSchema.nullable(),
  state: messageStateSchema,
  /** Message version after the transition. */
  version: z.number().int().nonnegative(),
  lifecycleRound,
  reasonCode: z.string().regex(/^[a-z0-9_]{1,64}$/, 'Expected a snake_case reason code'),
  actorRole: actorRoleSchema,
  actorType: z.enum(['system', 'user', 'api_key']),
  actorService: z.string().min(1).max(64),
  /** Envelope id of the event that caused the transition; null for api/sweeper actions. */
  causationEventId: z.uuid().nullable(),
  changedAt: z.iso.datetime(),
});
export type MessageStateChangedV1 = z.infer<typeof messageStateChangedV1>;

/**
 * An administrative rescan of a message's security pipeline (step 3.3 L10.2, edge E19), written
 * by the api through `message_outbox` (`aggregate_type = 'message'`) in the transaction that moves
 * the message to `scanning` with a new lifecycle round. Published to `email.security` and bound to
 * the five scan queues (dormant until 4.x). Consumers must check `lifecycleRound` against the
 * writer row before acting (a forged or stale request never scans another round).
 */
export const messageRescanRequestedV1 = z.object({
  messageId: decimalIdSchema,
  receivedAt: z.iso.datetime(),
  direction,
  emlS3Key: s3Key,
  /** The new round (a rescan always starts round ≥ 1). */
  lifecycleRound: z.number().int().min(1).max(65_535),
  scanKind: z.literal('rescan'),
  requestedAt: z.iso.datetime(),
  /**
   * Principal kind of the requester; the principal id stays in the audit row. `system` (step 4.2
   * A13): a rescan job of the signature-update detector in the email-worker (no human principal;
   * the lifecycle history records actor role `scanner`, reason `signature_rescan`).
   */
  requestedBy: z.enum(['user', 'api_key', 'system']),
});
export type MessageRescanRequestedV1 = z.infer<typeof messageRescanRequestedV1>;

/**
 * The true-file-type ids of the attachment engine (step 4.2 A5). Mirrors `FILE_TYPE_IDS` of
 * `@email-gateway/security-contracts` (event-contracts has no dependency on it; the email-worker,
 * which depends on both, asserts that the lists are equal, as for `SCAN_VERDICT_VALUES`).
 */
export const ATTACHMENT_FILE_TYPE_VALUES = [
  'pdf',
  'ooxml_word',
  'ooxml_excel',
  'ooxml_powerpoint',
  'ooxml_macro',
  'odf',
  'ole_office',
  'rtf',
  'chm',
  'zip',
  'gzip',
  'tar',
  '7z',
  'rar',
  'cab',
  'bzip2',
  'xz',
  'jar',
  'apk',
  'pe_executable',
  'msi',
  'elf',
  'macho',
  'lnk',
  'script_js',
  'script_vbs',
  'script_ps1',
  'script_batch',
  'script_shell',
  'hta',
  'iso',
  'vhd',
  'html',
  'svg',
  'xml',
  'png',
  'jpeg',
  'gif',
  'bmp',
  'webp',
  'tiff',
  'text',
  'ics',
  'eml',
  'unknown',
] as const;

/** Attachment verdicts that are submitted to the sandbox (step 4.2 A11). */
export const SANDBOX_ATTACHMENT_VERDICT_VALUES = ['suspicious', 'unknown'] as const;

/** An attachment part key: `org/{organizationId}/part/…` (step 3.1 M11). */
const partS3Key = z
  .string()
  .max(512)
  .regex(
    /^org\/[1-9][0-9]{0,19}\/part\/[A-Za-z0-9._/-]+$/,
    'Part keys are organization-prefixed (org/{organizationId}/part/…)',
  )
  .refine((key) => !key.split('/').includes('..'), { message: 'No .. segment in a part key' });

/**
 * A request to detonate one attachment in the sandbox (step 4.2 A2, A11; consumed from step 4.6).
 * Written by the email-worker's attachment engine through `message_outbox`
 * (`aggregate_type = 'attachment'`, `aggregate_id` = `sandbox_submissions.id`) in the finalize
 * transaction of the engine's final result, together with the `sandbox_submissions` row, for
 * every attachment whose verdict is `suspicious` or `unknown` and whose part object is stored
 * (at most `ATTACHMENT_SANDBOX_MAX_PER_MESSAGE` per message). Published to `email.security`
 * (`org.<id>.mail.attachment.sandbox_requested.v1`) and bound to `scan.sandbox.submissions` (topology
 * v8, step 4.6 X11: the email-worker's sandbox dispatcher; v4–v7 bound it to the dormant
 * `scan.sandbox`). The round never waits for the sandbox.
 *
 * Content rules (§2.0 invariant 2): ids, the part's S3 key, its hash, size, detected type, the
 * verdict and reason codes only. No filename, no content: the object is strict. Consumers must
 * check that the key's organization equals the envelope's `organizationId` before reading it.
 */
export const attachmentSandboxRequestedV1 = z
  .strictObject({
    /** `sandbox_submissions.id`. */
    submissionId: decimalIdSchema,
    messageId: decimalIdSchema,
    receivedAt: z.iso.datetime(),
    direction,
    /** `email_scans.id` of the round. */
    scanId: decimalIdSchema,
    lifecycleRound: z.number().int().min(0).max(65_535),
    attachment: z.strictObject({
      partIndex: z.number().int().min(0).max(65_535),
      sha256: z.string().regex(/^[0-9a-f]{64}$/, 'Expected a lower-case hex SHA-256'),
      sizeBytes: z.number().int().nonnegative(),
      detectedType: z.enum(ATTACHMENT_FILE_TYPE_VALUES),
      objectKey: partS3Key,
    }),
    attachmentVerdict: z.enum(SANDBOX_ATTACHMENT_VERDICT_VALUES),
    reasonCodes: z.array(scanReasonCode).min(1).max(16),
    requestedAt: z.iso.datetime(),
  })
  .superRefine((payload, ctx) => {
    if (new Set(payload.reasonCodes).size !== payload.reasonCodes.length) {
      ctx.addIssue({ code: 'custom', path: ['reasonCodes'], message: 'Duplicate reason code' });
    }
  });
export type AttachmentSandboxRequestedV1 = z.infer<typeof attachmentSandboxRequestedV1>;

/**
 * The organization of an `org/<id>/…` key, or null. Consumers of
 * `mail.attachment.sandbox_requested.v1` compare it with the envelope's `organizationId`.
 */
export function organizationIdOfKey(key: string): string | null {
  return /^org\/([1-9][0-9]{0,19})\//.exec(key)?.[1] ?? null;
}

/**
 * URL verdicts (step 4.3 U10). Mirrors `URL_VERDICTS` of `@email-gateway/security-contracts`
 * (event-contracts has no dependency on it; a consumer that depends on both asserts equality, as
 * for `SCAN_VERDICT_VALUES`).
 */
export const URL_VERDICT_VALUES = ['clean', 'suspicious', 'malicious', 'unknown'] as const;
/** Click decisions (step 4.3 U14). Mirrors `CLICK_DECISIONS` of security-contracts. */
export const CLICK_DECISION_VALUES = [
  'allowed',
  'warned',
  'blocked',
  'continued',
  'expired',
  'not_found',
] as const;
/** Kinds of a main-frame navigation recorded by the browser worker (step 4.3 U2). */
export const URL_NAVIGATION_KINDS = ['initial', 'http', 'js', 'meta'] as const;

/** Longest URL an event carries (U4 `URL_MAX_LENGTH`, after normalization). */
export const URL_EVENT_MAX_LENGTH = 2048;

const hasControlOrSpace = (value: string): boolean => {
  for (let i = 0; i < value.length; i += 1) {
    const c = value.charCodeAt(i);
    if (c <= 0x20 || c === 0x7f) return true;
  }
  return false;
};

/**
 * A normalized http(s) URL (U5 redirect form): absolute, `http:` or `https:`, no userinfo, no
 * whitespace or control characters, at most 2 048 characters.
 */
const normalizedHttpUrl = z
  .string()
  .min(1)
  .max(URL_EVENT_MAX_LENGTH)
  .refine((value) => /^https?:\/\//.test(value) && !hasControlOrSpace(value), {
    message: 'Expected a normalized http(s) URL',
  })
  .refine(
    (value) => {
      try {
        const url = new URL(value);
        return (
          (url.protocol === 'http:' || url.protocol === 'https:') &&
          url.username === '' &&
          url.password === '' &&
          url.hostname !== ''
        );
      } catch {
        return false;
      }
    },
    { message: 'Expected an absolute http(s) URL without userinfo' },
  );

/**
 * An ASCII host as WHATWG `URL.hostname` serializes it: a lower-case name (A-labels) or dotted
 * IPv4, or a bracketed IPv6 literal. At most 253 characters.
 */
export const URL_HOST_PATTERN =
  /^(?:(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*|\[[0-9a-f:.]{2,45}\])$/;
const urlHost = z.string().max(253).regex(URL_HOST_PATTERN, 'Expected an ASCII host');
/** A brand id of the protected brand list (`packages/url-security/data/brands.json`). */
const brandId = z.string().regex(/^[a-z0-9][a-z0-9_-]{0,31}$/, 'Expected a brand id');
/** A snake_case token (error codes). */
const token = z.string().regex(/^[a-z][a-z0-9_]{0,31}$/, 'Expected a snake_case token');
const urlSeq = z.number().int().min(0).max(65_535);
const boundedCount = (max: number) => z.number().int().min(0).max(max);
/** A software version for display (spaces allowed, no control characters), at most 64. */
const versionString = z
  .string()
  .min(1)
  .max(64)
  .refine((value) => [...value].every((c) => c.charCodeAt(0) >= 0x20 && c !== '\x7f'), {
    message: 'Expected a version string without control characters',
  });

/**
 * A request to inspect one URL in the isolated browser worker (step 4.3 U2, U15). Written by the
 * email-worker's URL engine through `message_outbox` (`aggregate_type = 'message'`) in the
 * finalize transaction of the engine's final result, together with the `url_dynamic_inspections`
 * row (`inspectionId` = its id). Published to `email.security`
 * (`org.<id>.mail.url.inspection_requested.v1`) and bound to `scan.url.inspect` (a bounded lossy
 * work queue). The round never waits for it.
 *
 * The only event that carries a URL (the browser worker has no database). Like every
 * `email.security` key it also reaches the `email.analytics` firehose: the analytics consumer
 * (not built) must drop or hash `url` (docs/architecture/data-ownership.md). No other content:
 * strict object.
 */
export const urlInspectionRequestedV1 = z
  .strictObject({
    /** `url_dynamic_inspections.id`. */
    inspectionId: decimalIdSchema,
    messageId: decimalIdSchema,
    receivedAt: z.iso.datetime(),
    /** `email_scans.id` of the round. */
    scanId: decimalIdSchema,
    lifecycleRound: z.number().int().min(0).max(65_535),
    /** `message_urls.url_seq`. */
    urlSeq,
    /** The URL to open (U5 redirect form, as stored in `message_urls.url`). */
    url: normalizedHttpUrl,
    /** SHA-256 of the identity form (`message_urls.url_sha256`). */
    urlSha256: sha256Hex,
    requestedAt: z.iso.datetime(),
    /** After this instant the worker publishes `failed`/`deadline_passed` without navigating. */
    deadlineAt: z.iso.datetime(),
  })
  .superRefine((payload, ctx) => {
    if (Date.parse(payload.deadlineAt) <= Date.parse(payload.requestedAt)) {
      ctx.addIssue({
        code: 'custom',
        path: ['deadlineAt'],
        message: 'deadlineAt must be after requestedAt',
      });
    }
  });
export type UrlInspectionRequestedV1 = z.infer<typeof urlInspectionRequestedV1>;

/**
 * The result of one browser inspection (step 4.3 U2, U15). Published by the url-browser-worker
 * **directly** (broker user `eg-url-browser`, publisher confirms; no outbox: the worker has no
 * database), routing key `org.<id>.mail.url.inspection_completed.v1` on `email.security`; the
 * request is acked only after the confirm. Bound to `scan.url.results` (ledger consumer
 * `email-worker.scan.url.results`), which applies it to the pending `url_dynamic_inspections` row
 * after echo-checking organization, message, `urlSeq` and `urlSha256` (a forged result cannot
 * create rows).
 *
 * Counts, booleans, hosts and brand ids only: no page body, no title text, no screenshot, no URL
 * (the final URL only as a hash and its host). `failed` carries an `errorCode`; `completed` none.
 */
export const urlInspectionCompletedV1 = z
  .strictObject({
    inspectionId: decimalIdSchema,
    messageId: decimalIdSchema,
    receivedAt: z.iso.datetime(),
    urlSeq,
    urlSha256: sha256Hex,
    status: z.enum(['completed', 'failed']),
    /** E.g. `navigation_timeout`, `proxy_refused`, `browser_crash`, `job_timeout`, `deadline_passed`. */
    errorCode: token.nullable(),
    workerVersion: versionString,
    browserVersion: versionString,
    finalUrlSha256: sha256Hex.nullable(),
    finalHost: urlHost.nullable(),
    /** Main-frame navigations and redirect responses, in order. */
    navigations: z
      .array(
        z.strictObject({
          host: urlHost,
          status: z.number().int().min(100).max(599).nullable(),
          kind: z.enum(URL_NAVIGATION_KINDS),
        }),
      )
      .max(10),
    signals: z.strictObject({
      passwordFields: boundedCount(1000),
      forms: boundedCount(1000),
      crossOriginFormAction: z.boolean(),
      formActionHosts: z.array(urlHost).max(5),
      downloadAttempted: z.boolean(),
      blockedRequests: boundedCount(100_000),
      requests: boundedCount(100_000),
      bytes: z.number().int().nonnegative(),
      titleBrandMatches: z.array(brandId).max(5),
      jsRedirect: z.boolean(),
      dialogs: boundedCount(1000),
    }),
    durationMs: z.number().int().nonnegative(),
    completedAt: z.iso.datetime(),
  })
  .superRefine((payload, ctx) => {
    if (payload.status === 'failed' && payload.errorCode === null) {
      ctx.addIssue({ code: 'custom', path: ['errorCode'], message: 'failed requires errorCode' });
    }
    if (payload.status === 'completed' && payload.errorCode !== null) {
      ctx.addIssue({
        code: 'custom',
        path: ['errorCode'],
        message: 'completed carries no errorCode',
      });
    }
    if ((payload.finalUrlSha256 === null) !== (payload.finalHost === null)) {
      ctx.addIssue({
        code: 'custom',
        path: ['finalHost'],
        message: 'finalUrlSha256 and finalHost are both set or both null',
      });
    }
    const unique = <T>(values: readonly T[]) => new Set(values).size === values.length;
    if (!unique(payload.signals.formActionHosts)) {
      ctx.addIssue({
        code: 'custom',
        path: ['signals', 'formActionHosts'],
        message: 'Duplicate host',
      });
    }
    if (!unique(payload.signals.titleBrandMatches)) {
      ctx.addIssue({
        code: 'custom',
        path: ['signals', 'titleBrandMatches'],
        message: 'Duplicate brand id',
      });
    }
  });
export type UrlInspectionCompletedV1 = z.infer<typeof urlInspectionCompletedV1>;

/**
 * One decided click of a rewritten link (step 4.3 U2, U14). Written by the click-service through
 * `message_outbox` (`aggregate_type = 'message'`, its own MySQL account) in the transaction of
 * the `url_click_events` row (`clickId` = its `public_id`, UUIDv7). Published to
 * `email.security`; no queue binding: it reaches only the `email.analytics` firehose. No URL, no
 * client address, no user identity (strict object). `expired` and `not_found` carry no verdict
 * (the URL was not evaluated).
 */
export const urlClickedV1 = z
  .strictObject({
    clickId: z.uuid(),
    messageId: decimalIdSchema,
    receivedAt: z.iso.datetime(),
    urlSeq,
    decision: z.enum(CLICK_DECISION_VALUES),
    verdict: z.enum(URL_VERDICT_VALUES).nullable(),
    reasonCodes: z.array(scanReasonCode).max(16),
    clickedAt: z.iso.datetime(),
  })
  .superRefine((payload, ctx) => {
    if (new Set(payload.reasonCodes).size !== payload.reasonCodes.length) {
      ctx.addIssue({ code: 'custom', path: ['reasonCodes'], message: 'Duplicate reason code' });
    }
    if ((payload.decision === 'expired' || payload.decision === 'not_found') && payload.verdict) {
      ctx.addIssue({
        code: 'custom',
        path: ['verdict'],
        message: `${payload.decision} carries no verdict`,
      });
    }
  });
export type UrlClickedV1 = z.infer<typeof urlClickedV1>;

/**
 * The second-stage trigger of a scan round (step 4.4 B2, ADR-0033): every dependency of the
 * stage-2 engine `engine` that is in the round's required set has its final row (definite or
 * failure). Written by the email-worker scan stage through `message_outbox`
 * (`aggregate_type = 'message'`) exactly once per (round, engine), in the `ScanRepository.complete()`
 * transaction that inserts the last dependency final (both locks held). Published to
 * `email.security` (`org.<id>.mail.message.scan_stage_ready.v1`) and bound only to the stage-2
 * engine's queue (topology v6: `scan.bec`); also reaches the `email.analytics` firehose.
 *
 * Consumers check `lifecycleRound` and `scanId` against the writer rows (the round's
 * `email_scans` row must exist with this id; a stage trigger never opens a round) and ignore a
 * trigger whose `engine` is not theirs. Ids, codes, the S3 key and times only (content guard):
 * strict object, dependency engines unique and never the triggered engine itself.
 */
export const messageScanStageReadyV1 = z
  .strictObject({
    messageId: decimalIdSchema,
    receivedAt: z.iso.datetime(),
    direction,
    emlS3Key: s3Key,
    lifecycleRound: z.number().int().min(0).max(65_535),
    /** `email_scans.id` of the round. */
    scanId: decimalIdSchema,
    scanKind: z.enum(['initial', 'rescan']),
    /** The stage-2 engine to run (an engine name, `scan_engine_results.engine`). */
    engine: z.string().regex(/^[a-z][a-z0-9_]{0,31}$/, 'Expected an engine name'),
    /** The dependency finals that made the stage ready: engine and final outcome. */
    dependencies: z
      .array(
        z.strictObject({
          engine: z.string().regex(/^[a-z][a-z0-9_]{0,31}$/, 'Expected an engine name'),
          outcome: engineOutcome,
        }),
      )
      .min(1)
      .max(8),
    readyAt: z.iso.datetime(),
  })
  .superRefine((payload, ctx) => {
    const names = payload.dependencies.map((d) => d.engine);
    if (new Set(names).size !== names.length) {
      ctx.addIssue({ code: 'custom', path: ['dependencies'], message: 'Duplicate engine' });
    }
    if (names.includes(payload.engine)) {
      ctx.addIssue({
        code: 'custom',
        path: ['dependencies'],
        message: 'An engine is never its own dependency',
      });
    }
    if (payload.scanKind === 'initial' && payload.lifecycleRound !== 0) {
      ctx.addIssue({
        code: 'custom',
        path: ['scanKind'],
        message: 'initial scans are round 0; rescans are rounds >= 1',
      });
    }
    if (payload.scanKind === 'rescan' && payload.lifecycleRound === 0) {
      ctx.addIssue({
        code: 'custom',
        path: ['scanKind'],
        message: 'initial scans are round 0; rescans are rounds >= 1',
      });
    }
  });
export type MessageScanStageReadyV1 = z.infer<typeof messageScanStageReadyV1>;

/**
 * DLP actions an incident can carry (step 4.5 D11, D13, D14): every action of `DLP_ACTIONS`
 * (`@email-gateway/security-contracts`) except `allow`, which never writes an incident.
 */
export const DLP_INCIDENT_ACTION_VALUES = [
  'alert',
  'require_approval',
  'quarantine',
  'block',
] as const;
/** Where an incident's action came from (`DLP_ACTION_SOURCES` without `none`). */
export const DLP_INCIDENT_ACTION_SOURCE_VALUES = ['tenant_policy', 'default_policy'] as const;
/** Severity of a DLP category aggregate (mirrors `DLP_SEVERITIES`). */
export const DLP_SEVERITY_VALUES = ['info', 'low', 'medium', 'high', 'critical'] as const;

/**
 * A DLP incident (step 4.5 D14, ADR-0037): the `dlp` engine's tenant policy yielded an effective
 * action other than `allow` for one scan round. Written by the email-worker scan stage through
 * `message_outbox` (`aggregate_type = 'message'`) in the transaction that inserts the round's dlp
 * final row and its `dlp_scan_results` row, only when the final row was inserted (once per round,
 * idempotent with the final row). Published to `email.security`
 * (`org.<id>.mail.message.dlp_incident.v1`); **no queue binds it in step 4.5**: it reaches only
 * the `email.analytics` firehose; the notification-worker binds it in step 6.2.
 *
 * Content rules (§2.0 invariant 2, content guard): ids, codes, counts and times only. No address,
 * no matched value, no masked sample, no policy / rule / pattern / dictionary name, no term: the
 * objects are strict, so a producer cannot add such a field. `policyId` / `ruleId` are the
 * winning rule's public ids (UUIDv7) for a tenant policy and null for the platform default
 * policy. `detectorCodes` are the DLP reason codes (`dlp.*`, `DLP_REASON_CODES`) of the findings
 * and coverage reasons the winning rule selected; categories and codes are unique. `categories`
 * is empty only for a **coverage-only** incident (a rule that selected `coverageReasons`, with no
 * finding): then `coverage` is `partial` and `detectorCodes` holds the coverage codes.
 */
export const messageDlpIncidentV1 = z
  .strictObject({
    messageId: decimalIdSchema,
    receivedAt: z.iso.datetime(),
    direction,
    lifecycleRound: z.number().int().min(0).max(65_535),
    /** `email_scans.id` of the round. */
    scanId: decimalIdSchema,
    action: z.enum(DLP_INCIDENT_ACTION_VALUES),
    actionSource: z.enum(DLP_INCIDENT_ACTION_SOURCE_VALUES),
    /** Public id of the winning policy (`dlp_policies.public_id`); null for the default policy. */
    policyId: z.uuid().nullable(),
    /** Public id of the winning rule (`dlp_policy_rules.public_id`); null for the default policy. */
    ruleId: z.uuid().nullable(),
    /** Per-category aggregates (`DLP_CATEGORIES`), counts of distinct values only. */
    categories: z
      .array(
        z.strictObject({
          category: z
            .string()
            .regex(/^[a-z][a-z_]{1,31}$/, 'Expected a dotless lower-case category'),
          count: z.number().int().min(0).max(1_000_000),
          maxSeverity: z.enum(DLP_SEVERITY_VALUES),
        }),
      )
      .max(10),
    detectorCodes: z.array(scanReasonCode).min(1).max(24),
    exceptionApplied: z.boolean(),
    coverage: z.enum(['complete', 'partial']),
    /** An encrypted evidence object was stored for the round (`dlp_evidence`). */
    evidenceAvailable: z.boolean(),
    detectedAt: z.iso.datetime(),
  })
  .superRefine((payload, ctx) => {
    if (payload.categories.length === 0 && payload.coverage !== 'partial') {
      // A rule that matched on coverage reasons only (e.g. hold encrypted archives) has no
      // category; with complete coverage some category must have matched.
      ctx.addIssue({
        code: 'custom',
        path: ['categories'],
        message: 'An incident without a category must have partial coverage',
      });
    }
    const categories = payload.categories.map((c) => c.category);
    if (new Set(categories).size !== categories.length) {
      ctx.addIssue({ code: 'custom', path: ['categories'], message: 'Duplicate category' });
    }
    if (new Set(payload.detectorCodes).size !== payload.detectorCodes.length) {
      ctx.addIssue({ code: 'custom', path: ['detectorCodes'], message: 'Duplicate reason code' });
    }
    payload.detectorCodes.forEach((code, index) => {
      if (!code.startsWith('dlp.')) {
        ctx.addIssue({
          code: 'custom',
          path: ['detectorCodes', index],
          message: 'Expected a DLP reason code (dlp.*)',
        });
      }
    });
    const tenant = payload.actionSource === 'tenant_policy';
    for (const field of ['policyId', 'ruleId'] as const) {
      if (tenant && payload[field] === null) {
        ctx.addIssue({
          code: 'custom',
          path: [field],
          message: 'A tenant policy incident names its winning policy and rule',
        });
      }
      if (!tenant && payload[field] !== null) {
        ctx.addIssue({
          code: 'custom',
          path: [field],
          message: 'The default policy has no policy or rule id',
        });
      }
    }
  });
export type MessageDlpIncidentV1 = z.infer<typeof messageDlpIncidentV1>;

// ---------------------------------------------------------------------------------------------
// Sandbox (step 4.6, docs/plan/steps/14-sandbox.md §4, X11; ADR-0039, ADR-0040)
// ---------------------------------------------------------------------------------------------

/**
 * Sandbox vocabularies. Mirror the lists of `@email-gateway/security-contracts` `sandbox.ts`
 * (event-contracts has no dependency on it; `@email-gateway/sandbox`, which depends on both,
 * asserts that the lists are equal).
 */
export const SANDBOX_PROFILE_VALUES = ['static', 'execute', 'browser'] as const;
export const SANDBOX_BACKEND_VALUES = ['disabled', 'static', 'hardened-container', 'vm'] as const;
export const SANDBOX_ISOLATION_VALUES = ['none', 'process', 'container', 'vm'] as const;
export const SANDBOX_VERDICT_VALUES = [
  'clean',
  'suspicious',
  'malicious',
  'unknown',
  'error',
  'timeout',
] as const;
export const SANDBOX_TASK_STATUS_VALUES = ['completed', 'not_executed', 'failed'] as const;
/** Terminal statuses of a submission announced by `mail.attachment.sandbox_completed.v1`. */
export const SANDBOX_COMPLETION_STATUS_VALUES = [
  'completed',
  'skipped',
  'failed',
  'expired',
] as const;
export const SANDBOX_FINDING_SEVERITY_VALUES = [
  'info',
  'low',
  'medium',
  'high',
  'critical',
] as const;
export const SANDBOX_ARTIFACT_KIND_VALUES = [
  'screenshot',
  'process_log',
  'network_log',
  'static_report',
  'dropped_file',
] as const;
export const SANDBOX_ARTIFACT_CONTENT_TYPE_VALUES = [
  'image/png',
  'text/plain',
  'application/json',
  'application/octet-stream',
] as const;
/** The content type of each artifact kind (mirrors `ARTIFACT_KIND_CONTENT_TYPE`). */
const ARTIFACT_KIND_CONTENT_TYPE: Readonly<
  Record<
    (typeof SANDBOX_ARTIFACT_KIND_VALUES)[number],
    (typeof SANDBOX_ARTIFACT_CONTENT_TYPE_VALUES)[number]
  >
> = {
  screenshot: 'image/png',
  process_log: 'text/plain',
  network_log: 'text/plain',
  static_report: 'application/json',
  dropped_file: 'application/octet-stream',
};
/** The isolation class of each backend (mirrors `SANDBOX_BACKEND_ISOLATION`). */
const BACKEND_ISOLATION: Readonly<
  Record<(typeof SANDBOX_BACKEND_VALUES)[number], (typeof SANDBOX_ISOLATION_VALUES)[number]>
> = { disabled: 'none', static: 'process', 'hardened-container': 'container', vm: 'vm' };
/** Backends that can execute a sample (X3). */
const EXECUTING_BACKENDS: readonly string[] = ['hardened-container', 'vm'];
/** Largest sample (64 MiB, X17). */
export const SANDBOX_MAX_SAMPLE_BYTES = 67_108_864;
export const SANDBOX_ARTIFACT_ALGORITHM_VALUE = 'sandbox-artifact/1';

const sandboxSeverity = z.enum(SANDBOX_FINDING_SEVERITY_VALUES);
const sandboxBounded = (min: number, max: number) => z.number().int().min(min).max(max);
const sandboxCounter = sandboxBounded(0, 1_000_000);
const sandboxPort = sandboxBounded(1, 65_535);
const isoInstant = z.iso.datetime();

/**
 * A canonical IP literal: dotted-quad IPv4 without leading zeros, or IPv6 as WHATWG serializes
 * it (lower case, compressed, no brackets, no zone).
 */
function isCanonicalIpLiteral(value: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
    return value.split('.').every((o) => o === String(Number(o)) && Number(o) <= 255);
  }
  if (!/^[0-9a-f:.]{2,45}$/.test(value) || !value.includes(':')) return false;
  try {
    return new URL(`http://[${value}]/`).hostname === `[${value}]`;
  } catch {
    return false;
  }
}
const canonicalIp = z
  .string()
  .max(45)
  .refine(isCanonicalIpLiteral, { message: 'Expected a canonical IP literal' });
/** A dotted finding code (`static.eicar_test`, `behaviour.metadata_access`), ≤ 64. */
const sandboxFindingCode = z
  .string()
  .max(64)
  .regex(/^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/, 'Expected a dotted lower-case finding code');
/** A sandbox reason code (`sandbox.*`), ≤ 64. */
const sandboxReasonCode = scanReasonCode.refine((value) => value.startsWith('sandbox.'), {
  message: 'Expected a sandbox reason code (sandbox.*)',
});
const sandboxReasonCodes = z
  .array(sandboxReasonCode)
  .max(16)
  .refine(unique, { message: 'Duplicate reason code' });

/** The task limits (X2 `TaskLimits`), bounded as `SANDBOX_TASK_LIMIT_BOUNDS`. */
const sandboxTaskLimits = z.strictObject({
  wallTimeoutMs: sandboxBounded(5_000, 600_000),
  memoryMb: sandboxBounded(64, 4_096),
  cpuMillis: sandboxBounded(100, 4_000),
  pids: sandboxBounded(16, 1_024),
  scratchMb: sandboxBounded(8, 1_024),
  maxArtifacts: sandboxBounded(0, 16),
  maxArtifactBytes: sandboxBounded(1, 8_388_608),
  maxTotalArtifactBytes: sandboxBounded(1, 33_554_432),
});

/** `samples/<yyyy>/<mm>/<taskId>.bin` (X12). */
const SAMPLE_KEY_PATTERN = /^samples\/\d{4}\/\d{2}\/([0-9a-f-]{36})\.bin$/;
/** `artifacts/<yyyy>/<mm>/<taskId>/<runId>/<seq>-<kind>.bin` (X12; runId: 16 hex per run). */
const ARTIFACT_KEY_PATTERN =
  /^artifacts\/\d{4}\/\d{2}\/([0-9a-f-]{36})\/([0-9a-f]{16})\/(\d{1,2})-([a-z_]+)\.bin$/;
/** The sealed one-time result token `t1.<iv>.<tag>.<ct>` (X11; base64url parts of 12, 16, 32 bytes). */
const SEALED_RESULT_TOKEN_PATTERN = /^t1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/;

/**
 * A sandbox task (step 4.6 X11, X13): one analysis of one staged sample, for the
 * `sandbox-controller`. Written by the email-worker's sandbox dispatcher through
 * `message_outbox` (`aggregate_type = 'sandbox_analysis'`, `aggregate_id` =
 * `sandbox_analyses.id`, organization = the analysis's dispatching organization) in the
 * transaction that marks the analysis `dispatched`. Published to `email.security`
 * (`org.<id>.mail.sandbox.task_requested.v1`), bound to `scan.sandbox` (bounded lossy work queue,
 * stateless consumer); also reaches the `email.analytics` firehose.
 *
 * Nothing secret in clear and no content (the task reaches the firehose): the sealed sample's key
 * in the sandbox bucket (the key embeds the task id), its plaintext hash, size and detected type,
 * the profile, the limits, the deadline and the task's one-time result token **sealed** under a
 * subkey of `SANDBOX_RESULT_KEY` (AAD bound to the task id; only its SHA-256 is stored on the
 * analysis). The controller opens it and authenticates its result with it (X11). Strict object.
 */
export const sandboxTaskRequestedV1 = z
  .strictObject({
    /** `sandbox_analyses.public_id` (UUIDv7). */
    taskId: z.uuid(),
    /** `sandbox_analyses.id`. */
    analysisId: decimalIdSchema,
    sample: z.strictObject({
      key: z
        .string()
        .max(512)
        .regex(SAMPLE_KEY_PATTERN, 'Expected samples/<yyyy>/<mm>/<taskId>.bin'),
      sha256: sha256Hex,
      sizeBytes: sandboxBounded(1, SANDBOX_MAX_SAMPLE_BYTES),
      detectedType: z.enum(ATTACHMENT_FILE_TYPE_VALUES),
    }),
    profile: z.enum(SANDBOX_PROFILE_VALUES),
    limits: sandboxTaskLimits,
    requestedAt: isoInstant,
    /** After this instant the controller answers `not_executed`/`deadline_passed` without a run. */
    deadlineAt: isoInstant,
    /** The sealed one-time result token (X11), `t1.<iv>.<tag>.<ct>`. */
    resultToken: z
      .string()
      .regex(SEALED_RESULT_TOKEN_PATTERN, 'Expected a sealed result token (t1.<iv>.<tag>.<ct>)'),
  })
  .superRefine((payload, ctx) => {
    if (SAMPLE_KEY_PATTERN.exec(payload.sample.key)?.[1] !== payload.taskId) {
      ctx.addIssue({
        code: 'custom',
        path: ['sample', 'key'],
        message: 'The sample key must embed the task id',
      });
    }
    if (Date.parse(payload.deadlineAt) <= Date.parse(payload.requestedAt)) {
      ctx.addIssue({
        code: 'custom',
        path: ['deadlineAt'],
        message: 'deadlineAt must be after requestedAt',
      });
    }
  });
export type SandboxTaskRequestedV1 = z.infer<typeof sandboxTaskRequestedV1>;

const sandboxObservations = z.strictObject({
  processes: z
    .array(
      z.strictObject({
        seq: sandboxBounded(0, 63),
        parentSeq: sandboxBounded(0, 63).nullable(),
        image: z.string().regex(/^[A-Za-z0-9._+-]{1,64}$/, 'Expected an image basename'),
        argvSha256: sha256Hex.nullable(),
        exitCode: z.number().int().min(-2_147_483_648).max(2_147_483_647).nullable(),
        killedBy: z.enum(['timeout', 'memory', 'pids']).nullable(),
      }),
    )
    .max(32),
  processCount: sandboxCounter,
  network: z.strictObject({
    dns: z
      .array(
        z.strictObject({
          name: urlHost,
          type: z.enum(['A', 'AAAA', 'MX', 'TXT', 'other']),
          source: z.enum(['sinkhole', 'static']),
        }),
      )
      .max(50),
    http: z
      .array(
        z.strictObject({
          host: urlHost,
          port: sandboxPort,
          method: z.enum(['GET', 'POST', 'HEAD', 'PUT', 'OTHER']),
          pathSha256: sha256Hex,
          userAgentSha256: sha256Hex.nullable(),
        }),
      )
      .max(50),
    tls: z.array(z.strictObject({ sni: urlHost, port: sandboxPort })).max(50),
    connections: z
      .array(
        z.strictObject({
          ip: canonicalIp,
          port: sandboxPort,
          protocol: z.enum(['tcp', 'udp']),
          outcome: z.enum(['refused', 'unreachable', 'sinkhole', 'timeout']),
        }),
      )
      .max(50),
    totals: z.strictObject({
      dns: sandboxCounter,
      http: sandboxCounter,
      tls: sandboxCounter,
      connections: sandboxCounter,
    }),
  }),
  files: z.strictObject({
    dropped: z
      .array(
        z.strictObject({
          seq: sandboxBounded(0, 65_535),
          sha256: sha256Hex,
          sizeBytes: count,
          typeHint: z.enum(ATTACHMENT_FILE_TYPE_VALUES),
        }),
      )
      .max(32),
    deniedWrites: sandboxCounter,
  }),
  findings: z
    .array(
      z.strictObject({
        code: sandboxFindingCode,
        severity: sandboxSeverity,
        count: sandboxBounded(1, 1_000_000),
      }),
    )
    .max(32),
  limitsHit: z.array(token).max(8),
  browser: z
    .strictObject({
      navigations: sandboxCounter,
      requests: sandboxCounter,
      downloadsAttempted: sandboxCounter,
      dialogs: sandboxCounter,
      passwordFields: sandboxCounter,
      forms: sandboxCounter,
    })
    .nullable(),
});

/**
 * The result of one sandbox task (step 4.6 X7, X11). Published by the `sandbox-controller`
 * **directly** (broker user `eg-sandbox`, publisher confirms; no outbox: the controller has no
 * database), routing key `org.<id>.mail.sandbox.task_completed.v1` on `email.security`; the
 * task is acked only after the confirm. Bound to `scan.sandbox.results` (ledger consumer
 * `email-worker.scan.sandbox.results`), which applies it to the dispatched `sandbox_analyses` row
 * after checking the result MAC — HMAC-SHA256 under a subkey of `SANDBOX_RESULT_KEY` over the
 * SHA-256 of the task's one-time result token, the envelope organization and the canonical JSON
 * of this whole payload without `resultMac` (X11; `@email-gateway/sandbox` `resultMac`) — and the
 * analysis id, organization, hash and the artifact key prefix. A modified body or a result for a
 * task its sender never received does not verify. Also reaches the analytics firehose.
 *
 * Codes, counts, hashes, sizes, types, host names and canonical IPs of observed indicators,
 * process image basenames and sealed artifact references only: no file names, no paths, no URLs,
 * no content (strict object). The controller never produces a verdict (`sandbox-map/1` runs in
 * the email-worker). `failed` carries an `errorCode`, `not_executed` a `notExecutedReason`,
 * `completed` neither; the isolation class is the backend's; only an executing backend can
 * report `executed: true`.
 */
export const sandboxTaskCompletedV1 = z
  .strictObject({
    taskId: z.uuid(),
    analysisId: decimalIdSchema,
    sampleSha256: sha256Hex,
    /** Hex HMAC-SHA256 over the token hash, organization and the whole payload (X11). */
    resultMac: sha256Hex,
    status: z.enum(SANDBOX_TASK_STATUS_VALUES),
    notExecutedReason: token.nullable(),
    errorCode: token.nullable(),
    backend: z.enum(SANDBOX_BACKEND_VALUES),
    backendVersion: versionString,
    isolation: z.enum(SANDBOX_ISOLATION_VALUES),
    executed: z.boolean(),
    profile: z.enum(SANDBOX_PROFILE_VALUES),
    controllerVersion: versionString,
    analyzerVersion: versionString.nullable(),
    startedAt: isoInstant,
    completedAt: isoInstant,
    durationMs: z.number().int().nonnegative().max(86_400_000),
    observations: sandboxObservations,
    artifacts: z
      .array(
        z.strictObject({
          seq: sandboxBounded(0, 15),
          kind: z.enum(SANDBOX_ARTIFACT_KIND_VALUES),
          contentType: z.enum(SANDBOX_ARTIFACT_CONTENT_TYPE_VALUES),
          key: z.string().max(512).regex(ARTIFACT_KEY_PATTERN, 'Expected an artifact key'),
          /** SHA-256 of the sealed object. */
          objectSha256: sha256Hex,
          /** SHA-256 of the plaintext artifact. */
          plainSha256: sha256Hex,
          sizeBytes: sandboxBounded(0, 8_388_608),
          /** `x1.<kid>.<ephemeralPub>.<iv>.<tag>.<ct>` (base64url). */
          wrappedKey: z
            .string()
            .max(256)
            .regex(/^x1\.[a-z0-9]{1,8}(\.[A-Za-z0-9_-]+){4}$/, 'Expected an x1 wrapped key'),
          keyId: z.string().regex(/^[a-z0-9]{1,16}$/, 'Expected a key id'),
          algorithm: z.literal(SANDBOX_ARTIFACT_ALGORITHM_VALUE),
        }),
      )
      .max(16),
    cleanup: z.strictObject({
      runnerRemoved: z.boolean().nullable(),
      scratchRemoved: z.boolean(),
    }),
  })
  .superRefine((payload, ctx) => {
    const issue = (path: (string | number)[], message: string) =>
      ctx.addIssue({ code: 'custom', path, message });
    if ((payload.status === 'failed') !== (payload.errorCode !== null)) {
      issue(['errorCode'], 'failed requires errorCode; other statuses carry none');
    }
    if ((payload.status === 'not_executed') !== (payload.notExecutedReason !== null)) {
      issue(
        ['notExecutedReason'],
        'not_executed requires notExecutedReason; other statuses carry none',
      );
    }
    if (payload.status === 'not_executed' && payload.executed) {
      issue(['executed'], 'not_executed cannot have executed the sample');
    }
    if (payload.executed && !EXECUTING_BACKENDS.includes(payload.backend)) {
      issue(['executed'], `backend ${payload.backend} never executes a sample`);
    }
    if (BACKEND_ISOLATION[payload.backend] !== payload.isolation) {
      issue(
        ['isolation'],
        `the isolation of backend ${payload.backend} is ${BACKEND_ISOLATION[payload.backend]}`,
      );
    }
    if (Date.parse(payload.completedAt) < Date.parse(payload.startedAt)) {
      issue(['completedAt'], 'completedAt must not be before startedAt');
    }
    const o = payload.observations;
    if (!unique(o.findings.map((f) => f.code)))
      issue(['observations', 'findings'], 'Duplicate finding code');
    if (!unique(o.limitsHit)) issue(['observations', 'limitsHit'], 'Duplicate limit');
    if (!unique(o.processes.map((p) => p.seq))) {
      issue(['observations', 'processes'], 'Duplicate process seq');
    }
    if (!unique(payload.artifacts.map((a) => a.seq)))
      issue(['artifacts'], 'Duplicate artifact seq');
    const runIds = new Set(payload.artifacts.map((a) => ARTIFACT_KEY_PATTERN.exec(a.key)?.[2]));
    if (runIds.size > 1) issue(['artifacts'], 'The artifacts of one result belong to one run');
    payload.artifacts.forEach((artifact, index) => {
      const match = ARTIFACT_KEY_PATTERN.exec(artifact.key);
      if (
        match?.[1] !== payload.taskId ||
        Number(match[3]) !== artifact.seq ||
        match[4] !== artifact.kind
      ) {
        issue(['artifacts', index, 'key'], 'The artifact key must embed the task id, seq and kind');
      }
      if (ARTIFACT_KIND_CONTENT_TYPE[artifact.kind] !== artifact.contentType) {
        issue(
          ['artifacts', index, 'contentType'],
          `The content type of ${artifact.kind} is ${ARTIFACT_KIND_CONTENT_TYPE[artifact.kind]}`,
        );
      }
      if (artifact.wrappedKey.split('.')[1] !== artifact.keyId) {
        issue(['artifacts', index, 'keyId'], 'The wrapped key names another key id');
      }
    });
  });
export type SandboxTaskCompletedV1 = z.infer<typeof sandboxTaskCompletedV1>;

/**
 * One sandbox submission reached a terminal state (step 4.6 X15): completed from its analysis,
 * skipped (tenant not opted in, plan feature off, type or size excluded, part unavailable),
 * failed or expired. Written by the email-worker's sandbox finalizer through `message_outbox`
 * (`aggregate_type = 'attachment'`, `aggregate_id` = `sandbox_submissions.id`, the submission's
 * organization) in the transaction that changes the submission. Published to `email.security`;
 * **no queue binds it in 4.6**: it reaches only the `email.analytics` firehose until policy (5.x)
 * and post-delivery remediation bind it. Ids, codes and times only (strict object).
 */
export const attachmentSandboxCompletedV1 = z
  .strictObject({
    submissionId: decimalIdSchema,
    messageId: decimalIdSchema,
    receivedAt: isoInstant,
    scanId: decimalIdSchema,
    lifecycleRound: z.number().int().min(0).max(65_535),
    partIndex: z.number().int().min(0).max(65_535),
    sha256: sha256Hex,
    status: z.enum(SANDBOX_COMPLETION_STATUS_VALUES),
    verdict: z.enum(SANDBOX_VERDICT_VALUES).nullable(),
    reasonCodes: sandboxReasonCodes,
    executed: z.boolean(),
    isolation: z.enum(SANDBOX_ISOLATION_VALUES).nullable(),
    completedAt: isoInstant,
  })
  .superRefine((payload, ctx) => {
    const issue = (path: string, message: string) =>
      ctx.addIssue({ code: 'custom', path: [path], message });
    switch (payload.status) {
      case 'skipped':
        if (payload.verdict !== null) issue('verdict', 'skipped carries no verdict');
        if (payload.isolation !== null) issue('isolation', 'skipped carries no isolation');
        if (payload.executed) issue('executed', 'skipped never executed');
        break;
      case 'completed':
        if (payload.verdict === null) issue('verdict', 'completed requires a verdict');
        break;
      case 'expired':
        if (payload.verdict !== null && payload.verdict !== 'timeout') {
          issue('verdict', 'expired carries verdict timeout or none');
        }
        break;
      case 'failed':
        if (payload.verdict !== null && payload.verdict !== 'error') {
          issue('verdict', 'failed carries verdict error or none');
        }
        break;
    }
    if (payload.verdict === 'clean' && payload.isolation !== 'vm') {
      issue('verdict', 'clean requires vm isolation (sandbox-map/1 C1)');
    }
  });
export type AttachmentSandboxCompletedV1 = z.infer<typeof attachmentSandboxCompletedV1>;

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
  MessageStateChanged: 'mail.message.state_changed.v1',
  MessageRescanRequested: 'mail.message.rescan_requested.v1',
  AttachmentSandboxRequested: 'mail.attachment.sandbox_requested.v1',
  UrlInspectionRequested: 'mail.url.inspection_requested.v1',
  UrlInspectionCompleted: 'mail.url.inspection_completed.v1',
  UrlClicked: 'mail.url.clicked.v1',
  MessageScanStageReady: 'mail.message.scan_stage_ready.v1',
  MessageDlpIncident: 'mail.message.dlp_incident.v1',
  SandboxTaskRequested: 'mail.sandbox.task_requested.v1',
  SandboxTaskCompleted: 'mail.sandbox.task_completed.v1',
  AttachmentSandboxCompleted: 'mail.attachment.sandbox_completed.v1',
} as const;
