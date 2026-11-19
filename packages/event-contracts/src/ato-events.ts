import { z } from 'zod';
import { decimalIdSchema } from './envelope';
import { isCanonicalIpLiteral } from './events';

/**
 * Account takeover (ATO) and security incident events (step 8.4,
 * docs/plan/steps/24-account-takeover-core.md D2, D3, §4.1; ADR-0070, ADR-0075).
 *
 * Source events are named after the producing domain (`auth.*` by the api, `smtp.*` by the
 * smtp-adapter) so other consumers can use them; ATO outputs use `ato.*`; incident events are
 * generic (`security.incident.*`) because ATP categories reuse them. Every payload is strict and
 * bounded: ids as decimal strings, public ids as UUIDs, codes, counts, times and hashes only.
 * No password, SASL secret, token, MFA code, raw SMTP username of an unknown account, subject,
 * body, attachment or recipient address (§2.0 invariant 8). Written through `message_outbox` and
 * published by the event-relay; each event has its own aggregate type so ATO rows never join
 * another aggregate's ordering chain (§1.4.5).
 *
 * The vocabularies below mirror `@email-gateway/security-contracts` (`ATO_RISK_LEVELS`,
 * `ATO_ACCOUNT_KINDS`, `SECURITY_INCIDENT_*`) and the Prisma enums; event-contracts depends on
 * neither (as for `SCAN_VERDICT_VALUES`), and `@email-gateway/security-incidents` (step 8.4 WP2),
 * which depends on both, asserts that the lists are equal. Category, subject type and origin
 * lists are append-only: consumers must ignore values they do not know.
 */

const iso = z.iso.datetime();
const uuid = z.uuid();
const sha256Hex = z.string().regex(/^[0-9a-f]{64}$/, 'Expected a lower-case hex SHA-256');
const snakeCode = (max: number) =>
  z
    .string()
    .max(max)
    .regex(/^[a-z][a-z0-9_]*$/, 'Expected a snake_case code');
/** Dotted lower-case reason / rule code (`ato.auth.success_after_failures`), ≤ 64. */
const dottedCode = z
  .string()
  .max(64)
  .regex(/^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/, 'Expected a dotted lower-case code');
const canonicalIp = z
  .string()
  .max(45)
  .refine(isCanonicalIpLiteral, { message: 'Expected a canonical IP literal' });
const unique = <T>(values: readonly T[]) => new Set(values).size === values.length;
const counter = z.number().int().min(0).max(4_294_967_295);
const score = z.number().int().min(0).max(100);

// ---------------------------------------------------------------------------------------------
// Vocabularies
// ---------------------------------------------------------------------------------------------

/** `login_audit_logs.outcome` (Prisma `LoginOutcome`). */
export const AUTH_LOGIN_OUTCOME_VALUES = [
  'success',
  'failure',
  'locked',
  'mfa_required',
  'mfa_failure',
  'rate_limited',
] as const;
/** How the login reached the api (D5): through the portal's trusted forwarder or directly. */
export const AUTH_LOGIN_CHANNEL_VALUES = ['portal', 'api'] as const;

/**
 * Audit actions of `audit_logs` that `AuditService.record` also publishes as
 * `auth.account.changed.v1` (D2; credential, session, persistence and data-access changes). The
 * api verifies every name against its audit call sites (step 8.4 WP3).
 */
export const ATO_ACCOUNT_CHANGE_ACTIONS = [
  'auth.refresh_token_reused',
  'auth.password_changed',
  'auth.password_reset',
  'auth.mfa_enabled',
  'auth.mfa_disabled',
  'auth.recovery_codes_regenerated',
  'session.revoked_all',
  'user.mfa_reset',
  'user.roles_changed',
  'role.created',
  'role.updated',
  'user.invited',
  'apikey.created',
  'smtp_connector.created',
  'smtp_connector.secret_rotated',
  'webhook.created',
  'message.revealed',
  'quarantine.downloaded',
  // Step 8.4 WP3: the design's `quarantine.entry_released` is not an audit action of the api; a
  // release is audited as `quarantine.release_requested` (operator release or approval request)
  // or `quarantine.self_released` (end-user self-release), so both replace it.
  'quarantine.release_requested',
  'quarantine.self_released',
  'platform.override_started',
] as const;
export type AtoAccountChangeAction = (typeof ATO_ACCOUNT_CHANGE_ACTIONS)[number];

export const ATO_ACTOR_TYPE_VALUES = ['user', 'api_key', 'system'] as const;

export const SMTP_AUTH_RESULT_VALUES = ['ok', 'fail', 'throttled', 'blocked'] as const;
export const SMTP_AUTH_MECHANISM_VALUES = ['plain', 'login', 'unknown'] as const;
export const SMTP_AUTH_USERNAME_CLASS_VALUES = [
  'connector',
  'unknown_generated_format',
  'unknown_other',
] as const;
export const SMTP_AUTH_FAILURE_REASON_VALUES = [
  'bad_credentials',
  'connector_inactive',
  'organization_inactive',
  'malformed',
  'ato_blocked',
  'ip_throttled',
] as const;
export const SMTP_SUBMISSION_CONTEXT_VALUES = ['submission', 'relay'] as const;
export const SMTP_CONNECTOR_AUTH_TYPE_VALUES = ['sasl', 'source_ip', 'client_certificate'] as const;
/** Largest batch of one telemetry outbox row (D4, `SMTP_ATO_TELEMETRY_BATCH_MAX` ≤ this). */
export const SMTP_TELEMETRY_MAX_ENTRIES = 200;

/** Mirrors `ATO_ACCOUNT_KINDS` (Prisma `AtoAccountKind`). */
export const ATO_ACCOUNT_KIND_VALUES = ['mailbox', 'gateway_user', 'smtp_connector'] as const;
/** Mirrors `ATO_RISK_LEVELS` (Prisma `AtoRiskLevel`). */
export const ATO_RISK_LEVEL_VALUES = ['low', 'medium', 'high', 'critical'] as const;
/** Prisma `AtoScoreTrigger`. */
export const ATO_SCORE_TRIGGER_VALUES = [
  'signal',
  'decay',
  'override',
  'dismissal',
  'settings',
  'feedback',
] as const;

/** Mirror `SECURITY_INCIDENT_*` of security-contracts (append-only). */
export const SECURITY_INCIDENT_CATEGORY_VALUES = ['account_takeover'] as const;
export const SECURITY_INCIDENT_SUBJECT_TYPE_VALUES = ['ato_account'] as const;
export const SECURITY_INCIDENT_ORIGIN_VALUES = ['detection', 'manual'] as const;
export const SECURITY_INCIDENT_STATUS_VALUES = [
  'open',
  'investigating',
  'confirmed',
  'false_positive',
  'mitigated',
  'resolved',
] as const;
export const SECURITY_INCIDENT_SEVERITY_VALUES = ['low', 'medium', 'high', 'critical'] as const;
export const SECURITY_INCIDENT_CHANGED_FIELD_VALUES = [
  'status',
  'severity',
  'assignee',
  'resolution',
  'evidence',
] as const;
/** Most reason codes of an incident (`security_incidents.reason_codes`). */
export const SECURITY_INCIDENT_MAX_REASON_CODES = 16;

export const ATO_RESPONSE_PHASE_VALUES = ['execute', 'rollback'] as const;
/** Terminal response states published by `ato.response.completed.v1`. */
export const ATO_RESPONSE_COMPLETED_STATUS_VALUES = [
  'succeeded',
  'failed',
  'unsupported',
  'rolled_back',
  'rollback_failed',
  'attested',
  'rejected',
  'cancelled',
  'expired',
] as const;
export const ATO_RESPONSE_PROVIDER_STATUS_VALUES = [
  'applied',
  'confirmed',
  'unconfirmed',
  'unsupported',
  'failed',
] as const;
/** Providers executed inline by the gateway (never through `ato.response.requested.v1`). */
export const ATO_RESPONSE_LOCAL_PROVIDERS = ['gateway', 'manual'] as const;

export const ATO_RESTRICTION_KIND_VALUES = ['send_block', 'auth_block'] as const;
export const ATO_RESTRICTION_SCOPE_VALUES = ['mailbox', 'connector', 'connector_ip'] as const;
export const ATO_RESTRICTION_STATUS_VALUES = ['active', 'lifted', 'expired'] as const;
/** Scopes allowed per restriction kind (D14). */
const RESTRICTION_SCOPES: Readonly<
  Record<
    (typeof ATO_RESTRICTION_KIND_VALUES)[number],
    readonly (typeof ATO_RESTRICTION_SCOPE_VALUES)[number][]
  >
> = { send_block: ['mailbox', 'connector'], auth_block: ['connector', 'connector_ip'] };

export const ATO_NOTIFICATION_KIND_VALUES = [
  'incident_alert',
  'approval_requested',
  'response_failed',
  'digest',
] as const;
export const ATO_NOTIFICATION_AUDIENCE_VALUES = ['tenant', 'soc', 'platform_soc'] as const;
export const ATO_DIGEST_PERIOD_VALUES = ['daily', 'weekly'] as const;
/** Which `refs` each ATO notification kind requires (D2). */
const ATO_NOTIFICATION_REQUIRED_REFS: Readonly<
  Record<(typeof ATO_NOTIFICATION_KIND_VALUES)[number], readonly string[]>
> = {
  incident_alert: ['incidentPublicId'],
  approval_requested: ['actionPublicId'],
  response_failed: ['actionPublicId'],
  digest: [],
};

const actionTypeCode = snakeCode(48);
const providerCode = snakeCode(32);

// ---------------------------------------------------------------------------------------------
// Source events (api, smtp-adapter)
// ---------------------------------------------------------------------------------------------

/**
 * One `login_audit_logs` row (D5): written by the api's `LoginAuditRepository.insert` in the same
 * writer transaction as the row (`aggregate_type = 'login'`, `aggregate_id` = the row id),
 * published to `email.events`, bound to `ato.events`. The envelope organization is the user's;
 * for an unknown account (`accountKnown: false`, `userId: null`) the platform organization. The
 * attempted e-mail is never carried (the worker reads the row back and keeps only an HMAC).
 */
export const authLoginRecordedV1 = z
  .strictObject({
    loginAuditId: decimalIdSchema,
    occurredAt: iso,
    outcome: z.enum(AUTH_LOGIN_OUTCOME_VALUES),
    failureReason: snakeCode(64).nullable(),
    accountKnown: z.boolean(),
    userId: decimalIdSchema.nullable(),
    channel: z.enum(AUTH_LOGIN_CHANNEL_VALUES),
  })
  .superRefine((p, ctx) => {
    if (p.accountKnown !== (p.userId !== null)) {
      ctx.addIssue({
        code: 'custom',
        path: ['userId'],
        message: 'userId is present exactly for a known account',
      });
    }
    if ((p.outcome === 'success' || p.outcome === 'mfa_required') && p.failureReason !== null) {
      ctx.addIssue({
        code: 'custom',
        path: ['failureReason'],
        message: 'A success or MFA challenge has no failure reason',
      });
    }
  });
export type AuthLoginRecordedV1 = z.infer<typeof authLoginRecordedV1>;

/**
 * An audited credential, session, persistence or data-access change (D5): written by the api's
 * `AuditService.record` with the same client (inside the caller's transaction) for actions in
 * `ATO_ACCOUNT_CHANGE_ACTIONS` with a non-null organization (`aggregate_type = 'audit'`,
 * `aggregate_id` = `audit_logs.id`), published to `email.events`, bound to `ato.events`.
 */
export const authAccountChangedV1 = z
  .strictObject({
    auditLogId: decimalIdSchema,
    auditCreatedAt: iso,
    action: z.enum(ATO_ACCOUNT_CHANGE_ACTIONS),
    actorType: z.enum(ATO_ACTOR_TYPE_VALUES),
    actorPublicId: uuid.nullable(),
    resourceType: z
      .string()
      .max(64)
      .regex(/^[a-z][a-z0-9_.]*$/, 'Expected a lower-case resource type'),
    resourcePublicId: z
      .string()
      .min(1)
      .max(64)
      .regex(/^[A-Za-z0-9._:-]+$/, 'Expected an opaque identifier')
      .nullable(),
  })
  .superRefine((p, ctx) => {
    if (p.actorType === 'system' && p.actorPublicId !== null) {
      ctx.addIssue({
        code: 'custom',
        path: ['actorPublicId'],
        message: 'A system action has no actor public id',
      });
    }
  });
export type AuthAccountChangedV1 = z.infer<typeof authAccountChangedV1>;

const telemetryProducer = z.strictObject({
  instance: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[A-Za-z0-9._-]+$/, 'Expected an instance name'),
});
const telemetrySeq = z
  .number()
  .int()
  .min(0)
  .max(SMTP_TELEMETRY_MAX_ENTRIES - 1);

function uniqueSeq(entries: readonly { seq: number }[], ctx: z.RefinementCtx): void {
  if (!unique(entries.map((e) => e.seq))) {
    ctx.addIssue({ code: 'custom', path: ['entries'], message: 'Duplicate seq' });
  }
}

const smtpAuthEntry = z
  .strictObject({
    seq: telemetrySeq,
    occurredAt: iso,
    result: z.enum(SMTP_AUTH_RESULT_VALUES),
    mechanism: z.enum(SMTP_AUTH_MECHANISM_VALUES),
    connectorId: decimalIdSchema.nullable(),
    clientIp: canonicalIp.nullable(),
    usernameClass: z.enum(SMTP_AUTH_USERNAME_CLASS_VALUES),
    /** First 16 hex of HMAC-SHA256(SMTP_ATO_USERNAME_HASH_KEY, username): unknown usernames only. */
    usernameHash: z
      .string()
      .regex(/^[0-9a-f]{16}$/, 'Expected 16 lower-case hex characters')
      .nullable(),
    failureReason: z.enum(SMTP_AUTH_FAILURE_REASON_VALUES).nullable(),
  })
  .superRefine((e, ctx) => {
    const known = e.usernameClass === 'connector';
    if (known !== (e.connectorId !== null)) {
      ctx.addIssue({
        code: 'custom',
        path: ['connectorId'],
        message: 'connectorId is present exactly for a connector username',
      });
    }
    if (known && e.usernameHash !== null) {
      ctx.addIssue({
        code: 'custom',
        path: ['usernameHash'],
        message: 'A known username is represented by connectorId, never hashed',
      });
    }
    if ((e.result === 'ok') !== (e.failureReason === null)) {
      ctx.addIssue({
        code: 'custom',
        path: ['failureReason'],
        message: 'Only a failed, throttled or blocked authentication has a failure reason',
      });
    }
    if (e.result === 'ok' && !known) {
      ctx.addIssue({
        code: 'custom',
        path: ['usernameClass'],
        message: 'A successful authentication names its connector',
      });
    }
    if ((e.result === 'blocked') !== (e.failureReason === 'ato_blocked')) {
      ctx.addIssue({
        code: 'custom',
        path: ['failureReason'],
        message: 'blocked goes with ato_blocked',
      });
    }
    if ((e.result === 'throttled') !== (e.failureReason === 'ip_throttled')) {
      ctx.addIssue({
        code: 'custom',
        path: ['failureReason'],
        message: 'throttled goes with ip_throttled',
      });
    }
  });

/**
 * A batch of SMTP AUTH decisions of one organization (D4): recorded by the smtp-adapter after the
 * SASL reply, flushed into one outbox row (`aggregate_type = 'smtp_telemetry'`, `aggregate_id` =
 * the organization id; unknown usernames in a batch of the platform organization), published to
 * `email.events`, bound to `ato.events`. At most once into the outbox (a crash loses at most one
 * flush interval). Infrastructure failures (`temp`) are not entries.
 */
export const smtpAuthRecordedV1 = z
  .strictObject({
    producer: telemetryProducer,
    entries: z.array(smtpAuthEntry).min(1).max(SMTP_TELEMETRY_MAX_ENTRIES),
  })
  .superRefine((p, ctx) => uniqueSeq(p.entries, ctx));
export type SmtpAuthRecordedV1 = z.infer<typeof smtpAuthRecordedV1>;

const smtpSubmissionEntry = z.strictObject({
  seq: telemetrySeq,
  occurredAt: iso,
  context: z.enum(SMTP_SUBMISSION_CONTEXT_VALUES),
  connectorId: decimalIdSchema,
  connectorAuthType: z.enum(SMTP_CONNECTOR_AUTH_TYPE_VALUES),
  /** postfix-outbound queue id (matches `email_messages.mta_queue_id`). */
  queueId: z
    .string()
    .regex(/^[0-9A-Za-z]{1,32}$/, 'Expected a Postfix queue id')
    .nullable(),
  clientIp: canonicalIp.nullable(),
  heloName: z
    .string()
    .min(1)
    .max(255)
    .regex(/^[\x21-\x7e]+$/, 'Expected a printable HELO name')
    .nullable(),
  tlsProtocol: z
    .string()
    .min(1)
    .max(16)
    .regex(/^[A-Za-z0-9._-]+$/, 'Expected a TLS protocol name')
    .nullable(),
  /** The lower-cased envelope sender (the mailbox account, D1). */
  senderAddress: z
    .string()
    .min(3)
    .max(320)
    .regex(/^[^\s@A-Z]+@[^\s@A-Z]+$/, 'Expected a lower-cased address'),
  recipientCount: z.number().int().min(0).max(10_000),
  sizeBytes: z.number().int().nonnegative(),
});

/**
 * A batch of accepted submissions of one organization at END-OF-MESSAGE in the `submission` and
 * `relay` contexts (D4): connector attribution of outbound mail and the client fingerprint. Same
 * outbox, aggregate and binding as `smtp.auth.recorded.v1`.
 */
export const smtpSubmissionRecordedV1 = z
  .strictObject({
    producer: telemetryProducer,
    entries: z.array(smtpSubmissionEntry).min(1).max(SMTP_TELEMETRY_MAX_ENTRIES),
  })
  .superRefine((p, ctx) => uniqueSeq(p.entries, ctx));
export type SmtpSubmissionRecordedV1 = z.infer<typeof smtpSubmissionRecordedV1>;

// ---------------------------------------------------------------------------------------------
// ATO outputs
// ---------------------------------------------------------------------------------------------

/**
 * An account's risk level changed (D11; `aggregate_type = 'ato_account'`, `aggregate_id` =
 * `ato_accounts.id`), written by the ATO store (worker or api) in the rescoring transaction,
 * published to `email.security`, bound to `email.webhooks` (public `ato.account.risk_changed`).
 */
export const atoAccountRiskUpdatedV1 = z
  .strictObject({
    accountId: decimalIdSchema,
    accountPublicId: uuid,
    kind: z.enum(ATO_ACCOUNT_KIND_VALUES),
    score,
    level: z.enum(ATO_RISK_LEVEL_VALUES),
    previousScore: score,
    previousLevel: z.enum(ATO_RISK_LEVEL_VALUES),
    trigger: z.enum(ATO_SCORE_TRIGGER_VALUES),
    computedAt: iso,
  })
  .superRefine((p, ctx) => {
    if (p.level === p.previousLevel) {
      ctx.addIssue({
        code: 'custom',
        path: ['level'],
        message: 'Published only when the level changes',
      });
    }
  });
export type AtoAccountRiskUpdatedV1 = z.infer<typeof atoAccountRiskUpdatedV1>;

const incidentSubject = z.strictObject({
  type: z.enum(SECURITY_INCIDENT_SUBJECT_TYPE_VALUES),
  publicId: uuid,
});

/**
 * A security incident was opened (D12, D24; every category; `aggregate_type =
 * 'security_incident'`, `aggregate_id` = `security_incidents.id`), written by the shared
 * `IncidentStore` in the opening transaction, published to `email.security`, bound to
 * `email.webhooks` (public `security.incident.created`).
 */
export const securityIncidentCreatedV1 = z
  .strictObject({
    incidentId: decimalIdSchema,
    incidentPublicId: uuid,
    category: z.enum(SECURITY_INCIDENT_CATEGORY_VALUES),
    subject: incidentSubject,
    origin: z.enum(SECURITY_INCIDENT_ORIGIN_VALUES),
    severity: z.enum(SECURITY_INCIDENT_SEVERITY_VALUES),
    status: z.literal('open'),
    detectedAt: iso,
    reasonCodes: z.array(dottedCode).max(SECURITY_INCIDENT_MAX_REASON_CODES),
  })
  .superRefine((p, ctx) => {
    if (!unique(p.reasonCodes)) {
      ctx.addIssue({ code: 'custom', path: ['reasonCodes'], message: 'Duplicate reason code' });
    }
  });
export type SecurityIncidentCreatedV1 = z.infer<typeof securityIncidentCreatedV1>;

/**
 * A security incident changed (status, severity, assignee, resolution; evidence additions at
 * most once per 15 minutes per incident; D12, D24). Same aggregate, exchange and binding as
 * `security.incident.created.v1` (public `security.incident.updated`).
 */
export const securityIncidentUpdatedV1 = z
  .strictObject({
    incidentId: decimalIdSchema,
    incidentPublicId: uuid,
    category: z.enum(SECURITY_INCIDENT_CATEGORY_VALUES),
    subject: incidentSubject,
    status: z.enum(SECURITY_INCIDENT_STATUS_VALUES),
    previousStatus: z.enum(SECURITY_INCIDENT_STATUS_VALUES),
    severity: z.enum(SECURITY_INCIDENT_SEVERITY_VALUES),
    previousSeverity: z.enum(SECURITY_INCIDENT_SEVERITY_VALUES),
    assigned: z.boolean(),
    changedFields: z.array(z.enum(SECURITY_INCIDENT_CHANGED_FIELD_VALUES)).min(1).max(5),
    actorType: z.enum(ATO_ACTOR_TYPE_VALUES),
    updatedAt: iso,
  })
  .superRefine((p, ctx) => {
    if (!unique(p.changedFields)) {
      ctx.addIssue({ code: 'custom', path: ['changedFields'], message: 'Duplicate field' });
    }
    if (p.changedFields.includes('status') !== (p.status !== p.previousStatus)) {
      ctx.addIssue({
        code: 'custom',
        path: ['changedFields'],
        message: 'status is listed exactly when the status changed',
      });
    }
    if (p.changedFields.includes('severity') !== (p.severity !== p.previousSeverity)) {
      ctx.addIssue({
        code: 'custom',
        path: ['changedFields'],
        message: 'severity is listed exactly when the severity changed',
      });
    }
  });
export type SecurityIncidentUpdatedV1 = z.infer<typeof securityIncidentUpdatedV1>;

/**
 * A provider response action to execute or roll back (D13, D15; `aggregate_type =
 * 'ato_response'`, `aggregate_id` = `ato_response_actions.id`), written by the ATO store **for
 * provider actions only** (gateway actions run inline), published to `email.security`, consumed
 * from `ato.responses` by the ato-worker's `respond` role (provider calls never run inside a
 * database transaction).
 */
export const atoResponseRequestedV1 = z
  .strictObject({
    actionId: decimalIdSchema,
    actionPublicId: uuid,
    phase: z.enum(ATO_RESPONSE_PHASE_VALUES),
    actionType: actionTypeCode,
    provider: providerCode,
    incidentId: decimalIdSchema.nullable(),
    accountId: decimalIdSchema,
    requestedAt: iso,
  })
  .superRefine((p, ctx) => {
    if ((ATO_RESPONSE_LOCAL_PROVIDERS as readonly string[]).includes(p.provider)) {
      ctx.addIssue({
        code: 'custom',
        path: ['provider'],
        message: 'Gateway and manual actions are executed inline, never requested',
      });
    }
  });
export type AtoResponseRequestedV1 = z.infer<typeof atoResponseRequestedV1>;

/**
 * A response action reached a terminal state (D13; same aggregate as the request), written by
 * the ATO store (gateway actions inline, provider actions by the `respond` role), published to
 * `email.security`, bound to `email.webhooks` (public `ato.response.completed`). Never claims what
 * did not happen: a provider action `succeeded` only with `providerStatus = 'confirmed'`.
 */
export const atoResponseCompletedV1 = z
  .strictObject({
    actionId: decimalIdSchema,
    actionPublicId: uuid,
    phase: z.enum(ATO_RESPONSE_PHASE_VALUES),
    actionType: actionTypeCode,
    provider: providerCode,
    status: z.enum(ATO_RESPONSE_COMPLETED_STATUS_VALUES),
    providerStatus: z.enum(ATO_RESPONSE_PROVIDER_STATUS_VALUES).nullable(),
    resultCode: snakeCode(64).nullable(),
    incidentPublicId: uuid.nullable(),
    accountPublicId: uuid,
    completedAt: iso,
  })
  .superRefine((p, ctx) => {
    const local = (ATO_RESPONSE_LOCAL_PROVIDERS as readonly string[]).includes(p.provider);
    if (p.status === 'succeeded' && !local && p.providerStatus !== 'confirmed') {
      ctx.addIssue({
        code: 'custom',
        path: ['providerStatus'],
        message: 'A provider action succeeds only with provider confirmation',
      });
    }
    if ((p.status === 'attested') !== (p.provider === 'manual')) {
      ctx.addIssue({
        code: 'custom',
        path: ['status'],
        message: 'Manual actions are attested, and only manual actions',
      });
    }
    const rollbackStatus = p.status === 'rolled_back' || p.status === 'rollback_failed';
    if (rollbackStatus !== (p.phase === 'rollback')) {
      ctx.addIssue({
        code: 'custom',
        path: ['phase'],
        message: 'rolled_back and rollback_failed complete the rollback phase only',
      });
    }
  });
export type AtoResponseCompletedV1 = z.infer<typeof atoResponseCompletedV1>;

/**
 * An SMTP restriction was applied, lifted or expired (D14; `aggregate_type = 'ato_restriction'`,
 * `aggregate_id` = `ato_smtp_restrictions.id`), published to `email.security`. No queue binding:
 * the smtp-adapter reads it from the outbox tail (cache invalidation) and the analytics firehose
 * receives it. The mailbox is a SHA-256 of the lower-cased address, never the address.
 */
export const atoRestrictionChangedV1 = z
  .strictObject({
    restrictionId: decimalIdSchema,
    kind: z.enum(ATO_RESTRICTION_KIND_VALUES),
    scope: z.enum(ATO_RESTRICTION_SCOPE_VALUES),
    connectorId: decimalIdSchema.nullable(),
    mailboxSha256: sha256Hex.nullable(),
    status: z.enum(ATO_RESTRICTION_STATUS_VALUES),
    expiresAt: iso,
    changedAt: iso,
  })
  .superRefine((p, ctx) => {
    if (!RESTRICTION_SCOPES[p.kind].includes(p.scope)) {
      ctx.addIssue({
        code: 'custom',
        path: ['scope'],
        message: `${p.kind} has scopes ${RESTRICTION_SCOPES[p.kind].join(', ')}`,
      });
    }
    const mailbox = p.scope === 'mailbox';
    if (mailbox !== (p.mailboxSha256 !== null) || mailbox !== (p.connectorId === null)) {
      ctx.addIssue({
        code: 'custom',
        path: ['scope'],
        message: 'A mailbox scope names the mailbox hash only; connector scopes the connector only',
      });
    }
  });
export type AtoRestrictionChangedV1 = z.infer<typeof atoRestrictionChangedV1>;

/**
 * An ATO e-mail notification request (D16; the first event of a throttle window;
 * `aggregate_type = 'ato_notification'`, `aggregate_id` = the organization id), written by the
 * ATO store, published to `email.security`, consumed from `email.notifications` by the
 * notification-worker, which reads what it renders at send time. Refs, counts and times only.
 */
export const atoNotificationRequestedV1 = z
  .strictObject({
    kind: z.enum(ATO_NOTIFICATION_KIND_VALUES),
    audience: z.enum(ATO_NOTIFICATION_AUDIENCE_VALUES),
    severity: z.enum(SECURITY_INCIDENT_SEVERITY_VALUES).nullable(),
    refs: z.strictObject({
      incidentPublicId: uuid.optional(),
      actionPublicId: uuid.optional(),
      accountPublicId: uuid.optional(),
    }),
    window: z.strictObject({ from: iso, to: iso }),
    counts: z.strictObject({
      suppressedBefore: counter,
      incidents: counter.optional(),
      criticalIncidents: counter.optional(),
      pendingApprovals: counter.optional(),
      restrictedAccounts: counter.optional(),
    }),
    digestPeriod: z.enum(ATO_DIGEST_PERIOD_VALUES).nullable(),
    requestedAt: iso,
  })
  .superRefine((p, ctx) => {
    const refs = p.refs as Record<string, unknown>;
    for (const field of ATO_NOTIFICATION_REQUIRED_REFS[p.kind]) {
      if (refs[field] === undefined) {
        ctx.addIssue({
          code: 'custom',
          path: ['refs', field],
          message: `A ${p.kind} notification names ${field}`,
        });
      }
    }
    if ((p.kind === 'digest') !== (p.digestPeriod !== null)) {
      ctx.addIssue({
        code: 'custom',
        path: ['digestPeriod'],
        message: 'digestPeriod is set exactly for a digest',
      });
    }
    if (p.kind === 'incident_alert' && p.severity === null) {
      ctx.addIssue({
        code: 'custom',
        path: ['severity'],
        message: 'An incident alert carries the severity',
      });
    }
    if (
      p.audience === 'platform_soc' &&
      (p.kind !== 'incident_alert' || p.severity !== 'critical')
    ) {
      ctx.addIssue({
        code: 'custom',
        path: ['audience'],
        message: 'The platform SOC receives critical incident alerts only',
      });
    }
    if (Date.parse(p.window.from) >= Date.parse(p.window.to)) {
      ctx.addIssue({ code: 'custom', path: ['window'], message: 'window.from precedes window.to' });
    }
  });
export type AtoNotificationRequestedV1 = z.infer<typeof atoNotificationRequestedV1>;
