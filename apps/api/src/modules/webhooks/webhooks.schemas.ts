import {
  buildEnvelope,
  SEVERITIES,
  subscriptionEventTypesSchema,
  subscriptionFiltersSchema,
  WEBHOOK_ENVELOPE_TYPES,
  WEBHOOK_EVENT_CATALOGUE,
  WEBHOOK_EVENT_TYPES,
  WEBHOOK_EXAMPLE_DATA,
  WEBHOOK_FILTER_NAMES,
  type WebhookEnvelopeType,
} from '@email-gateway/webhooks';
import { z } from 'zod';
import { defineListQuery } from '../../http/listing/list-query';
import { stripControlCharacters } from './domain/control-chars';
import { WEBHOOK_URL_MAX_LENGTH } from './domain/webhook-url';

/**
 * Request and response shapes of the webhook routes (step 6.2 §6.1, W5–W7, W12;
 * docs/plan/steps/19-webhooks-notifications.md). Every request schema is strict; responses never
 * carry a ciphertext, and the secret only in the original create/rotate response.
 */

/** v1 cursor resources (ADR-0051). */
export const WEBHOOKS_RESOURCE = 'webhooks';
export const WEBHOOK_DELIVERIES_RESOURCE = 'webhook_deliveries';

export const WEBHOOK_STATUSES = ['active', 'paused', 'disabled', 'deleted'] as const;
export type WebhookStatusValue = (typeof WEBHOOK_STATUSES)[number];
/** What `PATCH` may set (`deleted` only through `DELETE`). */
export const PATCHABLE_STATUSES = ['active', 'paused', 'disabled'] as const;
/** What `POST` may set. */
export const CREATABLE_STATUSES = ['active', 'paused'] as const;

export const DELIVERY_STATUSES = ['pending', 'succeeded', 'failed', 'dead', 'cancelled'] as const;
export const DELIVERY_TRIGGERS = ['event', 'replay', 'test'] as const;
export const REPLAY_STATUSES = ['queued', 'running', 'completed', 'failed', 'cancelled'] as const;
/** Statuses a range replay may select (W12). */
export const REPLAYABLE_STATUSES = ['succeeded', 'failed', 'dead', 'cancelled'] as const;
export const DEFAULT_REPLAY_STATUSES = ['failed', 'dead'] as const;
export const ATTEMPT_OUTCOMES = [
  'succeeded',
  'http_error',
  'redirect',
  'timeout',
  'dns_error',
  'connection_error',
  'tls_error',
  'blocked',
  'too_large',
  'secret_unavailable',
] as const;

/**
 * Upper bound of a subscription's `maxConcurrency`: the upper bound of the worker's
 * `WEBHOOK_MAX_INFLIGHT_PER_SUBSCRIPTION` (1–32); the worker applies
 * `min(maxConcurrency, WEBHOOK_MAX_INFLIGHT_PER_SUBSCRIPTION)`.
 */
export const MAX_CONCURRENCY_LIMIT = 32;
/** Longest rotation overlap (W7). */
export const ROTATION_OVERLAP_MAX_HOURS = 168;
/** Delivery history retention (monthly partitions, 2 months; partition registry). */
export const DELIVERY_RETENTION_DAYS = 62;

export const WebhookIdSchema = z.uuid();

/** Tenant text: control characters stripped, trimmed (§9). */
const tenantText = (max: number) =>
  z
    .string()
    .max(max * 4)
    .transform((value) => stripControlCharacters(value).trim())
    .pipe(z.string().max(max));

const name = tenantText(255).pipe(z.string().min(1, 'must not be empty'));
const description = tenantText(512);
const url = z
  .string()
  .min(1)
  .max(WEBHOOK_URL_MAX_LENGTH)
  .describe(
    'Absolute `https` URL (≤ 2048, no userinfo, no fragment, a port of WEBHOOK_ALLOWED_PORTS; ' +
      'hosts of private, loopback, link-local, metadata or other special-purpose addresses and ' +
      'the platform’s own hosts are refused with `422 webhook_url_not_allowed`)',
  );
const maxConcurrency = z
  .number()
  .int()
  .min(1)
  .max(MAX_CONCURRENCY_LIMIT)
  .describe(
    'Per-subscription in-flight cap (1-32); the delivery worker applies at most its own ' +
      'WEBHOOK_MAX_INFLIGHT_PER_SUBSCRIPTION. Null/absent: the worker default',
  );

export const CreateWebhookBodySchema = z.strictObject({
  name: name.describe('Display name (1-255; control characters removed)'),
  description: description.optional(),
  url,
  eventTypes: subscriptionEventTypesSchema.describe(
    '1-10 unique event types of the catalogue (`GET /webhooks/event-types`); no wildcard',
  ),
  filters: subscriptionFiltersSchema.optional(),
  status: z.enum(CREATABLE_STATUSES).default('active'),
  maxConcurrency: maxConcurrency.optional(),
});
export type CreateWebhookBody = z.output<typeof CreateWebhookBodySchema>;

export const UpdateWebhookBodySchema = z
  .strictObject({
    expectedRowVersion: z
      .number()
      .int()
      .min(1)
      .describe('`rowVersion` of the webhook as last read (`409 webhook_version_conflict`)'),
    name: name.optional(),
    description: description.nullable().optional(),
    url: url.optional(),
    eventTypes: subscriptionEventTypesSchema.optional(),
    filters: subscriptionFiltersSchema.nullable().optional(),
    status: z.enum(PATCHABLE_STATUSES).optional(),
    maxConcurrency: maxConcurrency.nullable().optional(),
  })
  .refine((body) => Object.keys(body).some((key) => key !== 'expectedRowVersion'), {
    message: 'must change at least one field',
  });
export type UpdateWebhookBody = z.output<typeof UpdateWebhookBodySchema>;

export const RotateSecretBodySchema = z.strictObject({
  overlapHours: z
    .number()
    .int()
    .min(0)
    .max(ROTATION_OVERLAP_MAX_HOURS)
    .optional()
    .describe(
      'How long the retiring secret keeps signing too (0-168; default ' +
        'WEBHOOK_SECRET_OVERLAP_HOURS_DEFAULT, 24). 0 = no overlap',
    ),
});
export type RotateSecretBody = z.output<typeof RotateSecretBodySchema>;

const isoInstant = z.iso.datetime({ offset: true });

export const CreateReplayBodySchema = z.strictObject({
  from: isoInstant.describe('Start of the range of event times (inclusive)'),
  to: isoInstant.describe('End of the range (exclusive); at most WEBHOOK_REPLAY_MAX_RANGE_HOURS'),
  statuses: z
    .array(z.enum(REPLAYABLE_STATUSES))
    .min(1)
    .max(REPLAYABLE_STATUSES.length)
    .refine((v) => new Set(v).size === v.length, { message: 'Duplicate value' })
    .optional()
    .describe('Statuses of the original deliveries to replay (default `failed`, `dead`)'),
  eventTypes: subscriptionEventTypesSchema
    .optional()
    .describe('Only these event types (default: every type of the subscription)'),
});
export type CreateReplayBody = z.output<typeof CreateReplayBodySchema>;

export const WebhookListQuerySchema = defineListQuery({
  filters: { status: { type: 'enum', values: WEBHOOK_STATUSES, maxValues: 4 } },
  sorts: ['-id'],
  defaultSort: '-id',
});
export type WebhookListQuery = z.output<typeof WebhookListQuerySchema>;

export const WEBHOOK_LIST_PARAMETERS: Record<string, string> = {
  status:
    '`active`, `paused`, `disabled`, `deleted`; comma list (default: every status except ' +
    '`deleted`)',
  limit: 'Page size, 1-100 (default 25)',
  cursor: '`nextCursor` of the previous page',
  sort: '`-id` (the only order: newest first)',
};

export const DeliveryListQuerySchema = defineListQuery({
  filters: {
    status: { type: 'enum', values: DELIVERY_STATUSES, maxValues: 5 },
    eventType: {
      type: 'enum',
      values: WEBHOOK_ENVELOPE_TYPES as unknown as readonly [string, ...string[]],
      maxValues: 10,
    },
    trigger: { type: 'enum', values: DELIVERY_TRIGGERS, maxValues: 3 },
  },
  sorts: ['-occurredAt'],
  defaultSort: '-occurredAt',
  range: true,
});
export type DeliveryListQuery = z.output<typeof DeliveryListQuerySchema>;

export const DELIVERY_LIST_PARAMETERS: Record<string, string> = {
  from: 'Start of the event-time range (ISO 8601 with offset, inclusive); default `to` − 24 h',
  to: 'End of the range (exclusive); default now. At most WEBHOOK_HISTORY_MAX_RANGE_DAYS (31)',
  status: '`pending`, `succeeded`, `failed`, `dead`, `cancelled`; comma list',
  eventType: 'Event type(s) of the catalogue or `webhook.ping`; comma list (≤ 10)',
  trigger: '`event`, `replay`, `test`; comma list',
  limit: 'Page size, 1-100 (default 25). A page may hold fewer rows (see the scan budget).',
  cursor: '`nextCursor` of the previous page',
  sort: '`-occurredAt` (the only order: newest event first)',
};

// ---------------------------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------------------------

const IsoDate = z.iso.datetime();

export const WebhookSchema = z.object({
  id: z.uuid(),
  name: z.string(),
  description: z.string().nullable(),
  url: z.string().describe('The endpoint (shown to webhook:read holders only)'),
  eventTypes: z.array(z.enum(WEBHOOK_EVENT_TYPES)),
  filters: subscriptionFiltersSchema.nullable(),
  status: z.enum(WEBHOOK_STATUSES),
  disabledReason: z
    .string()
    .nullable()
    .describe('`sustained_failure` (system, W11) or `manual` (PATCH status=disabled)'),
  disabledAt: IsoDate.nullable(),
  maxConcurrency: z.number().int().nullable(),
  secretVersion: z.number().int().describe('1 at creation, +1 per rotation'),
  secretRotatedAt: IsoDate.nullable(),
  previousSecretExpiresAt: IsoDate.nullable().describe(
    'While in the future, every delivery is signed with both secrets (two `v1=`)',
  ),
  consecutiveFailures: z.number().int(),
  failingSince: IsoDate.nullable(),
  lastSuccessAt: IsoDate.nullable(),
  lastFailureAt: IsoDate.nullable(),
  createdBy: z
    .object({ type: z.literal('user'), id: z.uuid() })
    .nullable()
    .describe('The creating user, or null (created with an API key, or the user was deleted)'),
  createdAt: IsoDate,
  updatedAt: IsoDate,
  rowVersion: z.number().int(),
});
export type WebhookView = z.output<typeof WebhookSchema>;

const secretField = z
  .string()
  .nullable()
  .describe(
    'The signing secret (`whsec_…`), shown ONLY in this response. `null` when the stored ' +
      'response of an earlier identical request is replayed (`Idempotency-Replayed: true`): ' +
      'rotate the secret to get a new one',
  );

export const CreatedWebhookSchema = WebhookSchema.extend({ secret: secretField });
export type CreatedWebhookView = z.output<typeof CreatedWebhookSchema>;

export const RotatedSecretSchema = z.object({
  id: z.uuid(),
  secret: secretField,
  secretVersion: z.number().int(),
  secretRotatedAt: IsoDate,
  previousSecretExpiresAt: IsoDate.nullable(),
});
export type RotatedSecretView = z.output<typeof RotatedSecretSchema>;

export const WebhookPageSchema = z.object({
  data: z.array(WebhookSchema),
  nextCursor: z.string().nullable(),
});
export type WebhookPage = z.output<typeof WebhookPageSchema>;

export const DeliverySchema = z.object({
  id: z.uuid().describe('Delivery public id (`EG-Delivery-Id`; new per replay)'),
  eventId: z.uuid().describe('Public event id (`EG-Event-Id`, envelope `id`)'),
  eventType: z.string(),
  occurredAt: IsoDate,
  status: z.enum(DELIVERY_STATUSES),
  trigger: z.enum(DELIVERY_TRIGGERS),
  deliverySeq: z.number().int().describe('0 = original delivery, 1.. = replays'),
  attemptCount: z.number().int(),
  nextAttemptAt: IsoDate.nullable().describe(
    'When the next attempt is due (pending only); null when terminal, or pending while the ' +
      'webhook is paused (parked until it is re-activated)',
  ),
  firstAttemptAt: IsoDate.nullable(),
  lastAttemptAt: IsoDate.nullable(),
  lastResponseCode: z.number().int().nullable(),
  lastLatencyMs: z.number().int().nullable(),
  lastError: z.string().nullable().describe('A code (e.g. `http_500`, `blocked:loopback`)'),
  completedAt: IsoDate.nullable(),
  createdAt: IsoDate,
});
export type DeliveryView = z.output<typeof DeliverySchema>;

export const DeliveryPageSchema = z.object({
  data: z.array(DeliverySchema),
  nextCursor: z.string().nullable(),
});
export type DeliveryPage = z.output<typeof DeliveryPageSchema>;

export const AttemptSchema = z.object({
  attemptNo: z.number().int(),
  attemptedAt: IsoDate,
  outcome: z.enum(ATTEMPT_OUTCOMES),
  httpStatus: z.number().int().nullable(),
  latencyMs: z.number().int(),
  responseSnippet: z
    .string()
    .nullable()
    .describe('First ≤ 512 characters of the response, secrets redacted; untrusted text'),
  retryAfterSeconds: z.number().int().nullable(),
  errorCode: z.string().nullable(),
  signatureCount: z.number().int(),
});

export const DeliveryDetailSchema = DeliverySchema.extend({
  attempts: z.array(AttemptSchema),
  event: z
    .record(z.string(), z.unknown())
    .nullable()
    .describe('The stored envelope (exactly what is signed and sent), or null after retention'),
});
export type DeliveryDetailView = z.output<typeof DeliveryDetailSchema>;

export const DeliveryReplayAcceptedSchema = z.object({
  deliveryId: z.uuid().describe('Public id of the new delivery (poll it in the history)'),
});
export type DeliveryReplayAccepted = z.output<typeof DeliveryReplayAcceptedSchema>;

export const TestAcceptedSchema = z.object({
  deliveryId: z.uuid(),
  eventId: z.uuid(),
});
export type TestAccepted = z.output<typeof TestAcceptedSchema>;

export const ReplayAcceptedSchema = z.object({
  replayId: z.uuid(),
  status: z.enum(REPLAY_STATUSES),
});
export type ReplayAccepted = z.output<typeof ReplayAcceptedSchema>;

export const ReplaySchema = z.object({
  id: z.uuid(),
  status: z.enum(REPLAY_STATUSES),
  from: IsoDate,
  to: IsoDate,
  statuses: z.array(z.enum(REPLAYABLE_STATUSES)),
  eventTypes: z.array(z.string()).nullable(),
  matchedCount: z.number().int().describe('Original deliveries the range matched so far'),
  createdCount: z
    .number()
    .int()
    .describe(
      'Replay deliveries created; lower than `matchedCount` for events that already had ' +
        'WEBHOOK_REPLAY_MAX_PER_DELIVERY replays (skipped, not re-sent)',
    ),
  truncated: z.boolean().describe('WEBHOOK_REPLAY_MAX_EVENTS was reached'),
  errorCode: z
    .string()
    .nullable()
    .describe(
      'Why a replay `failed`: `webhook_not_active`, `organization_inactive`, ' +
        '`webhooks_not_enabled`, `replay_invalid`',
    ),
  createdAt: IsoDate,
  startedAt: IsoDate.nullable(),
  completedAt: IsoDate.nullable(),
});
export type ReplayView = z.output<typeof ReplaySchema>;

export const EventTypeSchema = z.object({
  type: z.string(),
  version: z.number().int(),
  description: z.string(),
  severity: z.string().describe('How the severity of an event of this type is decided'),
  appliesFilters: z.array(z.enum(WEBHOOK_FILTER_NAMES)),
  subscribable: z.boolean().describe('False for `webhook.ping` (sent by the test route only)'),
  example: z.record(z.string(), z.unknown()).describe('An example envelope'),
});
export const EventTypesSchema = z.object({
  data: z.array(EventTypeSchema),
  severities: z.array(z.enum(SEVERITIES)),
});
export type EventTypesView = z.output<typeof EventTypesSchema>;

// ---------------------------------------------------------------------------------------------
// The catalogue (computed once) and the documentation examples
// ---------------------------------------------------------------------------------------------

const EXAMPLE_ORG = '0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b10';
const EXAMPLE_SOURCE_EVENT = '0193a1b2-0c4d-7e5f-8a6b-7c8d9e0f1a2b';
const EXAMPLE_OCCURRED_AT = '2026-11-13T09:14:03.120Z';

/** `GET /webhooks/event-types`: the ten types and the ping, each with an example envelope. */
export const EVENT_TYPES_VIEW: EventTypesView = Object.freeze({
  data: WEBHOOK_ENVELOPE_TYPES.map((type: WebhookEnvelopeType) => {
    const entry = WEBHOOK_EVENT_CATALOGUE[type];
    const { envelope } = buildEnvelope({
      type,
      occurredAt: EXAMPLE_OCCURRED_AT,
      organizationPublicId: EXAMPLE_ORG,
      sourceEventId: EXAMPLE_SOURCE_EVENT,
      data: WEBHOOK_EXAMPLE_DATA[type],
    });
    return {
      type: entry.type,
      version: entry.version,
      description: entry.description,
      severity: entry.severity,
      appliesFilters: [...entry.appliesFilters],
      subscribable: entry.subscribable,
      example: JSON.parse(JSON.stringify(envelope)) as Record<string, unknown>,
    };
  }),
  severities: [...SEVERITIES],
});

const exampleWebhook: WebhookView = {
  id: '0193a2c4-5d6e-7f80-9a1b-2c3d4e5f6a7b',
  name: 'SIEM ingestion',
  description: 'Threat and quarantine events to the SOC pipeline',
  url: 'https://hooks.acme.example/email-gateway',
  eventTypes: ['email.threat.detected', 'email.quarantined'],
  filters: { directions: ['inbound'], minSeverity: 'medium' },
  status: 'active',
  disabledReason: null,
  disabledAt: null,
  maxConcurrency: null,
  secretVersion: 1,
  secretRotatedAt: null,
  previousSecretExpiresAt: null,
  consecutiveFailures: 0,
  failingSince: null,
  lastSuccessAt: '2026-11-13T09:14:04.002Z',
  lastFailureAt: null,
  createdBy: { type: 'user', id: '0192e111-2a3b-7c4d-8e5f-6a7b8c9d0e1f' },
  createdAt: '2026-11-13T08:00:00.000Z',
  updatedAt: '2026-11-13T08:00:00.000Z',
  rowVersion: 1,
};

const exampleDelivery: DeliveryView = {
  id: '0193a2d0-1111-7a2b-8c3d-4e5f6a7b8c9d',
  eventId: '6f1d2c3b-4a59-8e7d-9c6b-5a4f3e2d1c0b',
  eventType: 'email.quarantined',
  occurredAt: '2026-11-13T09:14:03.120Z',
  status: 'succeeded',
  trigger: 'event',
  deliverySeq: 0,
  attemptCount: 2,
  nextAttemptAt: null,
  firstAttemptAt: '2026-11-13T09:14:03.500Z',
  lastAttemptAt: '2026-11-13T09:14:35.020Z',
  lastResponseCode: 200,
  lastLatencyMs: 182,
  lastError: null,
  completedAt: '2026-11-13T09:14:35.210Z',
  createdAt: '2026-11-13T09:14:03.400Z',
};

export const WEBHOOK_EXAMPLES = {
  create: {
    name: 'SIEM ingestion',
    description: 'Threat and quarantine events to the SOC pipeline',
    url: 'https://hooks.acme.example/email-gateway',
    eventTypes: ['email.threat.detected', 'email.quarantined'],
    filters: { directions: ['inbound'], minSeverity: 'medium' },
  },
  update: { expectedRowVersion: 1, status: 'paused' },
  rotate: { overlapHours: 24 },
  replay: {
    from: '2026-11-13T00:00:00Z',
    to: '2026-11-13T12:00:00Z',
    statuses: ['failed', 'dead'],
  },
  item: exampleWebhook,
  created: { ...exampleWebhook, secret: 'whsec_EXAMPLE-shown-once-store-it-now' },
  rotated: {
    id: exampleWebhook.id,
    secret: 'whsec_EXAMPLE-rotated-shown-once',
    secretVersion: 2,
    secretRotatedAt: '2026-11-13T10:00:00.000Z',
    previousSecretExpiresAt: '2026-11-14T10:00:00.000Z',
  },
  page: { data: [exampleWebhook], nextCursor: null },
  delivery: exampleDelivery,
  deliveryPage: {
    data: [
      exampleDelivery,
      {
        ...exampleDelivery,
        id: '0193a2d0-2222-7a2b-8c3d-4e5f6a7b8c9d',
        eventId: '7a2e3d4c-5b6a-8f8e-8d7c-6b5a4f3e2d1c',
        eventType: 'email.threat.detected',
        occurredAt: '2026-11-13T09:10:00.000Z',
        status: 'pending',
        attemptCount: 1,
        nextAttemptAt: '2026-11-13T09:10:31.000Z',
        lastResponseCode: 503,
        lastError: 'http_503',
        completedAt: null,
      },
    ],
    nextCursor: null,
  },
  deliveryDetail: {
    ...exampleDelivery,
    attempts: [
      {
        attemptNo: 1,
        attemptedAt: '2026-11-13T09:14:03.500Z',
        outcome: 'http_error',
        httpStatus: 503,
        latencyMs: 95,
        responseSnippet: 'upstream unavailable',
        retryAfterSeconds: 30,
        errorCode: 'http_503',
        signatureCount: 1,
      },
      {
        attemptNo: 2,
        attemptedAt: '2026-11-13T09:14:35.020Z',
        outcome: 'succeeded',
        httpStatus: 200,
        latencyMs: 182,
        responseSnippet: '{"ok":true}',
        retryAfterSeconds: null,
        errorCode: null,
        signatureCount: 1,
      },
    ],
    event: EVENT_TYPES_VIEW.data.find((t) => t.type === 'email.quarantined')!.example,
  },
  replayAccepted: { replayId: '0193a2e0-3333-7a2b-8c3d-4e5f6a7b8c9d', status: 'queued' },
  deliveryReplayAccepted: { deliveryId: '0193a2d0-4444-7a2b-8c3d-4e5f6a7b8c9d' },
  testAccepted: {
    deliveryId: '0193a2d0-5555-7a2b-8c3d-4e5f6a7b8c9d',
    eventId: '1b2c3d4e-5f60-8172-8394-a5b6c7d8e9f0',
  },
  replayView: {
    id: '0193a2e0-3333-7a2b-8c3d-4e5f6a7b8c9d',
    status: 'completed',
    from: '2026-11-13T00:00:00.000Z',
    to: '2026-11-13T12:00:00.000Z',
    statuses: ['failed', 'dead'],
    eventTypes: null,
    matchedCount: 42,
    createdCount: 42,
    truncated: false,
    errorCode: null,
    createdAt: '2026-11-13T12:05:00.000Z',
    startedAt: '2026-11-13T12:05:01.000Z',
    completedAt: '2026-11-13T12:05:03.000Z',
  },
} as const;
