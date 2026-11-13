import {
  ENGINE_OUTCOME_VALUES,
  POLICY_DECISION_SOURCE_VALUES,
  POLICY_DISPOSITION_VALUES,
  POLICY_FINAL_ACTION_VALUES,
  POLICY_RULE_ID_PATTERN,
} from '@email-gateway/event-contracts';
import { SCAN_VERDICTS } from '@email-gateway/security-contracts';
import { z } from 'zod';

/**
 * The public webhook event catalogue (step 6.2 §5, ADR-0054): ten subscribable types, all
 * version 1, plus the test-only `webhook.ping`. Every `data` schema is strict: a payload carries
 * public ids, the tenant's own domain names, codes, counts and times only — never a subject, an
 * address local part, a body, an attachment, a file name, an S3 key, a URL found in mail or a
 * secret (§2.0 invariant 1; enforced again by `assertWebhookPayloadSafe`).
 */
export const WEBHOOK_EVENT_TYPES = [
  'email.received',
  'email.scanned',
  'email.threat.detected',
  'email.policy.triggered',
  'email.quarantined',
  'email.released',
  'email.delivered',
  'email.rejected',
  'domain.verified',
  'domain.dns.failed',
] as const;
export type WebhookEventType = (typeof WEBHOOK_EVENT_TYPES)[number];

/** The test event of `POST /webhooks/{id}/test`; never subscribable. */
export const WEBHOOK_PING_TYPE = 'webhook.ping';
export type WebhookPingType = typeof WEBHOOK_PING_TYPE;
/** Every type an envelope may carry: the catalogue plus the ping. */
export type WebhookEnvelopeType = WebhookEventType | WebhookPingType;
export const WEBHOOK_ENVELOPE_TYPES: readonly WebhookEnvelopeType[] = Object.freeze([
  ...WEBHOOK_EVENT_TYPES,
  WEBHOOK_PING_TYPE,
]);

export const webhookEventTypeSchema = z.enum(WEBHOOK_EVENT_TYPES);

/** Public event severities, in rank order (`minSeverity` filters compare ranks). */
export const SEVERITIES = ['info', 'low', 'medium', 'high'] as const;
export type Severity = (typeof SEVERITIES)[number];
export const severitySchema = z.enum(SEVERITIES);

/** 0 (`info`) … 3 (`high`). */
export function severityRank(severity: Severity): number {
  const rank = SEVERITIES.indexOf(severity);
  if (rank < 0) throw new Error('Unknown severity');
  return rank;
}

/** The subscription filters (§5.3) a type's events can be narrowed by. */
export const WEBHOOK_FILTER_NAMES = ['directions', 'domainIds', 'minSeverity', 'verdicts'] as const;
export type WebhookFilterName = (typeof WEBHOOK_FILTER_NAMES)[number];

// ---------------------------------------------------------------------------------------------
// Shared building blocks
// ---------------------------------------------------------------------------------------------

const iso = z.iso.datetime();
const uuid = z.uuid();
const round = z.number().int().min(0).max(65_535);
const count = z.number().int().min(0).max(4_294_967_295);
const unique = <T>(values: readonly T[]): boolean => new Set(values).size === values.length;
const uniqueArray = <S extends z.ZodType>(item: S, min: number, max: number) =>
  z
    .array(item)
    .min(min)
    .max(max)
    .refine((values) => unique(values), { message: 'Duplicate value' });

/** A lower-case ASCII host name (punycode for IDNs), ≤ 253 characters. */
const DOMAIN_NAME_PATTERN =
  /^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?)*$/;
export const domainNameSchema = z
  .string()
  .regex(DOMAIN_NAME_PATTERN, 'Expected a lower-case ASCII domain name');

/** Dotted lower-case reason code (`spam.score`, `sandbox.static.x`), as the scan events carry. */
const reasonCode = z
  .string()
  .max(64)
  .regex(/^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/, 'Expected a dotted lower-case reason code');
const snakeCode = (max: number) =>
  z
    .string()
    .max(max)
    .regex(/^[a-z][a-z0-9_]*$/, 'Expected a snake_case code');
const engineName = snakeCode(32);
const direction = z.enum(['inbound', 'outbound', 'internal']);
const scanVerdict = z.enum(SCAN_VERDICTS);
/** Verdicts that make a round a threat (W3: `finalVerdict ∈ {spam, suspicious, malicious}`). */
export const THREAT_VERDICTS = ['spam', 'suspicious', 'malicious'] as const;
export type ThreatVerdict = (typeof THREAT_VERDICTS)[number];
const threatVerdict = z.enum(THREAT_VERDICTS);
const sha256 = z.string().regex(/^[0-9a-f]{64}$/, 'Expected a lower-case hex SHA-256');
/** `domains.status` (DomainStatus). */
export const DOMAIN_STATUSES = [
  'pending_verification',
  'verified',
  'failed',
  'disabled',
  'active',
  'suspended',
  'deleted',
] as const;
const domainStatus = z.enum(DOMAIN_STATUSES);
const dnsPurpose = z.enum(['verification', 'mx', 'spf', 'dkim', 'dmarc', 'mta_sts', 'tls_rpt']);
const dnsStatus = z.enum(['pending', 'valid', 'invalid', 'missing']);

/** Control characters (C0 and DEL) never allowed in a carried header value. */
// eslint-disable-next-line no-control-regex -- control characters are exactly what is rejected
const NO_CONTROL_CHARACTERS = /^[^\x00-\x1f\x7f]+$/;

/** Longest `internetMessageId` carried; longer (after stripping controls) → null (§5.1). */
export const INTERNET_MESSAGE_ID_MAX_LENGTH = 255;
/** Most recipient domains of a message carried in `message.recipientDomains`. */
export const MAX_RECIPIENT_DOMAINS = 20;

/**
 * `message` (§5.1): the message public id, receipt, direction, the tenant domain it belongs to,
 * the sanitized Internet Message-ID, the sender / header-from **domains** and the recipient
 * **domains** (never a local part), counts and size.
 */
export const webhookMessageSchema = z.strictObject({
  id: uuid,
  receivedAt: iso,
  direction,
  domainId: uuid.nullable(),
  internetMessageId: z
    .string()
    .min(1)
    .max(INTERNET_MESSAGE_ID_MAX_LENGTH)
    .regex(NO_CONTROL_CHARACTERS, 'No control characters')
    .nullable(),
  senderDomain: domainNameSchema.nullable(),
  headerFromDomain: domainNameSchema.nullable(),
  recipientCount: count,
  recipientDomains: uniqueArray(domainNameSchema, 0, MAX_RECIPIENT_DOMAINS),
  sizeBytes: count,
  attachmentCount: count,
});
export type WebhookMessage = z.infer<typeof webhookMessageSchema>;

/** `domain` (§5.1): the tenant's own domain. */
export const webhookDomainSchema = z.strictObject({
  id: uuid,
  name: domainNameSchema,
  status: domainStatus,
});
export type WebhookDomain = z.infer<typeof webhookDomainSchema>;

const ruleRef = z.strictObject({
  policyId: uuid,
  versionNo: z.number().int().min(1).max(4_294_967_295),
  ruleId: z.string().regex(POLICY_RULE_ID_PATTERN, 'Expected a policy rule id'),
});

// ---------------------------------------------------------------------------------------------
// Data schemas per type (§5.2)
// ---------------------------------------------------------------------------------------------

const emailReceivedData = z.strictObject({ message: webhookMessageSchema });

const emailScannedData = z.strictObject({
  message: webhookMessageSchema,
  scan: z.strictObject({
    lifecycleRound: round,
    kind: z.enum(['initial', 'rescan']),
    outcome: z.enum(['scanned', 'scan_failed']),
    verdict: scanVerdict,
    engines: z
      .array(z.strictObject({ engine: engineName, outcome: z.enum(ENGINE_OUTCOME_VALUES) }))
      .max(16)
      .refine((engines) => unique(engines.map((e) => e.engine)), {
        message: 'Duplicate engine',
      }),
    reasonCodes: uniqueArray(reasonCode, 0, 32),
    completedAt: iso,
  }),
});

const emailThreatDetectedData = z
  .strictObject({
    message: webhookMessageSchema,
    detection: z.strictObject({
      stage: z.enum(['scan', 'sandbox']),
      verdict: threatVerdict,
      riskScore: z.number().int().min(0).max(1000).nullable(),
      reasonCodes: uniqueArray(reasonCode, 0, 32),
      lifecycleRound: round,
      /** The decided final action (scan stage); null for a sandbox detection. */
      finalAction: z.enum(POLICY_FINAL_ACTION_VALUES).nullable(),
      /** The attachment (sandbox stage); null for a scan detection. */
      attachment: z
        .strictObject({
          partIndex: z.number().int().min(0).max(65_535),
          sha256,
          detectedType: snakeCode(64),
        })
        .nullable(),
    }),
  })
  .superRefine((data, ctx) => {
    const d = data.detection;
    if (d.stage === 'scan' && d.attachment !== null) {
      ctx.addIssue({
        code: 'custom',
        path: ['detection', 'attachment'],
        message: 'A scan detection names no attachment',
      });
    }
    if (d.stage === 'sandbox' && (d.attachment === null || d.finalAction !== null)) {
      ctx.addIssue({
        code: 'custom',
        path: ['detection'],
        message: 'A sandbox detection names its attachment and no final action',
      });
    }
  });

/** DSL action types (`TAG`, `WARN`, `URL_REWRITE`, `ARCHIVE`, `ALERT`, terminal actions). */
const actionType = z.string().regex(/^[A-Z][A-Z_]{0,31}$/, 'Expected an action type');

const emailPolicyTriggeredData = z.strictObject({
  message: webhookMessageSchema,
  policy: z.strictObject({
    disposition: z.enum(POLICY_DISPOSITION_VALUES),
    finalAction: z.enum(POLICY_FINAL_ACTION_VALUES),
    decisionSource: z.enum(POLICY_DECISION_SOURCE_VALUES),
    decisive: ruleRef.nullable(),
    matchedRules: z.array(ruleRef).min(1).max(16),
    actions: uniqueArray(actionType, 0, 16),
    overrideApplied: z.boolean(),
    lifecycleRound: round,
    evaluatedAt: iso,
  }),
});

/** Quarantine reason codes (QuarantineReason). */
const quarantineReason = z.enum([
  'spam',
  'bulk',
  'phishing',
  'malware',
  'bec',
  'dlp',
  'policy',
  'suspicious',
  'engine_unavailable',
  'manual',
]);

const emailQuarantinedData = z
  .strictObject({
    message: webhookMessageSchema,
    quarantine: z.strictObject({
      origin: z.enum(['policy', 'manual']),
      lifecycleRound: round,
      entryCount: z.number().int().min(1).max(4_294_967_295),
      kinds: z.strictObject({ quarantine: count, review: count }),
      reasons: uniqueArray(quarantineReason, 1, 8),
      entryIds: uniqueArray(uuid, 1, 50),
      earliestExpiresAt: iso,
    }),
  })
  .superRefine((data, ctx) => {
    const q = data.quarantine;
    if (q.kinds.quarantine + q.kinds.review !== q.entryCount) {
      ctx.addIssue({
        code: 'custom',
        path: ['quarantine', 'kinds'],
        message: 'kinds add up to entryCount',
      });
    }
    if (q.entryIds.length > q.entryCount) {
      ctx.addIssue({
        code: 'custom',
        path: ['quarantine', 'entryIds'],
        message: 'More entry ids than entries',
      });
    }
  });

const emailReleasedData = z.strictObject({
  message: webhookMessageSchema,
  release: z.strictObject({
    releaseId: uuid,
    mode: z.enum(['operator', 'self', 'approved']),
    entryIds: uniqueArray(uuid, 1, 50),
    recipientCount: z.number().int().min(1).max(4_294_967_295),
    // The approval's delivery sequence (`email_deliveries.delivery_seq`): 0 when the message had
    // no delivery before the release (a fully quarantined message), else the highest + 1.
    deliverySeq: z.number().int().min(0).max(65_535),
    approvedAt: iso,
  }),
});

const emailDeliveredData = z.strictObject({
  message: webhookMessageSchema,
  delivery: z.strictObject({
    outcome: z.enum(['complete', 'partial']),
    lifecycleRound: round,
    recipients: z.strictObject({
      delivered: count,
      failed: count,
      bounced: count,
      expired: count,
      suppressed: count,
      quarantined: count,
      discarded: count,
      other: count,
    }),
    completedAt: iso,
  }),
});

export const REJECTION_REASONS = [
  'policy_reject',
  'policy_discard',
  'quarantine_deleted',
  'review_rejected',
  'delivery_failed',
] as const;
const REJECTION_STAGE: Readonly<Record<(typeof REJECTION_REASONS)[number], string>> = {
  policy_reject: 'policy',
  policy_discard: 'policy',
  quarantine_deleted: 'quarantine',
  review_rejected: 'quarantine',
  delivery_failed: 'delivery',
};

const emailRejectedData = z
  .strictObject({
    message: webhookMessageSchema,
    rejection: z.strictObject({
      reason: z.enum(REJECTION_REASONS),
      stage: z.enum(['policy', 'quarantine', 'delivery']),
      lifecycleRound: round,
      rejectedAt: iso,
    }),
  })
  .superRefine((data, ctx) => {
    if (REJECTION_STAGE[data.rejection.reason] !== data.rejection.stage) {
      ctx.addIssue({
        code: 'custom',
        path: ['rejection', 'stage'],
        message: 'stage does not match reason',
      });
    }
  });

const domainVerifiedData = z.strictObject({
  domain: webhookDomainSchema,
  previousStatus: domainStatus.nullable(),
  verifiedAt: iso,
});

const domainDnsFailedData = z
  .strictObject({
    domain: webhookDomainSchema,
    failure: z.strictObject({
      kind: z.enum(['verification_failed', 'records_failed']),
      reason: snakeCode(64).nullable(),
      records: z
        .array(
          z.strictObject({
            purpose: dnsPurpose,
            recordKey: z.string().min(1).max(191),
            previousStatus: dnsStatus,
            status: dnsStatus,
          }),
        )
        .max(32),
      checkedAt: iso,
    }),
  })
  .superRefine((data, ctx) => {
    if (data.failure.kind === 'records_failed' && data.failure.records.length === 0) {
      ctx.addIssue({
        code: 'custom',
        path: ['failure', 'records'],
        message: 'A records failure names its records',
      });
    }
  });

const webhookPingData = z.strictObject({ subscriptionId: uuid, requestedAt: iso });

/** Strict `data` schema of every envelope type (§5.2). */
export const dataSchemas = {
  'email.received': emailReceivedData,
  'email.scanned': emailScannedData,
  'email.threat.detected': emailThreatDetectedData,
  'email.policy.triggered': emailPolicyTriggeredData,
  'email.quarantined': emailQuarantinedData,
  'email.released': emailReleasedData,
  'email.delivered': emailDeliveredData,
  'email.rejected': emailRejectedData,
  'domain.verified': domainVerifiedData,
  'domain.dns.failed': domainDnsFailedData,
  [WEBHOOK_PING_TYPE]: webhookPingData,
} as const satisfies Record<WebhookEnvelopeType, z.ZodType>;

export type WebhookEventData<T extends WebhookEnvelopeType> = z.infer<(typeof dataSchemas)[T]>;

// ---------------------------------------------------------------------------------------------
// Severity rules (§5.2)
// ---------------------------------------------------------------------------------------------

const VERDICT_SEVERITY: Readonly<Record<(typeof SCAN_VERDICTS)[number], Severity>> = {
  clean: 'info',
  unknown: 'info',
  timeout: 'info',
  error: 'info',
  spam: 'low',
  suspicious: 'medium',
  malicious: 'high',
};
/** DNS record purposes whose failure is `high` (mail flow and authentication). */
const CRITICAL_RECORD_PURPOSES: readonly string[] = ['mx', 'spf', 'dkim', 'dmarc'];

/**
 * The severity of an event of `type` with (already validated) `data`, by the fixed rules of
 * §5.2. Throws for an unknown type.
 */
export function eventSeverity<T extends WebhookEnvelopeType>(
  type: T,
  data: WebhookEventData<T>,
): Severity {
  switch (type) {
    case 'email.scanned':
      return VERDICT_SEVERITY[(data as WebhookEventData<'email.scanned'>).scan.verdict];
    case 'email.threat.detected':
      return VERDICT_SEVERITY[
        (data as WebhookEventData<'email.threat.detected'>).detection.verdict
      ];
    case 'email.policy.triggered':
      return (data as WebhookEventData<'email.policy.triggered'>).policy.disposition === 'allow'
        ? 'low'
        : 'medium';
    case 'email.quarantined':
      return 'medium';
    case 'email.rejected':
      return 'low';
    case 'domain.dns.failed': {
      const failure = (data as WebhookEventData<'domain.dns.failed'>).failure;
      if (failure.kind === 'verification_failed') return 'medium';
      return failure.records.some((r) => CRITICAL_RECORD_PURPOSES.includes(r.purpose))
        ? 'high'
        : 'medium';
    }
    case 'email.received':
    case 'email.released':
    case 'email.delivered':
    case 'domain.verified':
    case WEBHOOK_PING_TYPE:
      return 'info';
    default:
      throw new Error('Unknown webhook event type');
  }
}

// ---------------------------------------------------------------------------------------------
// Catalogue (GET /webhooks/event-types)
// ---------------------------------------------------------------------------------------------

export interface WebhookCatalogueEntry {
  type: WebhookEnvelopeType;
  /** Payload version of the type (1 for every type in 6.2). */
  version: 1;
  description: string;
  /** Human-readable severity rule. */
  severity: string;
  /** Subscription filters that narrow this type's events. */
  appliesFilters: readonly WebhookFilterName[];
  /** Whether a subscription may list the type (false for `webhook.ping`). */
  subscribable: boolean;
  /** An example `data` object (valid against `dataSchemas[type]`). */
  example: unknown;
}

const MESSAGE_FILTERS = ['directions', 'domainIds', 'minSeverity'] as const;
const VERDICT_FILTERS = ['directions', 'domainIds', 'minSeverity', 'verdicts'] as const;
const DOMAIN_FILTERS = ['domainIds', 'minSeverity'] as const;

const exampleMessage: WebhookMessage = {
  id: '0192f0c4-8a11-7c2e-9d3f-1a2b3c4d5e6f',
  receivedAt: '2026-11-13T09:14:02.481Z',
  direction: 'inbound',
  domainId: '0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b11',
  internetMessageId: '<CAF1x2y3z@mail.partner.example>',
  senderDomain: 'partner.example',
  headerFromDomain: 'partner.example',
  recipientCount: 2,
  recipientDomains: ['acme.example'],
  sizeBytes: 48_213,
  attachmentCount: 1,
};
const exampleDomain: WebhookDomain = {
  id: '0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b11',
  name: 'acme.example',
  status: 'active',
};
const examplePolicyId = '0192f0c4-9b22-7d3f-8e40-2b3c4d5e6f70';

/** One valid example `data` object per envelope type (documentation and tests). */
export const WEBHOOK_EXAMPLE_DATA: { readonly [T in WebhookEnvelopeType]: WebhookEventData<T> } = {
  'email.received': { message: exampleMessage },
  'email.scanned': {
    message: exampleMessage,
    scan: {
      lifecycleRound: 0,
      kind: 'initial',
      outcome: 'scanned',
      verdict: 'malicious',
      engines: [
        { engine: 'rspamd', outcome: 'suspicious' },
        { engine: 'attachment', outcome: 'malicious' },
        { engine: 'url', outcome: 'clean' },
      ],
      reasonCodes: ['attachment.clamav_match', 'spam.score'],
      completedAt: '2026-11-13T09:14:03.010Z',
    },
  },
  'email.threat.detected': {
    message: exampleMessage,
    detection: {
      stage: 'scan',
      verdict: 'malicious',
      riskScore: 940,
      reasonCodes: ['attachment.clamav_match'],
      lifecycleRound: 0,
      finalAction: 'quarantine',
      attachment: null,
    },
  },
  'email.policy.triggered': {
    message: exampleMessage,
    policy: {
      disposition: 'quarantine',
      finalAction: 'quarantine',
      decisionSource: 'tenant_rule',
      decisive: { policyId: examplePolicyId, versionNo: 3, ruleId: 'block-macros' },
      matchedRules: [{ policyId: examplePolicyId, versionNo: 3, ruleId: 'block-macros' }],
      actions: ['ALERT', 'TAG'],
      overrideApplied: false,
      lifecycleRound: 0,
      evaluatedAt: '2026-11-13T09:14:03.120Z',
    },
  },
  'email.quarantined': {
    message: exampleMessage,
    quarantine: {
      origin: 'policy',
      lifecycleRound: 0,
      entryCount: 2,
      kinds: { quarantine: 2, review: 0 },
      reasons: ['malware'],
      entryIds: ['0192f0c4-a133-7e40-9f51-3c4d5e6f7081', '0192f0c4-a133-7e40-9f51-3c4d5e6f7082'],
      earliestExpiresAt: '2026-12-13T09:14:03.120Z',
    },
  },
  'email.released': {
    message: exampleMessage,
    release: {
      releaseId: '0192f0c4-b244-7f51-8a62-4d5e6f708192',
      mode: 'operator',
      entryIds: ['0192f0c4-a133-7e40-9f51-3c4d5e6f7081'],
      recipientCount: 1,
      deliverySeq: 1,
      approvedAt: '2026-11-13T10:02:11.000Z',
    },
  },
  'email.delivered': {
    message: exampleMessage,
    delivery: {
      outcome: 'complete',
      lifecycleRound: 0,
      recipients: {
        delivered: 2,
        failed: 0,
        bounced: 0,
        expired: 0,
        suppressed: 0,
        quarantined: 0,
        discarded: 0,
        other: 0,
      },
      completedAt: '2026-11-13T09:14:05.900Z',
    },
  },
  'email.rejected': {
    message: exampleMessage,
    rejection: {
      reason: 'policy_reject',
      stage: 'policy',
      lifecycleRound: 0,
      rejectedAt: '2026-11-13T09:14:03.120Z',
    },
  },
  'domain.verified': {
    domain: { ...exampleDomain, status: 'verified' },
    previousStatus: 'pending_verification',
    verifiedAt: '2026-11-13T08:00:00.000Z',
  },
  'domain.dns.failed': {
    domain: exampleDomain,
    failure: {
      kind: 'records_failed',
      reason: null,
      records: [{ purpose: 'spf', recordKey: 'spf', previousStatus: 'valid', status: 'invalid' }],
      checkedAt: '2026-11-13T09:00:00.000Z',
    },
  },
  [WEBHOOK_PING_TYPE]: {
    subscriptionId: '0192f0c4-c355-7062-9b73-5e6f708192a3',
    requestedAt: '2026-11-13T09:20:00.000Z',
  },
};

const entry = (
  type: WebhookEnvelopeType,
  description: string,
  severity: string,
  appliesFilters: readonly WebhookFilterName[],
): WebhookCatalogueEntry => ({
  type,
  version: 1,
  description,
  severity,
  appliesFilters,
  subscribable: type !== WEBHOOK_PING_TYPE,
  example: WEBHOOK_EXAMPLE_DATA[type],
});

/** The catalogue (§5.2), in `WEBHOOK_EVENT_TYPES` order, then the ping. */
export const WEBHOOK_EVENT_CATALOGUE: Readonly<Record<WebhookEnvelopeType, WebhookCatalogueEntry>> =
  Object.freeze({
    'email.received': entry(
      'email.received',
      'A message was accepted and stored by the gateway.',
      'info',
      MESSAGE_FILTERS,
    ),
    'email.scanned': entry(
      'email.scanned',
      'A scan round of a message completed (initial scan or rescan).',
      'clean/unknown/timeout/error → info, spam → low, suspicious → medium, malicious → high',
      VERDICT_FILTERS,
    ),
    'email.threat.detected': entry(
      'email.threat.detected',
      'The final verdict of a message is spam, suspicious or malicious, or the sandbox found a malicious attachment after delivery.',
      'spam → low, suspicious → medium, malicious → high',
      VERDICT_FILTERS,
    ),
    'email.policy.triggered': entry(
      'email.policy.triggered',
      'At least one tenant policy rule matched a message.',
      'reject/quarantine/require_approval dispositions → medium, otherwise low',
      MESSAGE_FILTERS,
    ),
    'email.quarantined': entry(
      'email.quarantined',
      'A message was quarantined (by policy or manually) for one or more recipients.',
      'medium',
      MESSAGE_FILTERS,
    ),
    'email.released': entry(
      'email.released',
      'Quarantined recipients of a message were released for delivery.',
      'info',
      MESSAGE_FILTERS,
    ),
    'email.delivered': entry(
      'email.delivered',
      'Delivery of a message completed (all or some recipients delivered).',
      'info',
      MESSAGE_FILTERS,
    ),
    'email.rejected': entry(
      'email.rejected',
      'A stored message was rejected by policy, quarantine or delivery.',
      'low',
      MESSAGE_FILTERS,
    ),
    'domain.verified': entry(
      'domain.verified',
      'Ownership of a tenant domain was verified.',
      'info',
      DOMAIN_FILTERS,
    ),
    'domain.dns.failed': entry(
      'domain.dns.failed',
      'Domain verification failed, or a DNS record of a verified domain stopped validating.',
      'verification → medium, mx/spf/dkim/dmarc records → high, other records → medium',
      DOMAIN_FILTERS,
    ),
    [WEBHOOK_PING_TYPE]: entry(
      WEBHOOK_PING_TYPE,
      'Test event sent by POST /webhooks/{id}/test; not subscribable.',
      'info',
      [],
    ),
  });

/** True for the ten subscribable types (never `webhook.ping`). */
export function isWebhookEventType(value: string): value is WebhookEventType {
  return (WEBHOOK_EVENT_TYPES as readonly string[]).includes(value);
}

/** True for the ten types and the ping. */
export function isWebhookEnvelopeType(value: string): value is WebhookEnvelopeType {
  return (WEBHOOK_ENVELOPE_TYPES as readonly string[]).includes(value);
}
