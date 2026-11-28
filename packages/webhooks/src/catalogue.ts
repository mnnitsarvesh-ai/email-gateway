import {
  ATO_RESPONSE_COMPLETED_STATUS_VALUES,
  ATO_RESPONSE_PROVIDER_STATUS_VALUES,
  ENGINE_OUTCOME_VALUES,
  POLICY_DECISION_SOURCE_VALUES,
  POLICY_DISPOSITION_VALUES,
  POLICY_FINAL_ACTION_VALUES,
  POLICY_RULE_ID_PATTERN,
  SECURITY_INCIDENT_CHANGED_FIELD_VALUES,
} from '@email-gateway/event-contracts';
import {
  ATO_ACCOUNT_KINDS,
  ATO_RISK_LEVELS,
  SCAN_VERDICTS,
  SECURITY_INCIDENT_CATEGORIES,
  SECURITY_INCIDENT_ORIGINS,
  SECURITY_INCIDENT_SEVERITIES,
  SECURITY_INCIDENT_STATUSES,
  SECURITY_INCIDENT_SUBJECT_TYPES,
  type SecurityIncidentSeverity,
} from '@email-gateway/security-contracts';
import { z } from 'zod';

/**
 * The public webhook event catalogue (step 6.2 §5, ADR-0054; step 8.4 D16; step 8.2 D12
 * adds `integration.health_changed`; step API-4 the two `mailbox.*` types): seventeen subscribable
 * types, all version 1, plus the test-only `webhook.ping`. Every `data` schema is
 * strict: a payload carries public ids, the tenant's own domain names, codes, counts and times
 * only — never a subject, an address (local part or full), an IP address, a person's or
 * connector's name, a body, an attachment, a file name, an S3 key, a URL found in mail or a
 * secret (§2.0 invariant 1; enforced again by `assertWebhookPayloadSafe`).
 *
 * Step 8.4 adds the security incident types (`security.incident.created`,
 * `security.incident.updated`; every incident category of the shared model, ADR-0075) and the
 * account takeover types (`ato.account.risk_changed`, `ato.response.completed`). Receivers
 * filter incidents by `data.incident.category` and must **ignore unknown categories**: advanced
 * threat protection categories arrive later under the same two types.
 *
 * Step API-4 (A9.1, ADR-0106) appends the API-mode detection types `mailbox.threat.detected` and
 * `mailbox.dlp.detected` (version 1; the protection mode in `data`): detections of copies of
 * delivered mail (post-delivery). `email.threat.detected` v1 is unchanged and inline-only.
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
  // Step 8.4 D16 (security incidents of every category; account takeover).
  'security.incident.created',
  'security.incident.updated',
  'ato.account.risk_changed',
  'ato.response.completed',
  // Step 8.2 D12 (docs/plan/steps/25-m365-google-connectors.md, ADR-0079).
  'integration.health_changed',
  // Step API-4 A9.1 (docs/plan/steps/38-api-mode-parity-onboarding.md, ADR-0106).
  'mailbox.threat.detected',
  'mailbox.dlp.detected',
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

// Step 8.4 D16: security incidents and account takeover. Metadata only: public ids, codes,
// levels and times. No address, IP address or name (the account is its public id and kind).

const incidentCategory = z.enum(SECURITY_INCIDENT_CATEGORIES);
const incidentStatus = z.enum(SECURITY_INCIDENT_STATUSES);
const incidentSeverity = z.enum(SECURITY_INCIDENT_SEVERITIES);
const incidentSubject = z.strictObject({
  type: z.enum(SECURITY_INCIDENT_SUBJECT_TYPES),
  id: uuid,
});
const atoAccount = z.strictObject({ id: uuid, kind: z.enum(ATO_ACCOUNT_KINDS) });
const atoRiskLevel = z.enum(ATO_RISK_LEVELS);
/** Most reason codes of an incident (`security_incidents.reason_codes`). */
export const MAX_INCIDENT_REASON_CODES = 16;

const securityIncidentCreatedData = z.strictObject({
  incident: z.strictObject({
    id: uuid,
    category: incidentCategory,
    status: z.literal('open'),
    severity: incidentSeverity,
    origin: z.enum(SECURITY_INCIDENT_ORIGINS),
    detectedAt: iso,
    reasonCodes: uniqueArray(reasonCode, 0, MAX_INCIDENT_REASON_CODES),
  }),
  subject: incidentSubject,
});

const securityIncidentUpdatedData = z
  .strictObject({
    incident: z.strictObject({
      id: uuid,
      category: incidentCategory,
      status: incidentStatus,
      severity: incidentSeverity,
    }),
    subject: incidentSubject,
    previous: z.strictObject({ status: incidentStatus, severity: incidentSeverity }),
    changedFields: uniqueArray(z.enum(SECURITY_INCIDENT_CHANGED_FIELD_VALUES), 1, 5),
  })
  .superRefine((data, ctx) => {
    if (data.changedFields.includes('status') !== (data.incident.status !== data.previous.status)) {
      ctx.addIssue({
        code: 'custom',
        path: ['changedFields'],
        message: 'status is listed exactly when the status changed',
      });
    }
    if (
      data.changedFields.includes('severity') !==
      (data.incident.severity !== data.previous.severity)
    ) {
      ctx.addIssue({
        code: 'custom',
        path: ['changedFields'],
        message: 'severity is listed exactly when the severity changed',
      });
    }
  });

const atoAccountRiskChangedData = z
  .strictObject({
    account: atoAccount,
    risk: z.strictObject({
      score: z.number().int().min(0).max(100),
      level: atoRiskLevel,
      previousLevel: atoRiskLevel,
    }),
  })
  .superRefine((data, ctx) => {
    if (data.risk.level === data.risk.previousLevel) {
      ctx.addIssue({
        code: 'custom',
        path: ['risk', 'level'],
        message: 'Sent only when the level changes',
      });
    }
  });

const atoResponseCompletedData = z.strictObject({
  response: z.strictObject({
    id: uuid,
    type: snakeCode(48),
    status: z.enum(ATO_RESPONSE_COMPLETED_STATUS_VALUES),
    provider: snakeCode(32),
    providerStatus: z.enum(ATO_RESPONSE_PROVIDER_STATUS_VALUES).nullable(),
  }),
  incident: z.strictObject({ id: uuid }).nullable(),
  account: atoAccount,
});

/** `provider_connections.provider` (step 8.2). */
export const INTEGRATION_PROVIDERS = ['microsoft_365', 'google_workspace'] as const;
/** `provider_connections.health_status` (step 8.2). */
export const INTEGRATION_HEALTH_STATUSES = ['unknown', 'healthy', 'warning', 'critical'] as const;
export type IntegrationHealthStatus = (typeof INTEGRATION_HEALTH_STATUSES)[number];
/** Most failing check codes carried by one `integration.health_changed` event. */
export const INTEGRATION_MAX_FAILING_CHECKS = 10;
const integrationHealthStatus = z.enum(INTEGRATION_HEALTH_STATUSES);
/** A health check code (`credentials.token`, `routing.loops`, …). */
const integrationCheckCode = z
  .string()
  .max(64)
  .regex(/^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/, 'Expected a dotted lower-case check code');

/**
 * `integration.health_changed` (step 8.2 D12): metadata only — the connection's public id and
 * provider, the transition and the failing check codes. Never a tenant id, a domain list, a
 * credential, a token or provider error text.
 */
const integrationHealthChangedData = z
  .strictObject({
    connection: z.strictObject({ id: uuid, provider: z.enum(INTEGRATION_PROVIDERS) }),
    previousStatus: integrationHealthStatus,
    status: integrationHealthStatus,
    failingChecks: uniqueArray(integrationCheckCode, 0, INTEGRATION_MAX_FAILING_CHECKS),
    changedAt: iso,
  })
  .superRefine((data, ctx) => {
    if (data.previousStatus === data.status) {
      ctx.addIssue({
        code: 'custom',
        path: ['status'],
        message: 'A health transition changes the status',
      });
    }
  });

// Step API-4 A9.1: API-mode detections (copies of delivered mail). Metadata only: ids, codes,
// counts, the protection mode and times; never an address, a mailbox, a matched value or content.

/** Protection mode of a detection: `api` when a counted copy's domain is effective api. */
export const MAILBOX_PROTECTION_MODES = ['api', 'hybrid'] as const;
/** Source of the copies (`api_message_copies.source`). */
export const MAILBOX_COPY_SOURCES = ['journal', 'graph', 'gmail'] as const;
/** DLP actions that make a DLP detection (`allow` never does). */
export const MAILBOX_DLP_ACTIONS = ['alert', 'require_approval', 'quarantine', 'block'] as const;
/** Most copy public ids (`detectionIds`) and DLP category codes of one detection. */
export const MAILBOX_MAX_DETECTION_IDS = 20;
export const MAILBOX_MAX_DLP_CATEGORIES = 8;

const protectionMode = z.enum(MAILBOX_PROTECTION_MODES);
const copySource = z.enum(MAILBOX_COPY_SOURCES);
const detectionRemediation = z.strictObject({ pending: count, simulated: count, skipped: count });
const detectionIds = uniqueArray(uuid, 1, MAILBOX_MAX_DETECTION_IDS);

const mailboxThreatDetectedData = z
  .strictObject({
    message: webhookMessageSchema,
    detection: z.strictObject({
      stage: z.enum(['scan', 'sandbox']),
      verdict: threatVerdict,
      riskScore: z.number().int().min(0).max(1000).nullable(),
      reasonCodes: uniqueArray(reasonCode, 0, 32),
      protectionMode,
      direction,
      copySource,
      policyDisposition: z.enum(POLICY_DISPOSITION_VALUES).nullable(),
      mailboxCount: count,
      /** Remediation states of the counted copies (scan stage); null for a sandbox detection. */
      remediation: detectionRemediation.nullable(),
      /** The attachment (sandbox stage); null for a scan detection. */
      attachment: z
        .strictObject({
          partIndex: z.number().int().min(0).max(65_535),
          sha256,
          detectedType: snakeCode(64),
        })
        .nullable(),
      detectionIds,
      decidedAt: iso,
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
    if (d.stage === 'sandbox' && (d.attachment === null || d.remediation !== null)) {
      ctx.addIssue({
        code: 'custom',
        path: ['detection'],
        message: 'A sandbox detection names its attachment and no remediation',
      });
    }
  });

const mailboxDlpDetectedData = z
  .strictObject({
    message: webhookMessageSchema,
    dlp: z.strictObject({
      action: z.enum(MAILBOX_DLP_ACTIONS),
      verdict: snakeCode(32),
      categories: uniqueArray(snakeCode(48), 0, MAILBOX_MAX_DLP_CATEGORIES),
      protectionMode,
      direction,
      policyDisposition: z.enum(POLICY_DISPOSITION_VALUES).nullable(),
      mailboxCount: count,
      /** Remediation states of the counted copies; null for an outbound detection. */
      remediation: detectionRemediation.nullable(),
      detectionIds,
      decidedAt: iso,
    }),
  })
  .superRefine((data, ctx) => {
    if (data.dlp.direction === 'outbound' && data.dlp.remediation !== null) {
      ctx.addIssue({
        code: 'custom',
        path: ['dlp', 'remediation'],
        message: 'An outbound detection is never remediated',
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
  'security.incident.created': securityIncidentCreatedData,
  'security.incident.updated': securityIncidentUpdatedData,
  'ato.account.risk_changed': atoAccountRiskChangedData,
  'ato.response.completed': atoResponseCompletedData,
  'integration.health_changed': integrationHealthChangedData,
  'mailbox.threat.detected': mailboxThreatDetectedData,
  'mailbox.dlp.detected': mailboxDlpDetectedData,
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

/** `integration.health_changed` severity: critical → high, warning → medium, otherwise info. */
export function integrationHealthSeverity(status: IntegrationHealthStatus): Severity {
  if (status === 'critical') return 'high';
  if (status === 'warning') return 'medium';
  return 'info';
}

/**
 * Step 8.4 D16: the public severity of an incident severity or an ATO risk level (critical and
 * high → `high`, medium → `medium`, low → `low`; the exact level stays in `data`).
 */
export function incidentWebhookSeverity(level: SecurityIncidentSeverity): Severity {
  return level === 'critical' || level === 'high' ? 'high' : level;
}

/** A9.1 `mailbox.dlp.detected`: block/quarantine → high, require_approval → medium, alert → low. */
const DLP_ACTION_SEVERITY: Readonly<Record<(typeof MAILBOX_DLP_ACTIONS)[number], Severity>> = {
  block: 'high',
  quarantine: 'high',
  require_approval: 'medium',
  alert: 'low',
};

/** The public severity of a DLP detection action (A9.1). */
export function dlpDetectionSeverity(action: (typeof MAILBOX_DLP_ACTIONS)[number]): Severity {
  return DLP_ACTION_SEVERITY[action];
}

/** `ato.response.completed`: a failed execution or rollback is `medium`, every other end `info`. */
const RESPONSE_FAILURE_STATUSES: readonly string[] = ['failed', 'rollback_failed'];

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
    case 'security.incident.created':
      return incidentWebhookSeverity(
        (data as WebhookEventData<'security.incident.created'>).incident.severity,
      );
    case 'security.incident.updated':
      return incidentWebhookSeverity(
        (data as WebhookEventData<'security.incident.updated'>).incident.severity,
      );
    case 'ato.account.risk_changed':
      return incidentWebhookSeverity(
        (data as WebhookEventData<'ato.account.risk_changed'>).risk.level,
      );
    case 'ato.response.completed':
      return RESPONSE_FAILURE_STATUSES.includes(
        (data as WebhookEventData<'ato.response.completed'>).response.status,
      )
        ? 'medium'
        : 'info';
    case 'integration.health_changed':
      return integrationHealthSeverity(
        (data as WebhookEventData<'integration.health_changed'>).status,
      );
    case 'mailbox.threat.detected':
      return VERDICT_SEVERITY[
        (data as WebhookEventData<'mailbox.threat.detected'>).detection.verdict
      ];
    case 'mailbox.dlp.detected':
      return dlpDetectionSeverity((data as WebhookEventData<'mailbox.dlp.detected'>).dlp.action);
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
/** Step 8.4: incident and ATO events carry no direction, domain or verdict. */
const SEVERITY_FILTERS = ['minSeverity'] as const;
/** Connection events name no domain or message: only the severity filter applies. */
const INTEGRATION_FILTERS = ['minSeverity'] as const;

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
const exampleIncidentId = '0193a1b2-1c2d-7e3f-8a4b-5c6d7e8f9012';
const exampleAccount = { id: '0193a1b2-0a1b-7c2d-9e3f-4a5b6c7d8e9f', kind: 'mailbox' as const };

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
  'security.incident.created': {
    incident: {
      id: exampleIncidentId,
      category: 'account_takeover',
      status: 'open',
      severity: 'high',
      origin: 'detection',
      detectedAt: '2026-11-18T10:42:00.000Z',
      reasonCodes: ['ato.geo.impossible_travel', 'ato.access.new_asn'],
    },
    subject: { type: 'ato_account', id: exampleAccount.id },
  },
  'security.incident.updated': {
    incident: {
      id: exampleIncidentId,
      category: 'account_takeover',
      status: 'confirmed',
      severity: 'critical',
    },
    subject: { type: 'ato_account', id: exampleAccount.id },
    previous: { status: 'investigating', severity: 'high' },
    changedFields: ['status', 'severity'],
  },
  'ato.account.risk_changed': {
    account: exampleAccount,
    risk: { score: 78, level: 'critical', previousLevel: 'high' },
  },
  'ato.response.completed': {
    response: {
      id: '0193a1b2-2d3e-7f40-8b5c-6d7e8f901234',
      type: 'restrict_smtp_sending',
      status: 'succeeded',
      provider: 'gateway',
      providerStatus: 'applied',
    },
    incident: { id: exampleIncidentId },
    account: exampleAccount,
  },
  'integration.health_changed': {
    connection: { id: '0192f0c4-d466-7173-8c84-6f708192a3b4', provider: 'microsoft_365' },
    previousStatus: 'healthy',
    status: 'critical',
    failingChecks: ['domains.provider_verified', 'routing.loops'],
    changedAt: '2026-11-13T09:30:00.000Z',
  },
  'mailbox.threat.detected': {
    message: exampleMessage,
    detection: {
      stage: 'scan',
      verdict: 'malicious',
      riskScore: 910,
      reasonCodes: ['attachment.clamav_match'],
      protectionMode: 'api',
      direction: 'inbound',
      copySource: 'journal',
      policyDisposition: 'quarantine',
      mailboxCount: 2,
      remediation: { pending: 2, simulated: 0, skipped: 0 },
      attachment: null,
      detectionIds: [
        '0193b2c3-1a2b-7c3d-8e4f-5a6b7c8d9e01',
        '0193b2c3-1a2b-7c3d-8e4f-5a6b7c8d9e02',
      ],
      decidedAt: '2026-11-27T09:14:05.120Z',
    },
  },
  'mailbox.dlp.detected': {
    message: { ...exampleMessage, direction: 'outbound', recipientDomains: ['partner.example'] },
    dlp: {
      action: 'block',
      verdict: 'suspicious',
      categories: ['payment_card'],
      protectionMode: 'api',
      direction: 'outbound',
      policyDisposition: 'reject',
      mailboxCount: 1,
      remediation: null,
      detectionIds: ['0193b2c3-1a2b-7c3d-8e4f-5a6b7c8d9e03'],
      decidedAt: '2026-11-27T09:20:11.000Z',
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
    'security.incident.created': entry(
      'security.incident.created',
      'A security incident was opened (by detection or manually). data.incident.category names ' +
        'the category (account_takeover today). Receivers must ignore unknown categories: ' +
        'advanced threat protection categories arrive under the same type later.',
      'incident severity critical/high → high, medium → medium, low → low',
      SEVERITY_FILTERS,
    ),
    'security.incident.updated': entry(
      'security.incident.updated',
      'A security incident changed status, severity, assignee or resolution, or gained evidence ' +
        '(evidence-only updates at most once per 15 minutes per incident). Ignore unknown ' +
        'categories (data.incident.category).',
      'incident severity critical/high → high, medium → medium, low → low',
      SEVERITY_FILTERS,
    ),
    'ato.account.risk_changed': entry(
      'ato.account.risk_changed',
      'The account takeover risk level of a monitored account (mailbox, gateway user or SMTP ' +
        'connector) changed. The account is identified by its public id and kind only.',
      'risk level critical/high → high, medium → medium, low → low',
      SEVERITY_FILTERS,
    ),
    'ato.response.completed': entry(
      'ato.response.completed',
      'An account takeover response action reached its end (succeeded, failed, unsupported, ' +
        'attested, rejected, cancelled, expired, rolled back or rollback failed). Gateway ' +
        'restrictions report providerStatus applied; provider actions succeed only when confirmed.',
      'failed/rollback_failed → medium, otherwise info',
      SEVERITY_FILTERS,
    ),
    'integration.health_changed': entry(
      'integration.health_changed',
      'The health of a Microsoft 365 or Google Workspace connection changed (step 8.2): the connection id, provider, previous and new status and the failing check codes.',
      'critical → high, warning → medium, healthy/unknown → info',
      INTEGRATION_FILTERS,
    ),
    'mailbox.threat.detected': entry(
      'mailbox.threat.detected',
      'API mode (step API-4): a copy of a delivered message (journal copy or mailbox feed) was ' +
        'detected as spam, suspicious or malicious after delivery, by the scan or later by the ' +
        'sandbox. data.detection.protectionMode is api or hybrid; email.threat.detected stays ' +
        'inline-only, so subscribe to both types for every detection.',
      'spam → low, suspicious → medium, malicious → high',
      VERDICT_FILTERS,
    ),
    'mailbox.dlp.detected': entry(
      'mailbox.dlp.detected',
      'API mode (step API-4): data loss prevention detected sensitive data in a copy of a ' +
        'delivered message (inbound, internal or outbound). Category codes and the action only; ' +
        'outbound detections are never remediated.',
      'block/quarantine → high, require_approval → medium, alert → low',
      MESSAGE_FILTERS,
    ),
    [WEBHOOK_PING_TYPE]: entry(
      WEBHOOK_PING_TYPE,
      'Test event sent by POST /webhooks/{id}/test; not subscribable.',
      'info',
      [],
    ),
  });

/** True for the seventeen subscribable types (never `webhook.ping`). */
export function isWebhookEventType(value: string): value is WebhookEventType {
  return (WEBHOOK_EVENT_TYPES as readonly string[]).includes(value);
}

/** True for the seventeen types and the ping. */
export function isWebhookEnvelopeType(value: string): value is WebhookEnvelopeType {
  return (WEBHOOK_ENVELOPE_TYPES as readonly string[]).includes(value);
}
