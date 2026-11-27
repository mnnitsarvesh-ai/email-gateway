import {
  AUTO_CLAWBACK_MODES,
  CLAWBACK_APPROVAL_REASONS,
  CLAWBACK_APPROVAL_STATUSES,
  CLAWBACK_CHOSEN_VERDICTS,
  CLAWBACK_DECISION_MODES,
  CLAWBACK_MATCH_KEYS,
  CLAWBACK_PLANNED_ACTIONS,
  CLAWBACK_RESTORE_STATUSES,
  CLAWBACK_SIGNAL_KINDS,
  CLAWBACK_SIGNAL_LEVELS,
  CLAWBACK_STATUSES,
  CLAWBACK_TARGET_RESTORE_STATUSES,
  CLAWBACK_TARGET_STATUSES,
  CLAWBACK_TRIGGERS,
  ORG_SETTINGS_BOUNDS,
  orgSettingsSchema,
  REPORT_ANALYST_VERDICTS,
  REPORT_ASSESSMENTS,
  REPORT_FEEDBACK_STATES,
  REPORT_IDENTIFICATIONS,
  REPORT_STATUSES,
} from '@email-gateway/mailbox-api';
import { z } from 'zod';
import { defineListQuery } from '../../../http/listing/list-query';
import { stripControlCharacters } from '../../webhooks/domain/control-chars';
import { CAMPAIGN_SENDER_SUBJECT_HOURS } from '../api-mode.constants';
import {
  COPY_REMEDIATION_STATES,
  COPY_VERDICTS,
  COVERAGE_STATES,
  MAILBOX_STATUSES,
  PROVIDERS,
  PublicIdSchema,
} from './api-mode.schemas';

/**
 * Request and response shapes of the API-mode clawback, report and settings routes (step API-3
 * C9, C11, C14, docs/plan/steps/37-api-mode-clawback-reporting.md; ADR-0103, ADR-0104). Request
 * schemas are strict. Views carry hashes truncated, sender addresses and subject keys marked as
 * untrusted operator/mail data, codes and counts; never message content, provider ids or another
 * organization's rows. Target rows show the mailbox address masked and no sender or subject
 * without `remediation:purge`.
 */

const isoInstant = z.iso.datetime({ offset: true });
const nullableInstant = isoInstant.nullable();
const HEX64 = /^[0-9a-fA-F]{64}$/;

/** Untrusted free text: trimmed, control characters removed, 1-500. */
const reasonField = z
  .string()
  .max(2000)
  .transform((v) => stripControlCharacters(v).trim())
  .pipe(z.string().min(1).max(500))
  .describe('Why (1-500 characters; stored with the request and in the audit row)');

const expectedRowVersion = z
  .number()
  .int()
  .min(1)
  .max(4_294_967_295)
  .describe('The `rowVersion` read (CAS; a mismatch is `409`)');

const actorSchema = z.object({
  type: z.enum(['system', 'user', 'api_key']),
  userId: PublicIdSchema.nullable(),
});

// ---- clawbacks: create (C14 #1) ----------------------------------------------------------------

const hex64List = (max: number) =>
  z.array(z.string().regex(HEX64, 'must be a hex SHA-256')).min(1).max(max);

export const ExpandSchema = z
  .strictObject({
    attachments: z.boolean().optional().describe("Add the seed's attachment SHA-256s (≤ 20)"),
    urls: z.boolean().optional().describe("Add the seed's URL identity hashes (≤ 20)"),
    senderSubjectHours: z
      .number()
      .int()
      .min(CAMPAIGN_SENDER_SUBJECT_HOURS.min)
      .max(CAMPAIGN_SENDER_SUBJECT_HOURS.max)
      .optional()
      .describe("Add the seed's sender + subject key within ± this many hours (1-168)"),
  })
  .describe('Campaign expansion of a seed (C2.4)');
export type ExpandBody = z.output<typeof ExpandSchema>;

export const CreateClawbackBodySchema = z
  .strictObject({
    criteria: z
      .strictObject({
        messageId: z
          .string()
          .min(1)
          .max(998)
          .optional()
          .describe('Internet Message-ID (with or without angle brackets)'),
        attachmentSha256: hex64List(20).optional().describe('Attachment SHA-256s (1-20)'),
        url: z.string().min(1).max(8192).optional().describe('A URL (normalized to its identity)'),
        urlSha256: hex64List(20).optional().describe('URL identity SHA-256s (1-20)'),
        sender: z.string().min(3).max(320).optional().describe('Sender address (with `subject`)'),
        subject: z.string().min(1).max(998).optional().describe('Subject (with `sender`)'),
        from: isoInstant.optional().describe('Window start (with `to`; ≤ 31 days)'),
        to: isoInstant.optional().describe('Window end'),
      })
      .optional(),
    seedDetectionId: PublicIdSchema.optional().describe(
      'A detection (copy) to seed the search from (alone: its Message-ID)',
    ),
    expand: ExpandSchema.optional(),
    directions: z
      .array(z.enum(['inbound', 'internal']))
      .min(1)
      .max(2)
      .optional()
      .describe('Copy directions searched (default both)'),
    reason: reasonField,
  })
  .refine((b) => b.criteria !== undefined || b.seedDetectionId !== undefined, {
    message: 'give criteria or seedDetectionId',
    path: ['criteria'],
  });
export type CreateClawbackBody = z.output<typeof CreateClawbackBodySchema>;

export const ClawbackCreatedSchema = z.object({
  id: PublicIdSchema,
  status: z.literal('searching'),
  trigger: z.enum(CLAWBACK_TRIGGERS),
  rowVersion: z.number().int(),
});
export type ClawbackCreatedView = z.infer<typeof ClawbackCreatedSchema>;

// ---- clawbacks: views (C14 #2, #3) -------------------------------------------------------------

const countsSchema = z.object({
  targetsTotal: z.number().int(),
  mailboxesTotal: z.number().int(),
  targetsEligible: z.number().int(),
  mailboxesEligible: z.number().int().describe('Distinct mailboxes of the eligible targets'),
  skipped: z.number().int(),
  simulated: z.number().int(),
  queued: z.number().int(),
  succeeded: z.number().int(),
  failed: z.number().int(),
  cancelled: z.number().int(),
});

const approvalSchema = z.object({
  required: z.boolean(),
  status: z.enum(CLAWBACK_APPROVAL_STATUSES).nullable(),
  reasons: z.array(z.enum(CLAWBACK_APPROVAL_REASONS)),
  requestedAt: nullableInstant,
  expiresAt: nullableInstant,
  decidedAt: nullableInstant,
});

const restoreSchema = z.object({
  status: z.enum(CLAWBACK_RESTORE_STATUSES),
  queued: z.number().int(),
  succeeded: z.number().int(),
  failed: z.number().int(),
  skipped: z.number().int(),
});

export const ClawbackSchema = z.object({
  id: PublicIdSchema,
  trigger: z.enum(CLAWBACK_TRIGGERS),
  status: z.enum(CLAWBACK_STATUSES),
  decisionMode: z.enum(CLAWBACK_DECISION_MODES).nullable(),
  action: z.enum(['move_quarantine', 'move_junk', 'soft_delete', 'hard_delete']).nullable(),
  signalKind: z.enum(CLAWBACK_SIGNAL_KINDS).nullable(),
  counts: countsSchema,
  approval: approvalSchema,
  restore: restoreSchema,
  cancelRequested: z.boolean(),
  reportId: PublicIdSchema.nullable().describe('The report of a report clawback'),
  lastErrorCode: z.string().nullable(),
  signalAt: isoInstant,
  createdAt: isoInstant,
  submittedAt: nullableInstant,
  startedAt: nullableInstant,
  completedAt: nullableInstant,
  updatedAt: isoInstant,
  rowVersion: z.number().int().describe('CAS version (send it as `expectedRowVersion`)'),
});
export type ClawbackView = z.infer<typeof ClawbackSchema>;

export const ClawbackListQuerySchema = defineListQuery({
  filters: {
    status: { type: 'enum', values: CLAWBACK_STATUSES, maxValues: 14 },
    trigger: { type: 'enum', values: CLAWBACK_TRIGGERS, maxValues: 5 },
    approvalStatus: { type: 'enum', values: CLAWBACK_APPROVAL_STATUSES, maxValues: 5 },
  },
  sorts: ['-createdAt'],
  defaultSort: '-createdAt',
  range: true,
});
export type ClawbackListQuery = z.output<typeof ClawbackListQuerySchema>;

export const CLAWBACK_LIST_PARAMETERS: Record<string, string> = {
  status: `${CLAWBACK_STATUSES.map((s) => `\`${s}\``).join(', ')}; comma list`,
  trigger: '`late_verdict`, `threat_intel`, `campaign`, `report`, `admin`; comma list',
  approvalStatus: '`pending`, `approved`, `denied`, `expired`, `cancelled`; comma list',
  from: 'Start of the creation window (default `to` − 30 days; at most 93 days)',
  to: 'End of the creation window (exclusive; default now)',
  sort: '`-createdAt` (newest first)',
  limit: 'Page size, 1-100 (default 25)',
  cursor: '`nextCursor` of the previous page',
};

export const ClawbackPageSchema = z.object({
  data: z.array(ClawbackSchema),
  nextCursor: z.string().nullable(),
});
export type ClawbackPage = z.infer<typeof ClawbackPageSchema>;

const criteriaViewSchema = z.object({
  window: z.object({ from: isoInstant, to: isoInstant }),
  directions: z.array(z.enum(['inbound', 'internal'])),
  keys: z.object({
    messageIdHashes: z.array(z.string()).describe('Dedupe Message-ID hashes (truncated)'),
    attachmentSha256: z.array(z.string()).describe('Attachment SHA-256s (truncated)'),
    urlSha256: z.array(z.string()).describe('URL identity hashes (truncated)'),
    urlDomains: z.array(z.string()),
    senders: z.array(z.string()).describe('Sender addresses (untrusted)'),
    senderDomains: z.array(z.string()),
    senderSubject: z
      .object({
        sender: z.string().describe('Untrusted'),
        subjectKey: z.string().describe('Normalized subject key (untrusted)'),
      })
      .nullable(),
  }),
});

export const ClawbackDetailSchema = ClawbackSchema.extend({
  criteria: criteriaViewSchema,
  signal: z.object({
    kind: z.enum(CLAWBACK_SIGNAL_KINDS).nullable(),
    verdict: z.enum(COPY_VERDICTS).nullable().describe('The facts the policy decides on (C3)'),
    level: z.enum(CLAWBACK_SIGNAL_LEVELS).nullable(),
    hardBlocks: z.array(z.string()),
    seedDetectionId: PublicIdSchema.nullable(),
  }),
  requestedBy: actorSchema,
  submittedBy: PublicIdSchema.nullable().describe('The user who submitted it'),
  requestReason: z.string().nullable().describe('Operator-typed (untrusted)'),
  approvalDecision: z.object({
    decidedBy: PublicIdSchema.nullable().describe('The second person (approver or denier)'),
    reason: z.string().nullable().describe('Operator-typed (untrusted)'),
  }),
  hints: z.object({
    canSubmit: z.boolean(),
    canApprove: z
      .boolean()
      .describe('The caller may approve or deny (a pending request; not the requester/submitter)'),
    canCancel: z.boolean(),
    canRestore: z.boolean().describe('Also needs `quarantine:release`'),
  }),
});
export type ClawbackDetailView = z.infer<typeof ClawbackDetailSchema>;

// ---- clawbacks: targets (C14 #4) ---------------------------------------------------------------

export const ClawbackTargetListQuerySchema = defineListQuery({
  filters: {
    status: { type: 'enum', values: CLAWBACK_TARGET_STATUSES, maxValues: 7 },
    restoreStatus: { type: 'enum', values: CLAWBACK_TARGET_RESTORE_STATUSES, maxValues: 5 },
    mailboxId: { type: 'publicId', maxValues: 1 },
  },
  sorts: ['id'],
  defaultSort: 'id',
});
export type ClawbackTargetListQuery = z.output<typeof ClawbackTargetListQuerySchema>;

export const CLAWBACK_TARGET_PARAMETERS: Record<string, string> = {
  status: '`matched`, `skipped`, `simulated`, `queued`, `succeeded`, `failed`, `cancelled`',
  restoreStatus: '`none`, `queued`, `succeeded`, `failed`, `skipped`',
  mailboxId: 'A mailbox public id',
  sort: '`id` (materialization order)',
  limit: 'Page size, 1-100 (default 25)',
  cursor: '`nextCursor` of the previous page',
};

export const ClawbackTargetSchema = z.object({
  mailbox: z.object({
    id: PublicIdSchema,
    address: z
      .string()
      .describe('The mailbox address (local part masked without `remediation:purge`)'),
  }),
  connectionId: PublicIdSchema,
  detectionId: PublicIdSchema.nullable().describe('null once the copy is past its retention'),
  receivedAt: isoInstant,
  headerFrom: z
    .string()
    .nullable()
    .describe('Header From of the copy (untrusted; only with `remediation:purge`)'),
  subject: z
    .string()
    .nullable()
    .describe('Subject of the copy (untrusted; only with `remediation:purge`)'),
  matchKeys: z.array(z.enum(CLAWBACK_MATCH_KEYS)),
  copyRemediationState: z.enum(COPY_REMEDIATION_STATES).nullable(),
  status: z.enum(CLAWBACK_TARGET_STATUSES),
  plannedAction: z.enum(CLAWBACK_PLANNED_ACTIONS).nullable(),
  reasonCode: z.string().nullable().describe('Skip or result code (codes only)'),
  remediationId: PublicIdSchema.nullable().describe('The mailbox action of the target'),
  restoreStatus: z.enum(CLAWBACK_TARGET_RESTORE_STATUSES),
  restoreReasonCode: z.string().nullable(),
});
export type ClawbackTargetView = z.infer<typeof ClawbackTargetSchema>;

export const ClawbackTargetPageSchema = z.object({
  data: z.array(ClawbackTargetSchema),
  nextCursor: z.string().nullable(),
});
export type ClawbackTargetPage = z.infer<typeof ClawbackTargetPageSchema>;

// ---- clawbacks: submit, approve, deny, cancel, restore (C14 #5-#10) ---------------------------

export const SubmitClawbackBodySchema = z.discriminatedUnion('mode', [
  z.strictObject({
    mode: z.literal('policy'),
    verdict: z
      .enum(CLAWBACK_CHOSEN_VERDICTS)
      .optional()
      .describe('The verdict the policy decides on (default: the signal’s facts, else phishing)'),
    level: z.enum(CLAWBACK_SIGNAL_LEVELS).optional().describe('Default `critical`'),
    reason: reasonField,
    expectedRowVersion,
  }),
  z.strictObject({
    mode: z.literal('explicit'),
    action: z
      .enum(['move_quarantine', 'move_junk', 'soft_delete'])
      .describe('Hard delete is a separate portal-only operation'),
    reason: reasonField,
    expectedRowVersion,
  }),
]);
export type SubmitClawbackBody = z.output<typeof SubmitClawbackBodySchema>;

export const DecisionBodySchema = z.strictObject({ reason: reasonField, expectedRowVersion });
export type DecisionBody = z.output<typeof DecisionBodySchema>;

export const ReasonBodySchema = z.strictObject({ reason: reasonField });
export type ReasonBody = z.output<typeof ReasonBodySchema>;

export const SubmitClawbackResponseSchema = z.object({
  id: PublicIdSchema,
  status: z.enum(['queued', 'pending_approval']),
  requiresApproval: z.boolean(),
  approvalReasons: z.array(z.enum(CLAWBACK_APPROVAL_REASONS)),
  approvalExpiresAt: nullableInstant,
  rowVersion: z.number().int(),
});
export type SubmitClawbackResponseView = z.infer<typeof SubmitClawbackResponseSchema>;

// ---- reports (C14 #11-#14) ---------------------------------------------------------------------

const scanSchema = z.object({
  verdict: z.enum(COPY_VERDICTS).nullable(),
  riskScore: z.number().int().nullable(),
  level: z.enum(['none', 'low', 'medium', 'high', 'critical']).nullable(),
});

export const ReportSchema = z.object({
  id: PublicIdSchema,
  status: z.enum(REPORT_STATUSES),
  reporterAddress: z.string().describe('The reporter (untrusted)'),
  reportedAt: isoInstant,
  identification: z.enum(REPORT_IDENTIFICATIONS).nullable(),
  assessment: z.enum(REPORT_ASSESSMENTS).nullable().describe('Automatic pre-triage hint'),
  analystVerdict: z.enum(REPORT_ANALYST_VERDICTS).nullable(),
  scan: scanSchema,
  groupSize: z.number().int().describe('Reports of the same original (1 when ungrouped)'),
  clawbackId: PublicIdSchema.nullable(),
  rejectReason: z.string().nullable(),
  rowVersion: z.number().int(),
});
export type ReportView = z.infer<typeof ReportSchema>;

export const ReportListQuerySchema = defineListQuery({
  filters: {
    status: { type: 'enum', values: REPORT_STATUSES, maxValues: 7 },
    assessment: { type: 'enum', values: REPORT_ASSESSMENTS, maxValues: 4 },
    analystVerdict: { type: 'enum', values: REPORT_ANALYST_VERDICTS, maxValues: 5 },
    reporter: { type: 'email', maxLength: 320 },
  },
  sorts: ['-reportedAt'],
  defaultSort: '-reportedAt',
  range: true,
});
export type ReportListQuery = z.output<typeof ReportListQuerySchema>;

export const REPORT_LIST_PARAMETERS: Record<string, string> = {
  status:
    '`received`, `parsing`, `scanning`, `pending_triage`, `in_review`, `resolved`, `rejected`; ' +
    'comma list',
  assessment: '`malicious`, `suspicious`, `clean`, `unknown`; comma list',
  analystVerdict: '`malicious`, `phishing_simulation`, `spam`, `clean`, `inconclusive`; comma list',
  reporter: 'The reporter address (exact, case-insensitive)',
  from: 'Start of the report window (default `to` − 30 days; at most 93 days)',
  to: 'End of the report window (exclusive; default now)',
  sort: '`-reportedAt` (newest first)',
  limit: 'Page size, 1-100 (default 25)',
  cursor: '`nextCursor` of the previous page',
};

export const ReportPageSchema = z.object({
  data: z.array(ReportSchema),
  nextCursor: z.string().nullable(),
});
export type ReportPage = z.infer<typeof ReportPageSchema>;

export const ReportDetailSchema = ReportSchema.extend({
  reporter: z.object({
    address: z.string().describe('Untrusted'),
    mailboxId: PublicIdSchema.nullable(),
    userId: PublicIdSchema.nullable(),
  }),
  reportMailbox: z.object({ id: PublicIdSchema, address: z.string() }),
  original: z
    .object({
      messageIdHash: z.string().nullable().describe('Dedupe Message-ID hash (truncated)'),
      sender: z.string().nullable().describe('The original’s From (untrusted)'),
      subjectKey: z.string().nullable().describe('The original’s subject key (untrusted)'),
      date: nullableInstant,
      attachmentCount: z.number().int(),
      urlCount: z.number().int(),
      extraOriginals: z.number().int(),
    })
    .nullable(),
  originalDetectionId: PublicIdSchema.nullable().describe(
    'The original’s copy in the tenant (a detection), when found',
  ),
  originalIngested: z.boolean().describe('The attached original was ingested and scanned'),
  analyst: z.object({
    verdict: z.enum(REPORT_ANALYST_VERDICTS).nullable(),
    note: z.string().nullable().describe('Operator-typed (untrusted)'),
    triagedBy: PublicIdSchema.nullable(),
    triagedAt: nullableInstant,
  }),
  group: z.object({
    size: z.number().int(),
    members: z
      .array(
        z.object({
          id: PublicIdSchema,
          status: z.enum(REPORT_STATUSES),
          reporterAddress: z.string().describe('Untrusted'),
          reportedAt: isoInstant,
        }),
      )
      .describe('Other reports of the same original (≤ 50)'),
  }),
  history: z
    .array(
      z.object({
        at: isoInstant,
        actor: actorSchema,
        from: z.string().nullable(),
        to: z.string().nullable(),
        verdict: z.string().nullable(),
        reopened: z.boolean(),
      }),
    )
    .describe('Triage history (from the audit rows, newest first, ≤ 50)'),
  feedback: z.object({
    acknowledgement: z.enum(REPORT_FEEDBACK_STATES),
    result: z.enum(REPORT_FEEDBACK_STATES),
  }),
  updatedAt: isoInstant,
});
export type ReportDetailView = z.infer<typeof ReportDetailSchema>;

export const TriageBodySchema = z.strictObject({
  status: z.enum(['in_review', 'resolved', 'rejected']),
  verdict: z
    .enum(REPORT_ANALYST_VERDICTS)
    .optional()
    .describe('Required for `resolved`; not allowed otherwise'),
  note: z
    .string()
    .max(4000)
    .transform((v) => stripControlCharacters(v).trim())
    .pipe(z.string().max(1000))
    .optional()
    .describe('Analyst note (≤ 1000; untrusted; never in the audit row)'),
  notifyReporter: z
    .boolean()
    .optional()
    .describe('Send the result e-mail (default: the organization’s report feedback setting)'),
  applyToGroup: z
    .boolean()
    .optional()
    .describe('A resolve also resolves the open reports of the same original (default true)'),
  expectedRowVersion,
});
export type TriageBody = z.output<typeof TriageBodySchema>;

export const TriageResponseSchema = z.object({
  report: ReportSchema,
  groupResolved: z.number().int().describe('Other reports of the group resolved with it'),
  feedbackQueued: z.number().int().describe('Result e-mails requested'),
});
export type TriageResponseView = z.infer<typeof TriageResponseSchema>;

export const ReportClawbackBodySchema = z.strictObject({
  expand: ExpandSchema.optional(),
  reason: reasonField,
});
export type ReportClawbackBody = z.output<typeof ReportClawbackBodySchema>;

export const ReportClawbackResponseSchema = z.object({
  reportId: PublicIdSchema,
  clawbackId: PublicIdSchema,
  status: z.literal('searching'),
  trigger: z.enum(['report', 'campaign']),
});
export type ReportClawbackResponseView = z.infer<typeof ReportClawbackResponseSchema>;

// ---- report mailboxes (C14 #15-#17) ------------------------------------------------------------

export const ReportMailboxSchema = z.object({
  id: PublicIdSchema,
  address: z.string(),
  connectionId: PublicIdSchema,
  provider: z.enum(PROVIDERS),
  status: z.enum(MAILBOX_STATUSES),
  coverage: z.enum(COVERAGE_STATES),
  domain: z.object({ id: PublicIdSchema, name: z.string() }).nullable(),
  reportMailbox: z.boolean(),
  reportMailboxAt: nullableInstant,
  lastReportAt: nullableInstant,
});
export type ReportMailboxView = z.infer<typeof ReportMailboxSchema>;

export const ReportMailboxListSchema = z.object({
  data: z.array(ReportMailboxSchema),
  max: z.number().int().describe('Most report mailboxes allowed (API_MODE_REPORT_MAILBOXES_MAX)'),
});
export type ReportMailboxListView = z.infer<typeof ReportMailboxListSchema>;

export const AddReportMailboxBodySchema = z.strictObject({
  address: z.string().min(3).max(320).describe('The mailbox address (primary or alias)'),
  reason: reasonField,
});
export type AddReportMailboxBody = z.output<typeof AddReportMailboxBodySchema>;

export const SetReportMailboxBodySchema = z.strictObject({
  enabled: z.boolean(),
  reason: reasonField,
});
export type SetReportMailboxBody = z.output<typeof SetReportMailboxBodySchema>;

export const ReportMailboxChangeSchema = z.object({
  mailbox: ReportMailboxSchema,
  created: z.boolean().describe('A mailbox row was created for the address (status `discovered`)'),
  changed: z.boolean(),
});
export type ReportMailboxChangeView = z.infer<typeof ReportMailboxChangeSchema>;

// ---- settings (C14 #18, #19) -------------------------------------------------------------------

export const OrgSettingsValuesSchema = z.object({
  internalMailEnabled: z.boolean(),
  autoClawback: z.enum(AUTO_CLAWBACK_MODES),
  autoMaxMailboxes: z.number().int(),
  purgeApprovalMailboxes: z.number().int(),
  clawbackLookbackDays: z.number().int(),
  tiMinConfidence: z.number().int(),
  reportAckEnabled: z.boolean(),
  reportFeedbackEnabled: z.boolean(),
});

const bound = z.object({ min: z.number().int(), max: z.number().int() });

export const OrgSettingsViewSchema = z.object({
  settings: OrgSettingsValuesSchema,
  source: z.enum(['row', 'defaults']).describe('`defaults`: no settings row yet'),
  rowVersion: z
    .number()
    .int()
    .nullable()
    .describe('CAS version (null: no row; send `expectedRowVersion: null` to create it)'),
  updatedAt: nullableInstant,
  defaults: OrgSettingsValuesSchema,
  bounds: z.object({
    autoMaxMailboxes: bound,
    purgeApprovalMailboxes: bound,
    clawbackLookbackDays: bound,
    tiMinConfidence: bound,
  }),
  platform: z.object({
    hardDeleteAvailable: z.boolean().describe('API_MODE_HARD_DELETE_ENABLED'),
    clawbackMaxWindowDays: z.number().int(),
    purgeApprovalTtlHours: z.number().int(),
    reportMailboxesMax: z.number().int(),
  }),
});
export type OrgSettingsView = z.infer<typeof OrgSettingsViewSchema>;

export const PutOrgSettingsBodySchema = orgSettingsSchema.extend({
  reason: reasonField,
  expectedRowVersion: expectedRowVersion
    .nullable()
    .describe('The `rowVersion` read (null when no settings row exists: the PUT creates it)'),
});
export type PutOrgSettingsBody = z.output<typeof PutOrgSettingsBodySchema>;

export const OrgSettingsChangeSchema = OrgSettingsViewSchema.extend({
  changed: z.array(z.string()).describe('The settings that changed'),
  created: z.boolean(),
});
export type OrgSettingsChangeView = z.infer<typeof OrgSettingsChangeSchema>;

export { ORG_SETTINGS_BOUNDS };

// ---- examples (non-secret placeholders) ------------------------------------------------------

const CLAWBACK = '0192f3a0-eeee-7000-8000-00000000000e';
const REPORT = '0192f3a0-ffff-7000-8000-00000000000f';
const OTHER_REPORT = '0192f3a0-ffff-7000-8000-000000000010';
const DETECTION = '0192f3a0-6666-7000-8000-000000000006';
const MAILBOX = '0192f3a0-5555-7000-8000-000000000005';
const REPORT_MAILBOX = '0192f3a0-5555-7000-8000-000000000015';
const CONNECTION = '0192f3a0-3333-7000-8000-000000000003';
const DOMAIN = '0192f3a0-2222-7000-8000-000000000002';
const ACTION = '0192f3a0-8888-7000-8000-000000000008';
const USER = '0192f3a0-cccc-7000-8000-00000000000c';
const USER2 = '0192f3a0-cccc-7000-8000-00000000000d';
const T = '2026-11-27T09:00:00.000Z';
const HASH = '9b1d…';

const clawback = {
  id: CLAWBACK,
  trigger: 'admin' as const,
  status: 'pending_approval' as const,
  decisionMode: 'explicit' as const,
  action: 'move_junk' as const,
  signalKind: 'admin' as const,
  counts: {
    targetsTotal: 64,
    mailboxesTotal: 61,
    targetsEligible: 62,
    mailboxesEligible: 60,
    skipped: 2,
    simulated: 0,
    queued: 0,
    succeeded: 0,
    failed: 0,
    cancelled: 0,
  },
  approval: {
    required: true,
    status: 'pending' as const,
    reasons: ['mailbox_threshold' as const],
    requestedAt: T,
    expiresAt: '2026-11-30T09:00:00.000Z',
    decidedAt: null,
  },
  restore: { status: 'none' as const, queued: 0, succeeded: 0, failed: 0, skipped: 0 },
  cancelRequested: false,
  reportId: null,
  lastErrorCode: null,
  signalAt: '2026-11-27T08:55:00.000Z',
  createdAt: '2026-11-27T08:55:00.000Z',
  submittedAt: T,
  startedAt: null,
  completedAt: null,
  updatedAt: T,
  rowVersion: 4,
};

const report = {
  id: REPORT,
  status: 'pending_triage' as const,
  reporterAddress: 'alex@contoso.example',
  reportedAt: T,
  identification: 'attachment' as const,
  assessment: 'malicious' as const,
  analystVerdict: null,
  scan: { verdict: 'phishing' as const, riskScore: 910, level: 'critical' as const },
  groupSize: 2,
  clawbackId: null,
  rejectReason: null,
  rowVersion: 3,
};

const reportMailbox = {
  id: REPORT_MAILBOX,
  address: 'report-phishing@contoso.example',
  connectionId: CONNECTION,
  provider: 'microsoft_365' as const,
  status: 'disabled' as const,
  coverage: 'covered' as const,
  domain: { id: DOMAIN, name: 'contoso.example' },
  reportMailbox: true,
  reportMailboxAt: T,
  lastReportAt: T,
};

const settings = {
  internalMailEnabled: true,
  autoClawback: 'enforce' as const,
  autoMaxMailboxes: 500,
  purgeApprovalMailboxes: 50,
  clawbackLookbackDays: 14,
  tiMinConfidence: 80,
  reportAckEnabled: true,
  reportFeedbackEnabled: true,
};

const settingsView = {
  settings,
  source: 'row' as const,
  rowVersion: 2,
  updatedAt: T,
  defaults: settings,
  bounds: {
    autoMaxMailboxes: { min: 1, max: 20_000 },
    purgeApprovalMailboxes: { min: 1, max: 10_000 },
    clawbackLookbackDays: { min: 1, max: 60 },
    tiMinConfidence: { min: 50, max: 100 },
  },
  platform: {
    hardDeleteAvailable: false,
    clawbackMaxWindowDays: 31,
    purgeApprovalTtlHours: 72,
    reportMailboxesMax: 5,
  },
};

export const CLAWBACK_EXAMPLES = {
  create: {
    criteria: {
      messageId: '<campaign-1234@fabrikam.example>',
      from: '2026-11-26T00:00:00.000Z',
      to: '2026-11-27T09:00:00.000Z',
    },
    reason: 'Phishing campaign reported by the SOC',
  },
  createSeeded: {
    seedDetectionId: DETECTION,
    expand: { attachments: true, urls: true, senderSubjectHours: 72 },
    reason: 'Expand the campaign from the reported detection',
  },
  created: { id: CLAWBACK, status: 'searching' as const, trigger: 'admin' as const, rowVersion: 1 },
  clawback,
  clawbackPage: { data: [clawback], nextCursor: null },
  clawbackDetail: {
    ...clawback,
    criteria: {
      window: { from: '2026-11-26T00:00:00.000Z', to: T },
      directions: ['inbound' as const, 'internal' as const],
      keys: {
        messageIdHashes: [HASH],
        attachmentSha256: [],
        urlSha256: [],
        urlDomains: [],
        senders: [],
        senderDomains: [],
        senderSubject: null,
      },
    },
    signal: {
      kind: 'admin' as const,
      verdict: null,
      level: null,
      hardBlocks: [],
      seedDetectionId: null,
    },
    requestedBy: { type: 'user' as const, userId: USER },
    submittedBy: USER,
    requestReason: 'Phishing campaign reported by the SOC',
    approvalDecision: { decidedBy: null, reason: null },
    hints: { canSubmit: false, canApprove: true, canCancel: true, canRestore: false },
  },
  targetPage: {
    data: [
      {
        mailbox: { id: MAILBOX, address: 'a***@contoso.example' },
        connectionId: CONNECTION,
        detectionId: DETECTION,
        receivedAt: '2026-11-27T08:10:00.000Z',
        headerFrom: null,
        subject: null,
        matchKeys: ['message_id' as const],
        copyRemediationState: 'none' as const,
        status: 'matched' as const,
        plannedAction: 'move_junk' as const,
        reasonCode: null,
        remediationId: null,
        restoreStatus: 'none' as const,
        restoreReasonCode: null,
      },
    ],
    nextCursor: null,
  },
  submitPolicy: {
    mode: 'policy',
    verdict: 'phishing',
    level: 'critical',
    reason: 'Remove the campaign from every mailbox',
    expectedRowVersion: 2,
  },
  submitExplicit: {
    mode: 'explicit',
    action: 'move_junk',
    reason: 'Remove the campaign from every mailbox',
    expectedRowVersion: 2,
  },
  submitted: {
    id: CLAWBACK,
    status: 'pending_approval' as const,
    requiresApproval: true,
    approvalReasons: ['mailbox_threshold' as const],
    approvalExpiresAt: '2026-11-30T09:00:00.000Z',
    rowVersion: 3,
  },
  hardDelete: { reason: 'Irrecoverable malware: delete permanently', expectedRowVersion: 2 },
  decision: { reason: 'Verified with the SOC lead', expectedRowVersion: 3 },
  approved: {
    ...clawback,
    status: 'queued' as const,
    approval: {
      ...clawback.approval,
      status: 'approved' as const,
      decidedAt: '2026-11-27T09:30:00.000Z',
    },
    rowVersion: 5,
  },
  cancel: { reason: 'Wrong criteria' },
  restore: { reason: 'False positive: put the messages back' },
  report,
  reportPage: { data: [report], nextCursor: null },
  reportDetail: {
    ...report,
    reporter: { address: 'alex@contoso.example', mailboxId: MAILBOX, userId: USER2 },
    reportMailbox: { id: REPORT_MAILBOX, address: 'report-phishing@contoso.example' },
    original: {
      messageIdHash: HASH,
      sender: 'billing@fabrikam.example',
      subjectKey: 'Invoice overdue',
      date: '2026-11-27T08:10:00.000Z',
      attachmentCount: 1,
      urlCount: 2,
      extraOriginals: 0,
    },
    originalDetectionId: DETECTION,
    originalIngested: false,
    analyst: { verdict: null, note: null, triagedBy: null, triagedAt: null },
    group: {
      size: 2,
      members: [
        {
          id: OTHER_REPORT,
          status: 'pending_triage' as const,
          reporterAddress: 'sam@contoso.example',
          reportedAt: '2026-11-27T09:05:00.000Z',
        },
      ],
    },
    history: [],
    feedback: { acknowledgement: 'queued' as const, result: 'none' as const },
    updatedAt: T,
  },
  triage: {
    status: 'resolved',
    verdict: 'malicious',
    note: 'Credential phishing; clawed back',
    notifyReporter: true,
    applyToGroup: true,
    expectedRowVersion: 3,
  },
  triaged: {
    report: {
      ...report,
      status: 'resolved' as const,
      analystVerdict: 'malicious' as const,
      rowVersion: 4,
    },
    groupResolved: 1,
    feedbackQueued: 2,
  },
  reportClawback: {
    expand: { attachments: true, urls: false },
    reason: 'Remove the reported phishing from every mailbox',
  },
  reportClawbackCreated: {
    reportId: REPORT,
    clawbackId: CLAWBACK,
    status: 'searching' as const,
    trigger: 'campaign' as const,
  },
  reportMailbox,
  reportMailboxes: { data: [reportMailbox], max: 5 },
  addReportMailbox: {
    address: 'report-phishing@contoso.example',
    reason: 'Users forward suspicious mail here',
  },
  setReportMailbox: { enabled: true, reason: 'Users forward suspicious mail here' },
  reportMailboxChange: { mailbox: reportMailbox, created: false, changed: true },
  settings: settingsView,
  putSettings: {
    ...settings,
    reason: 'Ask for review on automatic clawbacks',
    expectedRowVersion: 2,
  },
  settingsChange: {
    ...settingsView,
    settings: { ...settings, autoClawback: 'review' as const },
    rowVersion: 3,
    changed: ['autoClawback'],
    created: false,
  },
  remediationId: ACTION,
} as const;
