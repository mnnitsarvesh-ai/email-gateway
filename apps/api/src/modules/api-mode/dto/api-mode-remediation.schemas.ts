import {
  API_MODE_ACTION_TRIGGERS,
  REMEDIATION_ACTION_KINDS,
  REMEDIATION_ACTIONS,
  REMEDIATION_MODES,
  REMEDIATION_RULE_ACTIONS,
  REMEDIATION_STATUSES,
  REMEDIABLE_VERDICTS,
  RULE_LEVELS,
} from '@email-gateway/mailbox-api';
import { z } from 'zod';
import { defineListQuery } from '../../../http/listing/list-query';
import { stripControlCharacters } from '../../webhooks/domain/control-chars';
import { ReleaseOutcomeSchema } from '../../quarantine/dto/quarantine.schemas';
import { PublicIdSchema } from './api-mode.schemas';

/**
 * Request and response shapes of the API-mode remediation routes (step API-2 R12, R13,
 * docs/plan/steps/36-api-mode-remediation.md; ADR-0101). Request schemas are strict; the policy
 * document is validated by the service with the strict `remediationPolicySchema` of
 * `@email-gateway/mailbox-api` (the body carries it as an opaque value so its issues are reported
 * with their document path). Views never carry provider message ids (`provider_refs` shows only
 * the container and the counts), message content or another organization's rows.
 */

const isoInstant = z.iso.datetime({ offset: true });
const nullableInstant = isoInstant.nullable();

/** Untrusted free text: trimmed, control characters removed, 1-500. */
const reasonField = z
  .string()
  .max(2000)
  .transform((v) => stripControlCharacters(v).trim())
  .pipe(z.string().min(1).max(500))
  .describe('Why (1-500 characters; stored with the request and in the audit row)');

export const COPY_REMEDIATION_STATE_VALUES = [
  'none',
  'pending',
  'simulated',
  'remediated',
  'restored',
  'failed',
  'skipped',
] as const;
export const PROVIDER_REF_CONTAINERS = [
  'quarantine_folder',
  'junk',
  'deleted_items',
  'inbox',
] as const;

// ---- policy (R2.1, R13 #1-#4) ----------------------------------------------------------------

/** The stored `api-remediation-policy/1` document as returned (validated before it is stored). */
export const RemediationPolicyDocumentSchema = z.object({
  v: z.literal(1),
  rules: z.array(
    z.object({
      id: z.string().describe('Rule id (unique in the document; untrusted operator text)'),
      when: z.object({
        verdicts: z.array(z.enum(REMEDIABLE_VERDICTS)),
        minLevel: z.enum(RULE_LEVELS).optional(),
        maxLevel: z.enum(RULE_LEVELS).optional(),
        hardBlock: z.boolean().optional(),
        minScore: z.number().int().optional(),
      }),
      action: z.enum(REMEDIATION_RULE_ACTIONS),
    }),
  ),
  remediateScanFailures: z.literal(false).optional(),
});
export type RemediationPolicyDocumentView = z.infer<typeof RemediationPolicyDocumentSchema>;

const presetSchema = z.object({
  mode: z.enum(REMEDIATION_MODES),
  document: RemediationPolicyDocumentSchema,
});

export const RemediationPolicyViewSchema = z.object({
  organization: z.object({
    source: z
      .enum(['platform_default', 'organization'])
      .describe('`platform_default`: no organization row; the P1 default applies'),
    id: PublicIdSchema.nullable(),
    mode: z.enum(REMEDIATION_MODES),
    document: RemediationPolicyDocumentSchema,
    sha256: z.string().describe('Hex SHA-256 of the canonical document (decision provenance)'),
    rowVersion: z
      .number()
      .int()
      .nullable()
      .describe('CAS version (null: no row; send `expectedRowVersion: null` to create it)'),
    updatedAt: nullableInstant,
  }),
  domains: z
    .array(
      z.object({
        id: PublicIdSchema,
        domainId: PublicIdSchema,
        domainName: z.string(),
        mode: z.enum(REMEDIATION_MODES),
        document: RemediationPolicyDocumentSchema,
        sha256: z.string(),
        rowVersion: z.number().int(),
        updatedAt: isoInstant,
      }),
    )
    .describe('Per-domain overrides (a domain without one inherits the organization policy)'),
  presets: z.object({
    p1: presetSchema.describe('The platform default'),
    detectOnlyStart: presetSchema.describe('P1 in detect-only mode: recommended start'),
    strict: presetSchema.describe('P1 + spam to Junk'),
  }),
  hardDeleteAvailable: z
    .boolean()
    .describe('The platform allows `hard_delete` rules (API_MODE_HARD_DELETE_ENABLED)'),
});
export type RemediationPolicyView = z.infer<typeof RemediationPolicyViewSchema>;

const expectedRowVersion = z
  .number()
  .int()
  .min(1)
  .max(4_294_967_295)
  .nullable()
  .describe('The `rowVersion` read (null when no policy row exists yet: the PUT creates it)');

export const PutRemediationPolicyBodySchema = z.strictObject({
  mode: z.enum(REMEDIATION_MODES),
  document: z
    .unknown()
    .describe(
      'The `api-remediation-policy/1` document: `{ v: 1, rules: [{ id, when: { verdicts, ' +
        'minLevel?, maxLevel?, hardBlock?, minScore? }, action }] (1-16, first match wins) }`; ' +
        'strict (unknown keys refused; `when.policyDispositions` is reserved)',
    ),
  reason: reasonField,
  expectedRowVersion,
});
export type PutRemediationPolicyBody = z.output<typeof PutRemediationPolicyBodySchema>;

export const RemediationPolicyChangeSchema = z.object({
  scope: z.enum(['organization', 'domain']),
  id: PublicIdSchema,
  domainId: PublicIdSchema.nullable(),
  mode: z.enum(REMEDIATION_MODES),
  document: RemediationPolicyDocumentSchema,
  sha256: z.string(),
  rowVersion: z.number().int(),
  updatedAt: isoInstant,
  created: z.boolean().describe('true: the row did not exist before'),
});
export type RemediationPolicyChangeView = z.infer<typeof RemediationPolicyChangeSchema>;

// ---- remediations (R13 #5-#9) ----------------------------------------------------------------

export const RemediationListQuerySchema = defineListQuery({
  filters: {
    status: { type: 'enum', values: REMEDIATION_STATUSES, maxValues: 7 },
    action: { type: 'enum', values: REMEDIATION_ACTION_KINDS, maxValues: 7 },
    // Step API-3 §3.2: `clawback` and `purge` appended (C14 additive change).
    trigger: { type: 'enum', values: API_MODE_ACTION_TRIGGERS, maxValues: 7 },
    mailboxId: { type: 'publicId', maxValues: 1 },
    connectionId: { type: 'publicId', maxValues: 1 },
    detectionId: { type: 'publicId', maxValues: 1 },
  },
  sorts: ['-createdAt'],
  defaultSort: '-createdAt',
  range: true,
});
export type RemediationListQuery = z.output<typeof RemediationListQuerySchema>;

export const REMEDIATION_LIST_PARAMETERS: Record<string, string> = {
  status:
    '`pending`, `in_progress`, `succeeded`, `failed`, `skipped`, `simulated`, `cancelled`; ' +
    'comma list',
  action:
    '`move_quarantine`, `move_junk`, `tag`, `soft_delete`, `hard_delete`, `restore_inbox`, ' +
    '`remove_tag`; comma list',
  trigger:
    '`policy`, `admin`, `release`, `end_user`, `system`, `clawback` (automatic clawback), ' +
    '`purge` (admin, report or campaign purge); comma list',
  mailboxId: 'A mailbox public id',
  connectionId: 'The 8.2 provider connection public id',
  detectionId: 'A detection (copy) public id',
  from: 'Start of the creation window (default `to` − 7 days; at most 31 days)',
  to: 'End of the creation window (exclusive; default now)',
  sort: '`-createdAt` (newest first)',
  limit: 'Page size, 1-100 (default 25)',
  cursor: '`nextCursor` of the previous page',
};

export const RemediationSchema = z.object({
  id: PublicIdSchema,
  action: z.enum(REMEDIATION_ACTION_KINDS),
  trigger: z.enum(API_MODE_ACTION_TRIGGERS),
  status: z.enum(REMEDIATION_STATUSES),
  reasonCode: z.string().nullable().describe('Skip, failure or result code (codes only)'),
  attempts: z.number().int(),
  lastErrorCode: z.string().nullable(),
  generation: z.number().int(),
  mailbox: z.object({
    id: PublicIdSchema,
    address: z.string().describe('The mailbox primary address'),
  }),
  connectionId: PublicIdSchema.describe('The 8.2 provider connection public id'),
  detectionId: PublicIdSchema.nullable().describe('null once the copy is past its retention'),
  quarantineEntryId: PublicIdSchema.nullable(),
  clawbackId: PublicIdSchema.nullable().describe(
    'Step API-3: the clawback this action belongs to (`clawback` / `purge` triggers)',
  ),
  createdAt: isoInstant,
  nextAttemptAt: nullableInstant,
  completedAt: nullableInstant,
  latencyMs: z
    .number()
    .int()
    .nullable()
    .describe('completedAt − the verdict time (policy rows) or the request'),
});
export type RemediationView = z.infer<typeof RemediationSchema>;

export const RemediationPageSchema = z.object({
  data: z.array(RemediationSchema),
  nextCursor: z.string().nullable(),
});
export type RemediationPage = z.infer<typeof RemediationPageSchema>;

const manualDecisionSchema = z.object({
  requestedAction: z.enum(REMEDIATION_ACTION_KINDS),
  reason: z.string().nullable().describe('Operator-typed (untrusted)'),
});

const decisionRecordView = z.object({
  v: z.literal(1),
  policy: z.object({
    scope: z.enum(['platform_default', 'organization', 'domain']),
    publicId: z.string().nullable(),
    rowVersion: z.number().int().nullable(),
    sha256: z.string(),
  }),
  mode: z.enum(REMEDIATION_MODES),
  ruleId: z.string().nullable(),
  inputs: z.object({
    verdict: z.string().nullable(),
    riskScore: z.number().int().nullable(),
    level: z.string().nullable(),
    hardBlocks: z.array(z.string()),
    verdictAuthority: z.enum(['copy', 'inline']),
  }),
  policyOutcome: z.null(),
  notes: z.array(z.string()),
});

export const RemediationDetailSchema = RemediationSchema.extend({
  decision: z
    .union([decisionRecordView, manualDecisionSchema])
    .nullable()
    .describe(
      '`api-remediation-decision/1` for policy rows, `{ requestedAction, reason }` otherwise',
    ),
  requestedBy: z.object({
    type: z.enum(['system', 'user', 'api_key']),
    userId: PublicIdSchema.nullable(),
  }),
  requestReason: z.string().nullable().describe('Operator-typed (untrusted)'),
  locateAttempts: z.number().int(),
  lastHttpStatus: z.number().int().nullable(),
  providerRefs: z
    .object({
      container: z.enum(PROVIDER_REF_CONTAINERS).nullable(),
      before: z.number().int().describe('How many provider messages were acted on'),
      after: z.number().int().describe('How many provider ids the actions returned'),
    })
    .nullable()
    .describe('Where the message is after the action; provider ids are never returned'),
  reverses: PublicIdSchema.nullable().describe('The remediation this reversal undoes'),
  reversedBy: PublicIdSchema.nullable().describe('The reversal that undid this remediation'),
  releaseId: PublicIdSchema.nullable().describe('The quarantine release of a release restore'),
  verdictAt: nullableInstant,
  startedAt: nullableInstant,
  updatedAt: isoInstant,
});
export type RemediationDetailView = z.infer<typeof RemediationDetailSchema>;

export const RemediateBodySchema = z.strictObject({
  action: z
    .enum(REMEDIATION_ACTIONS)
    .describe('`move_quarantine`, `move_junk`, `tag` or `soft_delete` (`hard_delete` is refused)'),
  reason: reasonField,
});
export type RemediateBody = z.output<typeof RemediateBodySchema>;

export const RestoreBodySchema = z.strictObject({ reason: reasonField });
export type RestoreBody = z.output<typeof RestoreBodySchema>;

export const RemediationRequestSchema = z.object({
  detectionId: PublicIdSchema,
  remediation: RemediationSchema.describe('The queued action (the worker runs it within seconds)'),
});
export type RemediationRequestView = z.infer<typeof RemediationRequestSchema>;

export const RestoreResponseSchema = z.object({
  detectionId: PublicIdSchema,
  via: z
    .enum(['mailbox_action', 'quarantine_release'])
    .describe('`mailbox_action`: a `remove_tag` row; `quarantine_release`: the entry’s release'),
  remediation: RemediationSchema.nullable(),
  release: ReleaseOutcomeSchema.nullable().describe('The quarantine release outcome'),
});
export type RestoreResponseView = z.infer<typeof RestoreResponseSchema>;

// ---- examples (non-secret placeholders) ------------------------------------------------------

const ACTION = '0192f3a0-8888-7000-8000-000000000008';
const DETECTION = '0192f3a0-6666-7000-8000-000000000006';
const MAILBOX = '0192f3a0-5555-7000-8000-000000000005';
const CONNECTION = '0192f3a0-3333-7000-8000-000000000003';
const DOMAIN = '0192f3a0-2222-7000-8000-000000000002';
const POLICY = '0192f3a0-9999-7000-8000-000000000009';
const ENTRY = '0192f3a0-aaaa-7000-8000-00000000000a';
const RELEASE = '0192f3a0-bbbb-7000-8000-00000000000b';
const USER = '0192f3a0-cccc-7000-8000-00000000000c';
const T = '2026-11-26T09:00:00.000Z';
const SHA = '3f'.repeat(32);

const p1Document = {
  v: 1 as const,
  rules: [
    {
      id: 'p1-high-confidence-malware-phishing-hb',
      when: { verdicts: ['malware' as const, 'phishing' as const], hardBlock: true },
      action: 'move_quarantine' as const,
    },
    {
      id: 'p1-high-confidence-malware-phishing',
      when: { verdicts: ['malware' as const, 'phishing' as const], minLevel: 'critical' as const },
      action: 'move_quarantine' as const,
    },
    {
      id: 'p1-other-malware-phishing',
      when: { verdicts: ['malware' as const, 'phishing' as const] },
      action: 'tag' as const,
    },
    {
      id: 'p1-suspicious',
      when: { verdicts: ['suspicious' as const, 'bec' as const] },
      action: 'tag' as const,
    },
  ],
};

const remediation = {
  id: ACTION,
  action: 'move_quarantine' as const,
  trigger: 'policy' as const,
  status: 'succeeded' as const,
  reasonCode: null,
  attempts: 1,
  lastErrorCode: null,
  generation: 0,
  mailbox: { id: MAILBOX, address: 'alex@contoso.example' },
  connectionId: CONNECTION,
  detectionId: DETECTION,
  quarantineEntryId: ENTRY,
  clawbackId: null,
  createdAt: T,
  nextAttemptAt: null,
  completedAt: '2026-11-26T09:00:04.000Z',
  latencyMs: 4_000,
};

export const REMEDIATION_EXAMPLES = {
  policy: {
    organization: {
      source: 'organization' as const,
      id: POLICY,
      mode: 'enforce' as const,
      document: p1Document,
      sha256: SHA,
      rowVersion: 3,
      updatedAt: T,
    },
    domains: [
      {
        id: '0192f3a0-dddd-7000-8000-00000000000d',
        domainId: DOMAIN,
        domainName: 'contoso.example',
        mode: 'detect_only' as const,
        document: p1Document,
        sha256: SHA,
        rowVersion: 1,
        updatedAt: T,
      },
    ],
    presets: {
      p1: { mode: 'enforce' as const, document: p1Document },
      detectOnlyStart: { mode: 'detect_only' as const, document: p1Document },
      strict: {
        mode: 'enforce' as const,
        document: {
          v: 1 as const,
          rules: [
            ...p1Document.rules,
            {
              id: 'strict-spam-junk',
              when: { verdicts: ['spam' as const] },
              action: 'move_junk' as const,
            },
          ],
        },
      },
    },
    hardDeleteAvailable: false,
  },
  policyPut: {
    mode: 'detect_only',
    document: p1Document,
    reason: 'Start in detect-only mode for the first week',
    expectedRowVersion: null,
  },
  policyChange: {
    scope: 'organization' as const,
    id: POLICY,
    domainId: null,
    mode: 'detect_only' as const,
    document: p1Document,
    sha256: SHA,
    rowVersion: 1,
    updatedAt: T,
    created: true,
  },
  domainPolicyChange: {
    scope: 'domain' as const,
    id: '0192f3a0-dddd-7000-8000-00000000000d',
    domainId: DOMAIN,
    mode: 'enforce' as const,
    document: p1Document,
    sha256: SHA,
    rowVersion: 2,
    updatedAt: T,
    created: false,
  },
  remediation,
  remediationPage: { data: [remediation], nextCursor: null },
  remediationDetail: {
    ...remediation,
    decision: {
      v: 1 as const,
      policy: { scope: 'organization' as const, publicId: POLICY, rowVersion: 3, sha256: SHA },
      mode: 'enforce' as const,
      ruleId: 'p1-high-confidence-malware-phishing-hb',
      inputs: {
        verdict: 'malware',
        riskScore: 990,
        level: 'critical',
        hardBlocks: ['hb.malware_attachment'],
        verdictAuthority: 'copy' as const,
      },
      policyOutcome: null,
      notes: [],
    },
    requestedBy: { type: 'system' as const, userId: null },
    requestReason: null,
    locateAttempts: 1,
    lastHttpStatus: null,
    providerRefs: { container: 'quarantine_folder' as const, before: 1, after: 1 },
    reverses: null,
    reversedBy: null,
    releaseId: null,
    verdictAt: T,
    startedAt: '2026-11-26T09:00:02.000Z',
    updatedAt: '2026-11-26T09:00:04.000Z',
  },
  retried: {
    ...remediation,
    status: 'pending' as const,
    attempts: 0,
    lastErrorCode: null,
    nextAttemptAt: T,
    completedAt: null,
    latencyMs: null,
  },
  remediate: { action: 'move_quarantine', reason: 'Confirmed phishing campaign' },
  remediationRequest: {
    detectionId: DETECTION,
    remediation: {
      ...remediation,
      trigger: 'admin' as const,
      status: 'pending' as const,
      attempts: 0,
      quarantineEntryId: null,
      nextAttemptAt: T,
      completedAt: null,
      latencyMs: null,
    },
  },
  restore: { reason: 'False positive confirmed with the sender' },
  restoreResponse: {
    detectionId: DETECTION,
    via: 'quarantine_release' as const,
    remediation: null,
    release: {
      outcome: 'queued' as const,
      entryId: ENTRY,
      state: 'releasing' as const,
      releaseId: RELEASE,
      rowVersion: 3,
    },
  },
  requester: USER,
} as const;
