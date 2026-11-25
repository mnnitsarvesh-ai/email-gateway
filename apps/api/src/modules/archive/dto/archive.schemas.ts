import {
  ARCHIVE_CATEGORIES,
  ARCHIVE_RECORD_STATUSES,
  archiveRetentionCriteriaSchema,
  INGEST_SOURCES,
  INTAKE_FORMATS,
  INTAKE_RECIPIENT_FIELDS,
  INTAKE_SOURCE_KINDS,
  archiveSettingsSchema,
  MESSAGE_ACTIONS,
  MESSAGE_DIRECTIONS,
  MESSAGE_VERDICTS,
  OBJECT_LOCK_MODES,
  RETENTION_EXPIRY_ACTIONS,
} from '@email-gateway/archive';
import { quarantinePreviewSchema } from '@email-gateway/mail-safety';
import { z } from 'zod';
import { stripControlCharacters } from '../../webhooks/domain/control-chars';
import { defineListQuery } from '../../../http/listing/list-query';

/**
 * Request and response shapes of the archive routes (step 8.1 §4.4 #1–#23,
 * docs/plan/steps/23-journaling-archiving.md A9–A11, A17, A19, A22). Request schemas are strict
 * at every node; responses carry ids, metadata, codes and hashes. Masked fields follow ADR-0062:
 * subjects and recipient addresses are masked for every caller and revealed only through the
 * audited `POST /archive/messages/{messageId}/reveal`.
 */

export const PublicIdSchema = z.uuid();

const isoInstant = z.iso.datetime({ offset: true });
const nullableInstant = isoInstant.nullable();
const sha256 = z.string().regex(/^[0-9a-f]{64}$/);

/** Tenant text: trimmed, no control characters. */
const text = (min: number, max: number) =>
  z
    .string()
    .max(max * 4)
    .transform((v) => stripControlCharacters(v).trim())
    .pipe(z.string().min(min).max(max));

// ---- settings (#1, #2; A22) ---------------------------------------------------------------------

const resolvedSettingsSchema = z.object({
  directions: z.object({ inbound: z.boolean(), outbound: z.boolean(), internal: z.boolean() }),
  include: z.object({ rejected: z.boolean(), quarantined: z.boolean(), failed: z.boolean() }),
  scope: z.object({
    mode: z.enum(['all', 'include', 'exclude']),
    domainIds: z.array(z.string()),
    departmentIds: z.array(z.string()),
    userIds: z.array(z.string()),
    addresses: z.array(z.string()),
  }),
  policyArchive: z.object({ enabled: z.boolean() }),
  access: z.object({ previewEnabled: z.boolean(), downloadEnabled: z.boolean() }),
  intake: z
    .object({ scanEnabled: z.boolean() })
    .describe('Step 8.6 D8: scan journal intake messages (default false; `journal:manage`)'),
});

export const ArchiveSettingsViewSchema = z.object({
  enabled: z.boolean(),
  entitled: z.boolean().describe('The plan includes the `archiving` feature'),
  immutability: z.enum(OBJECT_LOCK_MODES),
  objectLockAvailable: z
    .boolean()
    .describe('S3 Object Lock is available on the archive storage (probed, cached)'),
  defaultRetentionPolicyId: PublicIdSchema.nullable(),
  settings: resolvedSettingsSchema.describe(
    'The effective `archive-settings/1` (defaults applied)',
  ),
  generation: z.number().int().min(0),
  journalEnabledAt: nullableInstant,
  rowVersion: z.number().int().min(0).describe('0 when the organization has no settings row yet'),
  updatedAt: nullableInstant,
});
export type ArchiveSettingsView = z.infer<typeof ArchiveSettingsViewSchema>;

export const UpdateArchiveSettingsBodySchema = z
  .strictObject({
    expectedRowVersion: z
      .number()
      .int()
      .min(0)
      .max(4_294_967_295)
      .describe('`rowVersion` of GET /archive/settings (0 when no row exists yet)'),
    enabled: z.boolean().optional(),
    immutability: z
      .enum(OBJECT_LOCK_MODES)
      .optional()
      .describe(
        '`none` | `governance` | `compliance` (S3 Object Lock of new captures). ' +
          '`compliance` can never be weakened',
      ),
    defaultRetentionPolicyId: PublicIdSchema.nullable().optional(),
    settings: archiveSettingsSchema
      .optional()
      .describe(
        'The whole `archive-settings/1` document (every key optional; replaces the stored one)',
      ),
  })
  .refine((b) => Object.keys(b).some((k) => k !== 'expectedRowVersion'), {
    message: 'must change at least one field',
  });
export type UpdateArchiveSettingsBody = z.output<typeof UpdateArchiveSettingsBodySchema>;

// ---- retention policies (#3–#7; A11) ------------------------------------------------------------

export const RetentionPolicySchema = z.object({
  id: PublicIdSchema,
  name: z.string(),
  retentionDays: z.number().int(),
  onExpiry: z.enum(RETENTION_EXPIRY_ACTIONS),
  priority: z.number().int(),
  criteria: z.record(z.string(), z.unknown()).describe('`archive-retention/1`'),
  isDefault: z.boolean().describe('The default policy of the archive settings'),
  rowVersion: z.number().int(),
  createdAt: isoInstant,
  updatedAt: isoInstant,
});
export type RetentionPolicyView = z.infer<typeof RetentionPolicySchema>;

export const RetentionPolicyPageSchema = z.object({
  data: z.array(RetentionPolicySchema),
  nextCursor: z.string().nullable(),
});
export type RetentionPolicyPage = z.infer<typeof RetentionPolicyPageSchema>;

const retentionFields = {
  name: text(1, 128).describe('Unique per organization (1-128)'),
  retentionDays: z
    .number()
    .int()
    .min(1)
    .max(36_500)
    .describe(
      'Days after `received_at` (≤ the plan limit `archive_retention_days` and ' +
        'ARCHIVE_MAX_RETENTION_DAYS: `422 archive_retention_exceeds_limit`)',
    ),
  onExpiry: z.enum(RETENTION_EXPIRY_ACTIONS).default('delete'),
  priority: z
    .number()
    .int()
    .min(0)
    .max(10_000)
    .default(100)
    .describe('Lower first; the first matching live policy wins, else the default policy'),
  criteria: archiveRetentionCriteriaSchema.default({}),
};

export const CreateRetentionPolicyBodySchema = z.strictObject(retentionFields);
export type CreateRetentionPolicyBody = z.output<typeof CreateRetentionPolicyBodySchema>;

export const UpdateRetentionPolicyBodySchema = z.strictObject({
  expectedRowVersion: z.number().int().min(1).max(4_294_967_295),
  ...retentionFields,
});
export type UpdateRetentionPolicyBody = z.output<typeof UpdateRetentionPolicyBodySchema>;

export const RetentionPolicyListQuerySchema = defineListQuery({
  filters: {},
  sorts: ['priority'],
  defaultSort: 'priority',
});
export type RetentionPolicyListQuery = z.output<typeof RetentionPolicyListQuerySchema>;

// ---- keys (#8, #9; A9) --------------------------------------------------------------------------

export const ArchiveKeySchema = z.object({
  id: PublicIdSchema,
  version: z.number().int().min(1),
  status: z.enum(['active', 'retired', 'destroyed']),
  rootKeyId: z.string(),
  algorithm: z.string(),
  rotationReason: z.string().nullable(),
  createdBy: PublicIdSchema.nullable().describe('Public id of the user who rotated, if any'),
  createdAt: isoInstant,
  activatedAt: nullableInstant,
  retiredAt: nullableInstant,
  destroyedAt: nullableInstant,
});
export type ArchiveKeyView = z.infer<typeof ArchiveKeySchema>;

export const ArchiveKeyPageSchema = z.object({
  data: z.array(ArchiveKeySchema),
  nextCursor: z.string().nullable(),
});
export type ArchiveKeyPage = z.infer<typeof ArchiveKeyPageSchema>;

export const ArchiveKeyListQuerySchema = defineListQuery({
  filters: {},
  sorts: ['-version'],
  defaultSort: '-version',
});
export type ArchiveKeyListQuery = z.output<typeof ArchiveKeyListQuerySchema>;

export const RotateKeyBodySchema = z.strictObject({
  reason: text(1, 256).describe('Why the key is rotated (audited)'),
});
export type RotateKeyBody = z.output<typeof RotateKeyBodySchema>;

export const RotatedKeySchema = z.object({
  key: ArchiveKeySchema,
  previousVersion: z.number().int().nullable(),
});
export type RotatedKeyView = z.infer<typeof RotatedKeySchema>;

// ---- status (#10) -------------------------------------------------------------------------------

export const ArchiveStatusSchema = z.object({
  generatedAt: isoInstant,
  settings: z.object({
    enabled: z.boolean(),
    entitled: z.boolean(),
    immutability: z.enum(OBJECT_LOCK_MODES),
    generation: z.number().int(),
  }),
  capture: z.object({
    pending: z.number().int(),
    capturedOpen: z.number().int(),
    failed: z.number().int(),
    lost: z.number().int(),
    oldestPendingAt: nullableInstant,
  }),
  records: z.object({
    active: z.number().int(),
    expiryReview: z.number().int(),
    disposing: z.number().int(),
  }),
  index: z.object({
    queued: z.number().int(),
    oldestQueuedAt: nullableInstant,
    lagSeconds: z.number().int(),
  }),
  disposals: z.object({ inProgress: z.number().int(), failed: z.number().int() }),
  keys: z.object({ activeVersion: z.number().int().nullable(), versions: z.number().int() }),
  objectLock: z.object({ available: z.boolean() }),
  search: z.object({ configured: z.boolean(), available: z.boolean() }),
});
export type ArchiveStatusView = z.infer<typeof ArchiveStatusSchema>;

// ---- capture issues (#11, #12) and disposals (#13) ---------------------------------------------

/** `skipped` lists only intents that aged out (`max_age`): mail that was never archived. */
export const CAPTURE_ISSUE_STATUSES = ['failed', 'lost', 'pending', 'skipped'] as const;

export const CaptureIssueSchema = z.object({
  messageId: PublicIdSchema,
  receivedAt: isoInstant,
  status: z.enum(['pending', 'captured_open', 'closed', 'skipped', 'lost', 'failed']),
  code: z.string().nullable().describe('`last_error_code` or `skip_reason` (a code, never text)'),
  attempts: z.number().int(),
  sources: z.object({ journal: z.boolean(), policy: z.boolean() }),
  nextCheckAt: isoInstant,
  createdAt: isoInstant,
});
export type CaptureIssueView = z.infer<typeof CaptureIssueSchema>;

export const CaptureIssuePageSchema = z.object({
  data: z.array(CaptureIssueSchema),
  nextCursor: z.string().nullable(),
});
export type CaptureIssuePage = z.infer<typeof CaptureIssuePageSchema>;

export const CaptureIssueListQuerySchema = defineListQuery({
  filters: { status: { type: 'enum', values: CAPTURE_ISSUE_STATUSES, maxValues: 4 } },
  sorts: ['-receivedAt'],
  defaultSort: '-receivedAt',
});
export type CaptureIssueListQuery = z.output<typeof CaptureIssueListQuerySchema>;

export const CaptureRetrySchema = z.object({
  messageId: PublicIdSchema,
  status: z.literal('pending'),
  nextCheckAt: isoInstant,
});
export type CaptureRetryView = z.infer<typeof CaptureRetrySchema>;

export const DISPOSAL_REASONS = [
  'retention_expired',
  'review_disposed',
  'organization_deleted',
] as const;
export const DISPOSAL_STATES = [
  'shredded',
  'objects_deleted',
  'index_deleted',
  'completed',
  'failed',
] as const;

export const DisposalSchema = z.object({
  messageId: PublicIdSchema,
  receivedAt: isoInstant,
  reason: z.enum(DISPOSAL_REASONS),
  state: z.enum(DISPOSAL_STATES),
  sha256,
  sizeBytes: z.number().int(),
  attempts: z.number().int(),
  requestedAt: isoInstant,
  completedAt: nullableInstant,
});
export type DisposalView = z.infer<typeof DisposalSchema>;

export const DisposalPageSchema = z.object({
  data: z.array(DisposalSchema),
  nextCursor: z.string().nullable(),
});
export type DisposalPage = z.infer<typeof DisposalPageSchema>;

export const DisposalListQuerySchema = defineListQuery({
  filters: {
    reason: { type: 'enum', values: DISPOSAL_REASONS, maxValues: 3 },
    state: { type: 'enum', values: DISPOSAL_STATES, maxValues: 5 },
  },
  sorts: ['-requestedAt'],
  defaultSort: '-requestedAt',
  range: true,
});
export type DisposalListQuery = z.output<typeof DisposalListQuerySchema>;

// ---- export signing keys (#14) ------------------------------------------------------------------

export const SigningKeysSchema = z.object({
  data: z.array(
    z.object({
      id: z.string(),
      algorithm: z.literal('Ed25519'),
      format: z.literal('spki-der-base64url'),
      publicKey: z.string(),
      current: z.boolean(),
    }),
  ),
});
export type SigningKeysView = z.infer<typeof SigningKeysSchema>;

// ---- messages: search (#15), detail (#16) ------------------------------------------------------

export const ArchiveMessageSchema = z.object({
  messageId: PublicIdSchema,
  receivedAt: isoInstant,
  capturedAt: nullableInstant,
  direction: z.enum(MESSAGE_DIRECTIONS),
  category: z.enum(ARCHIVE_CATEGORIES),
  sources: z.array(z.enum(['journal', 'policy'])),
  ingestSources: z
    .array(z.enum(INGEST_SOURCES))
    .describe(
      'Step 8.6: where the record’s copies came from (`gateway`, `journal_intake`); both when a ' +
        'journal intake copy was merged into a gateway record (or the reverse)',
    ),
  status: z.enum(ARCHIVE_RECORD_STATUSES),
  envelopeFrom: z.string().describe('Sender side: in clear (ADR-0062)'),
  headerFrom: z.string().nullable(),
  recipients: z.array(z.string()).describe('Masked (`f***@example.com`) for every caller'),
  recipientsTruncated: z.boolean(),
  subject: z.null().describe('Always null: masked (reveal through the audited reveal route)'),
  subjectMasked: z.boolean(),
  sizeBytes: z.number().int(),
  attachmentCount: z.number().int(),
  attachmentNames: z.array(z.string()).describe('In clear (the open ADR-0062 question)'),
  verdict: z.enum(MESSAGE_VERDICTS).nullable(),
  finalAction: z.enum(MESSAGE_ACTIONS).nullable(),
  riskScore: z.number().int().nullable(),
  malicious: z.boolean(),
  retainUntil: nullableInstant,
  legalHold: z.boolean(),
  lockMode: z.enum(OBJECT_LOCK_MODES),
});
export type ArchiveMessageView = z.infer<typeof ArchiveMessageSchema>;

export const ArchiveMessagePageSchema = z.object({
  data: z.array(ArchiveMessageSchema),
  nextCursor: z.string().nullable(),
});
export type ArchiveMessagePage = z.infer<typeof ArchiveMessagePageSchema>;

export const ARCHIVE_SEARCH_LIST = defineListQuery({
  filters: {
    direction: { type: 'enum', values: MESSAGE_DIRECTIONS, maxValues: 3 },
    category: { type: 'enum', values: ARCHIVE_CATEGORIES, maxValues: 4 },
    source: { type: 'enum', values: ['journal', 'policy'] as const, maxValues: 2 },
    ingestSource: { type: 'enum', values: INGEST_SOURCES, maxValues: 1 },
    status: { type: 'enum', values: ARCHIVE_RECORD_STATUSES, maxValues: 3 },
    sender: { type: 'email' },
    senderDomain: { type: 'domain' },
    recipient: { type: 'email' },
    recipientDomain: { type: 'domain' },
    subject: { type: 'string', maxLength: 256 },
    custodian: { type: 'email' },
    internetMessageId: { type: 'string', maxLength: 998 },
    hasAttachments: { type: 'bool' },
    attachmentName: { type: 'string', maxLength: 256 },
    attachmentSha256: { type: 'string', maxLength: 64, maxValues: 10 },
    verdict: { type: 'enum', values: MESSAGE_VERDICTS, maxValues: 9 },
    finalAction: { type: 'enum', values: MESSAGE_ACTIONS, maxValues: 7 },
    riskScore: { type: 'int', min: 0, max: 1000, range: true },
    malicious: { type: 'bool' },
    legalHold: { type: 'bool' },
    holdId: { type: 'publicId' },
  },
  sorts: ['-receivedAt', 'receivedAt'],
  defaultSort: '-receivedAt',
  range: true,
});
export const ArchiveSearchQuerySchema = ARCHIVE_SEARCH_LIST;
export type ArchiveSearchQuery = z.output<typeof ArchiveSearchQuerySchema>;

export const ArchiveMessageDetailSchema = ArchiveMessageSchema.extend({
  internetMessageId: z.string().nullable(),
  parties: z.object({
    envelopeFrom: z.string(),
    headerFrom: z.string().nullable(),
    recipients: z.array(
      z.object({
        seq: z.number().int(),
        address: z.string().describe('Masked'),
        direction: z
          .enum(MESSAGE_DIRECTIONS)
          .nullable()
          .describe('Null for an external recipient of an external journal intake sender (8.6)'),
        status: z.string(),
        finalAction: z.string().nullable(),
        field: z
          .enum(INTAKE_RECIPIENT_FIELDS)
          .optional()
          .describe('Step 8.6: the journal envelope field of an intake recipient'),
        ingestSources: z
          .array(z.enum(INGEST_SOURCES))
          .optional()
          .describe('Step 8.6: the copies that named this recipient (merged records)'),
      }),
    ),
    recipientCount: z.number().int(),
    recipientsTruncated: z.boolean(),
  }),
  capture: z.object({
    capturedAt: isoInstant,
    sources: z.object({
      journal: z.boolean(),
      policy: z.boolean(),
      policyRuleRef: z.string().nullable(),
    }),
    messageState: z.string(),
    messageStateReason: z.string().nullable(),
    settingsGeneration: z.number().int(),
    outcomeRefreshedAt: nullableInstant,
  }),
  retention: z.object({
    policyId: PublicIdSchema.nullable(),
    policyName: z.string().nullable(),
    retainUntil: isoInstant,
    effectiveRetainUntil: isoInstant.describe('max(stored, the live policy now): extend-only'),
    expiryAction: z.enum(RETENTION_EXPIRY_ACTIONS),
  }),
  holds: z
    .array(z.object({ id: PublicIdSchema, name: z.string(), caseId: PublicIdSchema.nullable() }))
    .nullable()
    .describe(
      'Active holds that match the record now; null unless the caller holds ' +
        '`archive:legal_hold` or `ediscovery:manage` (who is under hold is confidential)',
    ),
  immutability: z.object({ lockMode: z.enum(OBJECT_LOCK_MODES), lockUntil: nullableInstant }),
  integrity: z.object({
    sha256,
    sizeBytes: z.number().int(),
    storedBytes: z.number().int(),
    encryptionFormat: z.string(),
    keyVersion: z.number().int(),
  }),
  rounds: z.array(
    z.object({ round: z.number().int(), revision: z.number().int(), frozenAt: isoInstant }),
  ),
  intake: z
    .object({
      sourceId: PublicIdSchema.nullable().describe('The journal intake source (null: unknown)'),
      sourceDisplayName: z.string().nullable(),
      kind: z.enum(INTAKE_SOURCE_KINDS).nullable(),
    })
    .nullable()
    .describe(
      'Step 8.6: the journal intake source of the record’s primary copy, or null for a gateway ' +
        'record (format, envelope and proof are in the journal view)',
    ),
  mergedCopies: z
    .array(
      z.object({
        id: PublicIdSchema.describe(
          'Public id of the merged copy (`variant` of POST …/download-grants when ' +
            '`contentVariant`)',
        ),
        receivedAt: isoInstant,
        source: z.enum(INGEST_SOURCES),
        sizeBytes: z.number().int(),
        sha256,
        contentVariant: z
          .boolean()
          .describe('The copy’s body differed: its EML is stored as a content variant'),
        recipientsAdded: z.number().int(),
        mergedAt: isoInstant,
      }),
    )
    .describe('Step 8.6 D7: copies of the same message merged into this record (≤ 8)'),
});
export type ArchiveMessageDetailView = z.infer<typeof ArchiveMessageDetailSchema>;

// ---- journal (#17), security (#18), reveal (#19), preview (#20) ---------------------------------

export const ArchiveJournalViewSchema = z.object({
  messageId: PublicIdSchema,
  captureId: PublicIdSchema,
  capturedAt: isoInstant,
  category: z.enum(ARCHIVE_CATEGORIES),
  message: z.object({
    internetMessageId: z.string().nullable(),
    envelopeFrom: z.string(),
    headerFrom: z.string().nullable(),
    subject: z.null(),
    subjectMasked: z.boolean(),
    sizeBytes: z.number().int(),
    emlSha256: sha256,
    clientIp: z.string().nullable(),
    clientHelo: z.string().nullable(),
  }),
  envelope: z.object({
    recipients: z.array(
      z.object({
        seq: z.number().int(),
        address: z.string().describe('Masked'),
        direction: z
          .enum(MESSAGE_DIRECTIONS)
          .nullable()
          .describe('Null for an external recipient of an external journal intake sender (8.6)'),
        status: z.string(),
        field: z
          .enum(INTAKE_RECIPIENT_FIELDS)
          .optional()
          .describe('Step 8.6: `to`, `cc`, `bcc`, `recipient`, `envelope` or `header`'),
      }),
    ),
  }),
  intake: z
    .object({
      sourceId: PublicIdSchema,
      kind: z.enum(INTAKE_SOURCE_KINDS),
      format: z.enum(INTAKE_FORMATS),
      envelope: z.object({
        sender: z.string().nullable().describe('Sender side: in clear (ADR-0062)'),
        onBehalfOf: z.string().nullable(),
        messageId: z.string().nullable(),
        recipients: z.array(
          z.object({
            address: z.string().describe('Masked'),
            field: z.enum(INTAKE_RECIPIENT_FIELDS),
            expandedFrom: z.string().optional().describe('Masked distribution list'),
            forwardedFrom: z.string().optional().describe('Masked'),
          }),
        ),
        truncated: z.boolean(),
      }),
      envelopeMismatch: z.boolean(),
      proof: z.object({
        network: z.string(),
        tls: z.boolean(),
        clientCert: z.string(),
        tenantHeader: z.string(),
        headerToken: z.string(),
        dkim: z.string(),
      }),
    })
    .nullable()
    .describe(
      'Step 8.6: the journal envelope (BCC included; addresses masked) and the sender proof ' +
        'codes of a journal intake copy; null for a gateway capture',
    ),
  headers: z.array(
    z.object({
      name: z.string(),
      value: z.string().nullable(),
      masked: z.boolean().describe('To, Cc, Subject and unknown names: value null'),
    }),
  ),
  parse: z.object({ status: z.string().nullable(), codes: z.array(z.string()) }),
  body: z.object({
    textAvailable: z.boolean(),
    htmlAvailable: z.boolean(),
    truncated: z.boolean(),
    unavailableReason: z.string().nullable(),
  }),
  attachments: z.array(
    z.object({
      partIndex: z.number().int(),
      fileName: z.string().nullable(),
      contentType: z.string().nullable(),
      detectedType: z.string().nullable(),
      sizeBytes: z.number().int(),
      sha256: sha256.nullable(),
    }),
  ),
  deliveries: z.array(
    z.object({ seq: z.number().int(), status: z.string(), finalAt: nullableInstant }),
  ),
});
export type ArchiveJournalView = z.infer<typeof ArchiveJournalViewSchema>;

export const ArchiveSecurityViewSchema = z.object({
  messageId: PublicIdSchema,
  rounds: z.array(
    z.object({
      round: z.number().int(),
      revision: z.number().int(),
      frozenAt: isoInstant,
      scan: z
        .record(z.string(), z.unknown())
        .describe('The scan round as GET /messages/{messageId}/scans maps it (masked)'),
    }),
  ),
  dlpEvidence: z
    .literal('not_retained')
    .describe('DLP evidence has its own retention and is not archived'),
});
export type ArchiveSecurityView = z.infer<typeof ArchiveSecurityViewSchema>;

export const ARCHIVE_REVEAL_FIELDS = ['subject', 'recipients', 'headers'] as const;

export const ArchiveRevealBodySchema = z.strictObject({
  fields: z
    .array(z.enum(ARCHIVE_REVEAL_FIELDS))
    .min(1)
    .max(3)
    .refine((v) => new Set(v).size === v.length, { message: 'must not repeat a value' })
    .describe('`subject`, `recipients` (envelope recipients), `headers` (To, Cc, Subject)'),
});
export type ArchiveRevealBody = z.output<typeof ArchiveRevealBodySchema>;

export const ArchiveRevealSchema = z.object({
  messageId: PublicIdSchema,
  revealedAt: isoInstant,
  subject: z.string().nullable().optional(),
  recipients: z
    .array(z.object({ seq: z.number().int(), address: z.string() }))
    .optional()
    .describe('At most the first 1 000 envelope recipients'),
  headers: z.array(z.object({ name: z.string(), value: z.string() })).optional(),
});
export type ArchiveRevealView = z.infer<typeof ArchiveRevealSchema>;

export const ArchivePreviewSchema = quarantinePreviewSchema;

// ---- downloads (#21, #22) and disposal (#23) ----------------------------------------------------

export const DownloadGrantBodySchema = z.strictObject({
  password: z.string().min(1).max(1024).describe('The caller’s password (re-authorization)'),
  variant: PublicIdSchema.optional().describe(
    'Step 8.6: the `mergedCopies[].id` of a content variant to download instead of the ' +
      'primary copy',
  ),
  totpCode: z
    .string()
    .regex(/^[0-9]{6}$/)
    .optional()
    .describe('Required when the caller has MFA enrolled'),
});
export type DownloadGrantBody = z.output<typeof DownloadGrantBodySchema>;

export const DownloadGrantSchema = z.object({
  token: z.string().describe('`v1.<payload>.<mac>`: single use, bound to you and the target'),
  expiresAt: isoInstant,
  filename: z.string(),
  sizeBytes: z.number().int(),
  sha256,
});
export type DownloadGrantView = z.infer<typeof DownloadGrantSchema>;

export const DisposeBodySchema = z.strictObject({
  reason: text(1, 1024).describe('Why the reviewed record is disposed (audited)'),
});
export type DisposeBody = z.output<typeof DisposeBodySchema>;

export const DisposeAcceptedSchema = z.object({
  messageId: PublicIdSchema,
  status: z.literal('disposing'),
  disposalRequestedAt: isoInstant,
});
export type DisposeAccepted = z.infer<typeof DisposeAcceptedSchema>;

// ---- examples (OpenAPI; placeholders contain EXAMPLE) -------------------------------------------

const ID = {
  policy: '0193a1c2-1111-7a00-8000-000000000001',
  policy2: '0193a1c2-1111-7a00-8000-000000000002',
  key: '0193a1c2-2222-7a00-8000-000000000001',
  user: '0193a1c2-3333-7a00-8000-000000000001',
  message: '0193a1c2-4444-7a00-8000-000000000001',
  domain: '0193a1c2-5555-7a00-8000-000000000001',
  hold: '0193a1c2-6666-7a00-8000-000000000001',
  case: '0193a1c2-7777-7a00-8000-000000000001',
  mergedCopy: '0193a1c2-9999-7a00-8000-000000000001',
} as const;
export const ARCHIVE_EXAMPLE_IDS = ID;

const settingsResolved = {
  directions: { inbound: true, outbound: true, internal: false },
  include: { rejected: false, quarantined: true, failed: false },
  scope: {
    mode: 'include' as const,
    domainIds: [ID.domain],
    departmentIds: [],
    userIds: [],
    addresses: ['legal@example.com'],
  },
  policyArchive: { enabled: true },
  access: { previewEnabled: true, downloadEnabled: false },
  intake: { scanEnabled: false },
};

const policyView: RetentionPolicyView = {
  id: ID.policy,
  name: 'Seven years',
  retentionDays: 2555,
  onExpiry: 'review',
  priority: 100,
  criteria: {},
  isDefault: true,
  rowVersion: 1,
  createdAt: '2026-11-16T09:00:00.000Z',
  updatedAt: '2026-11-16T09:00:00.000Z',
};

const keyView: ArchiveKeyView = {
  id: ID.key,
  version: 2,
  status: 'active',
  rootKeyId: 'r1',
  algorithm: 'aes-256-gcm',
  rotationReason: 'Annual rotation',
  createdBy: ID.user,
  createdAt: '2026-11-16T09:30:00.000Z',
  activatedAt: '2026-11-16T09:30:00.000Z',
  retiredAt: null,
  destroyedAt: null,
};

const messageView: ArchiveMessageView = {
  messageId: ID.message,
  receivedAt: '2026-11-16T10:15:00.000Z',
  capturedAt: '2026-11-16T10:17:03.120Z',
  direction: 'inbound',
  category: 'delivered',
  sources: ['journal'],
  ingestSources: ['gateway', 'journal_intake'],
  status: 'active',
  envelopeFrom: 'sender@example.org',
  headerFrom: 'sender@example.org',
  recipients: ['u***@example.com'],
  recipientsTruncated: false,
  subject: null,
  subjectMasked: true,
  sizeBytes: 2048,
  attachmentCount: 1,
  attachmentNames: ['report.pdf'],
  verdict: 'clean',
  finalAction: 'deliver',
  riskScore: 12,
  malicious: false,
  retainUntil: '2033-11-14T10:15:00.000Z',
  legalHold: false,
  lockMode: 'none',
};

export const ARCHIVE_EXAMPLES = {
  settings: {
    enabled: true,
    entitled: true,
    immutability: 'governance',
    objectLockAvailable: true,
    defaultRetentionPolicyId: ID.policy,
    settings: settingsResolved,
    generation: 3,
    journalEnabledAt: '2026-11-16T09:05:00.000Z',
    rowVersion: 3,
    updatedAt: '2026-11-16T09:05:00.000Z',
  } satisfies ArchiveSettingsView,
  settingsUpdate: {
    expectedRowVersion: 2,
    enabled: true,
    immutability: 'governance',
    defaultRetentionPolicyId: ID.policy,
    settings: {
      directions: { inbound: true, outbound: true, internal: false },
      include: { quarantined: true },
      scope: { mode: 'include', domainIds: [ID.domain], addresses: ['legal@example.com'] },
      access: { previewEnabled: true, downloadEnabled: false },
    },
  },
  policy: policyView,
  policyPage: { data: [policyView], nextCursor: null } satisfies RetentionPolicyPage,
  policyCreate: {
    name: 'Seven years',
    retentionDays: 2555,
    onExpiry: 'review',
    priority: 100,
    criteria: {},
  },
  policyUpdate: {
    expectedRowVersion: 1,
    name: 'Seven years',
    retentionDays: 2920,
    onExpiry: 'review',
    priority: 100,
    criteria: { directions: ['outbound'] },
  },
  key: keyView,
  keyPage: {
    data: [
      keyView,
      {
        ...keyView,
        id: ID.policy2,
        version: 1,
        status: 'retired',
        rotationReason: null,
        createdBy: null,
        retiredAt: '2026-11-16T09:30:00.000Z',
      },
    ],
    nextCursor: null,
  } satisfies ArchiveKeyPage,
  rotate: { reason: 'Annual rotation' },
  rotated: { key: keyView, previousVersion: 1 } satisfies RotatedKeyView,
  status: {
    generatedAt: '2026-11-17T08:00:00.000Z',
    settings: { enabled: true, entitled: true, immutability: 'governance', generation: 3 },
    capture: {
      pending: 4,
      capturedOpen: 120,
      failed: 1,
      lost: 0,
      oldestPendingAt: '2026-11-17T07:58:30.000Z',
    },
    records: { active: 15234, expiryReview: 3, disposing: 0 },
    index: { queued: 2, oldestQueuedAt: '2026-11-17T07:59:58.000Z', lagSeconds: 2 },
    disposals: { inProgress: 0, failed: 0 },
    keys: { activeVersion: 2, versions: 2 },
    objectLock: { available: true },
    search: { configured: true, available: true },
  } satisfies ArchiveStatusView,
  captureIssues: {
    data: [
      {
        messageId: ID.message,
        receivedAt: '2026-11-16T10:15:00.000Z',
        status: 'failed',
        code: 'storage_error',
        attempts: 7,
        sources: { journal: true, policy: false },
        nextCheckAt: '2026-11-17T09:00:00.000Z',
        createdAt: '2026-11-16T10:17:00.000Z',
      },
    ],
    nextCursor: null,
  } satisfies CaptureIssuePage,
  // Step AI-5 D8: the single read answers any intent status (here a captured one).
  captureIssue: {
    messageId: ID.message,
    receivedAt: '2026-11-16T10:15:00.000Z',
    status: 'captured_open',
    code: null,
    attempts: 1,
    sources: { journal: true, policy: false },
    nextCheckAt: '2026-11-16T10:20:00.000Z',
    createdAt: '2026-11-16T10:15:02.000Z',
  } satisfies CaptureIssueView,
  captureRetry: {
    messageId: ID.message,
    status: 'pending',
    nextCheckAt: '2026-11-17T08:00:00.000Z',
  } satisfies CaptureRetryView,
  disposals: {
    data: [
      {
        messageId: ID.message,
        receivedAt: '2019-11-16T10:15:00.000Z',
        reason: 'retention_expired',
        state: 'completed',
        sha256: 'a'.repeat(64),
        sizeBytes: 2048,
        attempts: 1,
        requestedAt: '2026-11-17T02:00:00.000Z',
        completedAt: '2026-11-17T02:00:09.000Z',
      },
    ],
    nextCursor: null,
  } satisfies DisposalPage,
  signingKeys: {
    data: [
      {
        id: 'es2',
        algorithm: 'Ed25519',
        format: 'spki-der-base64url',
        publicKey: 'EXAMPLE-ED25519-SPKI-PUBLIC-KEY',
        current: true,
      },
      {
        id: 'es1',
        algorithm: 'Ed25519',
        format: 'spki-der-base64url',
        publicKey: 'EXAMPLE-ED25519-SPKI-PREVIOUS-KEY',
        current: false,
      },
    ],
  } satisfies SigningKeysView,
  message: messageView,
  messagePage: {
    data: [messageView],
    nextCursor: 'EXAMPLE-CURSOR',
  } satisfies ArchiveMessagePage,
  detail: {
    ...messageView,
    internetMessageId: '<example-1@example.org>',
    parties: {
      envelopeFrom: 'sender@example.org',
      headerFrom: 'sender@example.org',
      recipients: [
        {
          seq: 0,
          address: 'u***@example.com',
          direction: 'inbound',
          status: 'delivered',
          finalAction: 'deliver',
        },
      ],
      recipientCount: 1,
      recipientsTruncated: false,
    },
    capture: {
      capturedAt: '2026-11-16T10:17:03.120Z',
      sources: { journal: true, policy: false, policyRuleRef: null },
      messageState: 'delivered',
      messageStateReason: 'delivery_complete',
      settingsGeneration: 3,
      outcomeRefreshedAt: null,
    },
    retention: {
      policyId: ID.policy,
      policyName: 'Seven years',
      retainUntil: '2033-11-14T10:15:00.000Z',
      effectiveRetainUntil: '2033-11-14T10:15:00.000Z',
      expiryAction: 'review',
    },
    holds: null,
    immutability: { lockMode: 'none', lockUntil: null },
    integrity: {
      sha256: 'a'.repeat(64),
      sizeBytes: 2048,
      storedBytes: 4096,
      encryptionFormat: 'archive-object/1',
      keyVersion: 2,
    },
    rounds: [{ round: 1, revision: 1, frozenAt: '2026-11-16T10:17:02.900Z' }],
    intake: null,
    mergedCopies: [
      {
        id: ID.mergedCopy,
        receivedAt: '2026-11-16T10:15:02.000Z',
        source: 'journal_intake',
        sizeBytes: 2211,
        sha256: 'c'.repeat(64),
        contentVariant: false,
        recipientsAdded: 1,
        mergedAt: '2026-11-16T10:19:00.000Z',
      },
    ],
  } satisfies ArchiveMessageDetailView,
  journal: {
    messageId: ID.message,
    captureId: '0193a1c2-8888-7a00-8000-000000000001',
    capturedAt: '2026-11-16T10:17:03.120Z',
    category: 'delivered',
    message: {
      internetMessageId: '<example-1@example.org>',
      envelopeFrom: 'sender@example.org',
      headerFrom: 'Sender <sender@example.org>',
      subject: null,
      subjectMasked: true,
      sizeBytes: 2048,
      emlSha256: 'a'.repeat(64),
      clientIp: '192.0.2.10',
      clientHelo: 'mail.example.org',
    },
    envelope: {
      recipients: [
        { seq: 0, address: 'u***@example.com', direction: 'inbound', status: 'delivered' },
      ],
    },
    intake: null,
    headers: [
      { name: 'From', value: 'Sender <sender@example.org>', masked: false },
      { name: 'Subject', value: null, masked: true },
    ],
    parse: { status: 'parsed', codes: [] },
    body: { textAvailable: true, htmlAvailable: false, truncated: false, unavailableReason: null },
    attachments: [
      {
        partIndex: 2,
        fileName: 'report.pdf',
        contentType: 'application/pdf',
        detectedType: 'application/pdf',
        sizeBytes: 1024,
        sha256: 'b'.repeat(64),
      },
    ],
    deliveries: [{ seq: 0, status: 'delivered', finalAt: '2026-11-16T10:15:04.000Z' }],
  } satisfies ArchiveJournalView,
  security: {
    messageId: ID.message,
    rounds: [
      {
        round: 1,
        revision: 1,
        frozenAt: '2026-11-16T10:17:02.900Z',
        scan: {
          scanId: '9001',
          round: 1,
          scanKind: 'initial',
          status: 'completed',
          verdict: 'clean',
          engines: [],
          risk: [],
          policy: null,
        },
      },
    ],
    dlpEvidence: 'not_retained',
  } satisfies ArchiveSecurityView,
  reveal: { fields: ['subject', 'headers'] },
  revealed: {
    messageId: ID.message,
    revealedAt: '2026-11-17T08:01:00.000Z',
    subject: 'Quarterly report',
    headers: [{ name: 'Subject', value: 'Quarterly report' }],
  } satisfies ArchiveRevealView,
  preview: {
    version: 'preview/1',
    subject: 'Quarterly report',
    headers: [{ name: 'From', value: 'Sender <sender@example.org>' }],
    body: {
      source: 'text',
      text: 'Hello, the report is attached.',
      truncated: false,
      unavailableReason: null,
    },
    links: [],
    linksTruncated: false,
    attachments: [
      {
        partIndex: 2,
        filename: 'report.pdf',
        declaredType: 'application/pdf',
        detectedType: 'application/pdf',
        typeFamily: 'document',
        sizeBytes: 1024,
        sha256: 'b'.repeat(64),
        verdict: 'clean',
        reasonCodes: [],
        downloadable: false,
      },
    ],
    dlp: { masked: 0, categories: [] },
  },
  grantBody: { password: 'EXAMPLE-PASSWORD', totpCode: '123456' },
  grant: {
    token: 'v1.EXAMPLE-PAYLOAD.EXAMPLE-MAC',
    expiresAt: '2026-11-17T08:02:00.000Z',
    filename: `message-${ID.message}.eml`,
    sizeBytes: 2048,
    sha256: 'a'.repeat(64),
  } satisfies DownloadGrantView,
  dispose: { reason: 'Reviewed: no further retention required' },
  disposed: {
    messageId: ID.message,
    status: 'disposing',
    disposalRequestedAt: '2026-11-17T08:03:00.000Z',
  } satisfies DisposeAccepted,
} as const;

/** Query parameter descriptions of the archive lists (OpenAPI). */
export const ARCHIVE_SEARCH_PARAMETERS: Record<string, string> = {
  from: 'Start of the `received_at` range (ISO 8601 with offset, inclusive). Required',
  to:
    'End of the range (inclusive). Required; at most ARCHIVE_SEARCH_MAX_RANGE_DAYS (366) after ' +
    '`from` (`400 archive_search_range_invalid`)',
  direction: '`inbound`, `outbound`, `internal`; comma list',
  category: '`delivered`, `rejected`, `quarantined`, `failed`; comma list',
  source: '`journal`, `policy` (capture source); comma list',
  ingestSource:
    'Step 8.6: `gateway` or `journal_intake` (where a copy of the record came from; records ' +
    'indexed before 8.6 are `gateway`)',
  status: '`active`, `expiry_review`, `disposing`; comma list',
  sender: 'Envelope sender or header From (exact address, case-insensitive)',
  senderDomain: 'Sender domain',
  recipient: 'Exact recipient address. Needs `message:reveal` (`403 archive_filter_forbidden`)',
  recipientDomain: 'Recipient domain',
  subject: 'Subject phrase. Needs `message:reveal` (`403 archive_filter_forbidden`)',
  custodian:
    'Sender or recipient address (custodian). Needs `message:reveal` (`403 archive_filter_forbidden`)',
  internetMessageId: 'The Message-ID header (with or without angle brackets)',
  hasAttachments: '`true` | `false`',
  attachmentName: 'Attachment file name phrase',
  attachmentSha256: 'SHA-256 of an attachment (64 hex); comma list (≤ 10)',
  verdict: 'Final verdict; comma list',
  finalAction: 'Final action; comma list',
  'riskScore.gte': 'Risk score at least (0-1000)',
  'riskScore.lte': 'Risk score at most (0-1000)',
  malicious: '`true` | `false`',
  legalHold: '`true` | `false`: a hold blocked an expiry of the record',
  holdId:
    'Records the hold covers now (informational). Needs `archive:legal_hold` or ' +
    '`ediscovery:manage` (`403 archive_filter_forbidden`)',
  sort: '`-receivedAt` (default) | `receivedAt`',
  limit: 'Page size, 1-100 (default 25)',
  cursor: '`nextCursor` of the previous page (bound to the filters, the range and the sort)',
  riskScore: 'Exact risk score',
};

export const PAGE_PARAMETERS: Record<string, string> = {
  limit: 'Page size, 1-100 (default 25)',
  cursor: '`nextCursor` of the previous page',
};
