import { archiveSettingsSchema, INTAKE_SOURCE_KINDS } from '@email-gateway/archive';
import { z } from 'zod';
import { defineListQuery } from '../../../http/listing/list-query';
import { stripControlCharacters } from '../../webhooks/domain/control-chars';

/**
 * Request and response shapes of the journaling routes (step 8.6 D1, D10, D11,
 * docs/plan/steps/27-journal-intake-and-archive-split.md). Request schemas are strict at every
 * node. Intake addresses and header tokens are credentials: masked (`journal-••••<last 4>@…`,
 * `••••<last 4>`) unless the caller holds `journal:manage` and asks to reveal (audited), shown
 * once on creation and rotation (ADR-0057 redacted replay).
 */

export const PublicIdSchema = z.uuid();

const isoInstant = z.iso.datetime({ offset: true });
const nullableInstant = isoInstant.nullable();

/** Tenant text: trimmed, no control characters. */
const text = (min: number, max: number) =>
  z
    .string()
    .max(max * 4)
    .transform((v) => stripControlCharacters(v).trim())
    .pipe(z.string().min(min).max(max));

export const INTAKE_KINDS = INTAKE_SOURCE_KINDS;
export const INTAKE_STATUSES = ['pending_verification', 'active', 'paused', 'disabled'] as const;
export const INTAKE_HEALTH = ['unknown', 'healthy', 'silent', 'failing', 'paused'] as const;

/** Kinds bound to an 8.2 provider connection; the others register their own networks. */
export const PROVIDER_INTAKE_KINDS = ['microsoft_365_journal', 'google_workspace_copy'] as const;
export const NETWORK_INTAKE_KINDS = ['exchange_onprem_journal', 'smtp_bcc'] as const;

const fingerprint = z
  .string()
  .regex(/^(?:[0-9a-fA-F]{64}|(?:[0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2})$/, 'must be a SHA-256')
  .transform((v) => v.replace(/:/g, '').toLowerCase());

// ---- settings (GET/PUT /journaling/settings) -----------------------------------------------------

const journalingSettingsSchema = z.object({
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
  intake: z.object({ scanEnabled: z.boolean() }),
});

export const JournalingSettingsViewSchema = z.object({
  enabled: z.boolean().describe('Journaling (capture) is on'),
  entitled: z.boolean().describe('The plan includes the `archiving` feature'),
  intakeEntitled: z.boolean().describe('The plan includes the `journal_intake` feature'),
  intakeAvailable: z
    .boolean()
    .describe('The platform has a journal intake domain (JOURNAL_INTAKE_DOMAIN)'),
  journalEnabledAt: nullableInstant,
  settings: journalingSettingsSchema.describe(
    'The journaling half of the effective `archive-settings/1` (defaults applied)',
  ),
  generation: z.number().int().min(0),
  rowVersion: z
    .number()
    .int()
    .min(0)
    .describe('The `rowVersion` of the archive settings row (shared with /archive/settings)'),
  updatedAt: nullableInstant,
});
export type JournalingSettingsView = z.infer<typeof JournalingSettingsViewSchema>;

const settingsShape = archiveSettingsSchema.shape;

export const UpdateJournalingSettingsBodySchema = z
  .strictObject({
    expectedRowVersion: z
      .number()
      .int()
      .min(0)
      .max(4_294_967_295)
      .describe('`rowVersion` of GET /journaling/settings (0 when no row exists yet)'),
    enabled: z.boolean().optional(),
    settings: z
      .strictObject({
        directions: settingsShape.directions,
        include: settingsShape.include,
        scope: settingsShape.scope,
        policyArchive: settingsShape.policyArchive,
        intake: settingsShape.intake,
      })
      .optional()
      .describe(
        'The journaling sections of `archive-settings/1` (every key optional; replaces the stored ' +
          'journaling sections; `access` is never changed here)',
      ),
  })
  .refine((b) => Object.keys(b).some((k) => k !== 'expectedRowVersion'), {
    message: 'must change at least one field',
  });
export type UpdateJournalingSettingsBody = z.output<typeof UpdateJournalingSettingsBodySchema>;

// ---- intake sources -------------------------------------------------------------------------------

const countersSchema = z.object({
  day: z.iso.date(),
  accepted: z.number().int(),
  duplicates: z.number().int(),
  bytes: z.number().int(),
  refusedAddress: z.number().int(),
  refusedNetwork: z.number().int(),
  refusedTls: z.number().int(),
  refusedSize: z.number().int(),
  refusedRate: z.number().int(),
  refusedUnavailable: z.number().int(),
  droppedProof: z.number().int(),
  unwrapFailed: z.number().int(),
});
export type IntakeCountersView = z.infer<typeof countersSchema>;

export const IntakeSourceSchema = z.object({
  id: PublicIdSchema,
  kind: z.enum(INTAKE_KINDS),
  displayName: z.string(),
  status: z.enum(INTAKE_STATUSES),
  providerConnectionId: PublicIdSchema.nullable().describe('Provider kinds: the 8.2 connection'),
  networks: z.array(z.string()).nullable().describe('On-premises kinds: registered CIDRs'),
  requireTls: z.boolean(),
  clientCertFingerprints: z.array(z.string()),
  maxMessageBytes: z.number().int().nullable(),
  silenceAlertMinutes: z.number().int().nullable(),
  address: z
    .string()
    .nullable()
    .describe(
      '`journal-<token>@<intake domain>`: masked (`journal-••••<last 4>@…`) unless revealed; ' +
        'null when the platform has no intake domain',
    ),
  headerToken: z
    .string()
    .nullable()
    .describe('Google Workspace: the `X-EG-Journal-Token` value (masked unless revealed)'),
  revealed: z.boolean().describe('`address` / `headerToken` are in clear'),
  addressVersion: z.number().int(),
  previousAddressValidUntil: nullableInstant.describe(
    'After a rotation: the previous address is accepted until then',
  ),
  verifiedAt: nullableInstant.describe('First accepted message'),
  lastAcceptedAt: nullableInstant,
  lastRefusedAt: nullableInstant,
  lastRefusalCode: z.string().nullable(),
  health: z.object({ status: z.enum(INTAKE_HEALTH), changedAt: nullableInstant }),
  attestations: z.array(
    z.object({ code: z.string(), userId: z.string().nullable(), at: isoInstant }),
  ),
  rowVersion: z.number().int(),
  createdAt: isoInstant,
  updatedAt: isoInstant,
  disabledAt: nullableInstant,
});
export type IntakeSourceView = z.infer<typeof IntakeSourceSchema>;

export const IntakeSourceDetailSchema = IntakeSourceSchema.extend({
  counters: z.array(countersSchema).describe('The last 7 UTC days (today included), newest first'),
});
export type IntakeSourceDetailView = z.infer<typeof IntakeSourceDetailSchema>;

export const IntakeSourcePageSchema = z.object({
  data: z.array(IntakeSourceSchema),
  nextCursor: z.string().nullable(),
});
export type IntakeSourcePage = z.infer<typeof IntakeSourcePageSchema>;

export const IntakeSourceListQuerySchema = defineListQuery({
  filters: {
    status: { type: 'enum', values: INTAKE_STATUSES, maxValues: 4 },
    kind: { type: 'enum', values: INTAKE_KINDS, maxValues: 4 },
    health: { type: 'enum', values: INTAKE_HEALTH, maxValues: 5 },
  },
  sorts: ['-id'],
  defaultSort: '-id',
});
export type IntakeSourceListQuery = z.output<typeof IntakeSourceListQuerySchema>;

export const IntakeSourceGetQuerySchema = z.strictObject({
  reveal: z
    .enum(['true', 'false'])
    .optional()
    .transform((v) => v === 'true'),
});
export type IntakeSourceGetQuery = z.output<typeof IntakeSourceGetQuerySchema>;

const networksField = z
  .array(z.string().min(2).max(49))
  .min(1)
  .max(32)
  .describe('On-premises kinds: 1-32 public CIDRs of the sending servers (never a provider range)');

export const CreateIntakeSourceBodySchema = z.strictObject({
  kind: z.enum(INTAKE_KINDS),
  displayName: text(1, 128),
  providerConnectionId: PublicIdSchema.optional().describe(
    'Required for `microsoft_365_journal` / `google_workspace_copy`: an 8.2 connection of the ' +
      'same provider, bound to its tenant, not disabled',
  ),
  networks: networksField.optional(),
  requireTls: z.boolean().optional().describe('Default true'),
  clientCertFingerprints: z.array(fingerprint).max(4).optional(),
  maxMessageBytes: z.number().int().min(1024).max(157_286_400).optional(),
  silenceAlertMinutes: z
    .number()
    .int()
    .min(5)
    .max(10_080)
    .nullable()
    .optional()
    .describe('Default 240; null switches the silence alert off'),
});
export type CreateIntakeSourceBody = z.output<typeof CreateIntakeSourceBodySchema>;

export const UpdateIntakeSourceBodySchema = z
  .strictObject({
    expectedRowVersion: z.number().int().min(1).max(4_294_967_295),
    displayName: text(1, 128).optional(),
    networks: networksField.optional(),
    requireTls: z.boolean().optional(),
    clientCertFingerprints: z.array(fingerprint).max(4).optional(),
    maxMessageBytes: z.number().int().min(1024).max(157_286_400).nullable().optional(),
    silenceAlertMinutes: z.number().int().min(5).max(10_080).nullable().optional(),
    status: z
      .enum(['active', 'paused'])
      .optional()
      .describe(
        '`paused` stops intake (RCPT `450`); `active` resumes it (`pending_verification` until ' +
          'the first accepted message)',
      ),
  })
  .refine((b) => Object.keys(b).some((k) => k !== 'expectedRowVersion'), {
    message: 'must change at least one field',
  });
export type UpdateIntakeSourceBody = z.output<typeof UpdateIntakeSourceBodySchema>;

export const CreatedIntakeSourceSchema = z.object({
  source: IntakeSourceSchema.describe('The source (address and token masked)'),
  address: z
    .string()
    .nullable()
    .describe('The intake address in clear: ONLY in the live response (null on a replay)'),
  headerToken: z
    .string()
    .nullable()
    .describe('Google Workspace: the header token in clear, ONLY in the live response'),
});
export type CreatedIntakeSourceView = z.infer<typeof CreatedIntakeSourceSchema>;

export const AttestationBodySchema = z.strictObject({
  code: z
    .string()
    .max(64)
    .regex(/^[a-z0-9]+(\.[a-z0-9_]+)+$/, 'must be an attestation code')
    .describe('An attestation code of the source kind’s guide (`journal.*`)'),
  attested: z.boolean().describe('`true` records the statement, `false` withdraws it'),
});
export type AttestationBody = z.output<typeof AttestationBodySchema>;

export const AttestationsSchema = z.object({
  sourceId: PublicIdSchema,
  attestations: z.array(
    z.object({ code: z.string(), userId: z.string().nullable(), at: isoInstant }),
  ),
  rowVersion: z.number().int(),
});
export type AttestationsView = z.infer<typeof AttestationsSchema>;

// ---- wizard, guide, status --------------------------------------------------------------------

export const INTAKE_WIZARD_STEPS = [
  'archiving',
  'domains',
  'connection',
  'configure',
  'verify',
  'monitor',
] as const;
export const WIZARD_STEP_STATUSES = [
  'not_started',
  'in_progress',
  'done',
  'blocked',
  'skipped',
] as const;

export const IntakeWizardSchema = z.object({
  sourceId: PublicIdSchema,
  kind: z.enum(INTAKE_KINDS),
  steps: z.array(
    z.object({
      step: z.enum(INTAKE_WIZARD_STEPS),
      status: z.enum(WIZARD_STEP_STATUSES),
      blockers: z.array(z.string()),
      reason: z
        .string()
        .optional()
        .describe(
          'Step API-1: why a step is skipped beyond the kind (`api_mode`: the archiving step, ' +
            'when active API mode entitles the source without archiving)',
        ),
    }),
  ),
  nextAction: z.object({ step: z.enum(INTAKE_WIZARD_STEPS), action: z.string() }).nullable(),
  missingAttestations: z.array(z.string()),
});
export type IntakeWizardView = z.infer<typeof IntakeWizardSchema>;

const guideStep = z.object({
  id: z.string(),
  title: z.string(),
  paragraphs: z.array(z.string()),
  values: z.array(z.object({ label: z.string(), value: z.string() })).optional(),
  commands: z
    .array(z.object({ language: z.enum(['powershell', 'dns', 'text']), code: z.string() }))
    .optional(),
  warning: z.string().optional(),
  attestation: z
    .object({
      code: z.string(),
      statement: z.string(),
      attested: z.boolean(),
      attestedAt: z.string().nullable(),
    })
    .optional(),
});

export const JournalIntakeGuideSchema = z.object({
  schema: z.literal('journal-intake-guide/1'),
  kind: z.enum(INTAKE_KINDS),
  source: z.object({ id: PublicIdSchema, displayName: z.string(), kind: z.enum(INTAKE_KINDS) }),
  address: z.string().describe('Masked unless the caller holds `journal:manage`'),
  headerToken: z.string().optional(),
  revealed: z.boolean(),
  notice: z.string(),
  sections: z.array(
    z.object({
      id: z.string(),
      number: z.number().int(),
      title: z.string(),
      paragraphs: z.array(z.string()),
      steps: z.array(guideStep),
    }),
  ),
  attestations: z.array(
    z.object({
      code: z.string(),
      statement: z.string(),
      attested: z.boolean(),
      attestedAt: z.string().nullable(),
    }),
  ),
  generatedAt: isoInstant,
});

export const JournalingStatusSchema = z.object({
  generatedAt: isoInstant,
  settings: z.object({
    enabled: z.boolean(),
    entitled: z.boolean(),
    intakeEntitled: z.boolean(),
    intakeAvailable: z.boolean(),
    generation: z.number().int(),
  }),
  capture: z.object({
    pending: z.number().int(),
    capturedOpen: z.number().int(),
    closed: z.number().int().describe('Captured and closed (outcome final)'),
    failed: z.number().int(),
    lost: z.number().int(),
    skipped: z.number().int(),
    oldestPendingAt: nullableInstant,
  }),
  sources: z.object({
    total: z.number().int().describe('Not disabled'),
    byStatus: z.record(z.enum(INTAKE_STATUSES), z.number().int()),
    byHealth: z
      .record(z.enum(INTAKE_HEALTH), z.number().int())
      .describe('Sources that are not disabled, by health'),
  }),
  intakeToday: z.object({
    day: z.iso.date(),
    accepted: z.number().int(),
    duplicates: z.number().int(),
    bytes: z.number().int(),
    refused: z.number().int(),
    droppedProof: z.number().int(),
    unwrapFailed: z.number().int(),
  }),
});
export type JournalingStatusView = z.infer<typeof JournalingStatusSchema>;

// ---- examples (OpenAPI; placeholders contain EXAMPLE, addresses masked) --------------------------

const ID = {
  source: '0193a1c2-aaaa-7a00-8000-000000000001',
  connection: '0193a1c2-bbbb-7a00-8000-000000000001',
  user: '0193a1c2-3333-7a00-8000-000000000001',
  domain: '0193a1c2-5555-7a00-8000-000000000001',
} as const;
export const JOURNALING_EXAMPLE_IDS = ID;

const sourceView: IntakeSourceView = {
  id: ID.source,
  kind: 'microsoft_365_journal',
  displayName: 'Contoso Microsoft 365',
  status: 'active',
  providerConnectionId: ID.connection,
  networks: null,
  requireTls: true,
  clientCertFingerprints: [],
  maxMessageBytes: null,
  silenceAlertMinutes: 240,
  address: 'journal-••••wxyz@journal.example.com',
  headerToken: null,
  revealed: false,
  addressVersion: 1,
  previousAddressValidUntil: null,
  verifiedAt: '2026-11-20T08:00:00.000Z',
  lastAcceptedAt: '2026-11-20T09:40:00.000Z',
  lastRefusedAt: null,
  lastRefusalCode: null,
  health: { status: 'healthy', changedAt: '2026-11-20T08:01:00.000Z' },
  attestations: [
    { code: 'journal.m365.rule_created', userId: ID.user, at: '2026-11-20T07:55:00.000Z' },
  ],
  rowVersion: 3,
  createdAt: '2026-11-20T07:50:00.000Z',
  updatedAt: '2026-11-20T08:01:00.000Z',
  disabledAt: null,
};

const counters: IntakeCountersView = {
  day: '2026-11-20',
  accepted: 1834,
  duplicates: 2,
  bytes: 96_468_221,
  refusedAddress: 0,
  refusedNetwork: 0,
  refusedTls: 0,
  refusedSize: 0,
  refusedRate: 0,
  refusedUnavailable: 0,
  droppedProof: 0,
  unwrapFailed: 0,
};

const journalingSettings = {
  directions: { inbound: true, outbound: true, internal: true },
  include: { rejected: false, quarantined: false, failed: false },
  scope: { mode: 'all' as const, domainIds: [], departmentIds: [], userIds: [], addresses: [] },
  policyArchive: { enabled: true },
  intake: { scanEnabled: false },
};

export const JOURNALING_EXAMPLES = {
  settings: {
    enabled: true,
    entitled: true,
    intakeEntitled: true,
    intakeAvailable: true,
    journalEnabledAt: '2026-11-16T09:05:00.000Z',
    settings: journalingSettings,
    generation: 3,
    rowVersion: 3,
    updatedAt: '2026-11-16T09:05:00.000Z',
  } satisfies JournalingSettingsView,
  settingsUpdate: {
    expectedRowVersion: 3,
    settings: {
      directions: { inbound: true, outbound: true, internal: true },
      intake: { scanEnabled: true },
    },
  },
  source: sourceView,
  sourceDetail: { ...sourceView, counters: [counters] } satisfies IntakeSourceDetailView,
  sourcePage: { data: [sourceView], nextCursor: null } satisfies IntakeSourcePage,
  sourceCreate: {
    kind: 'microsoft_365_journal',
    displayName: 'Contoso Microsoft 365',
    providerConnectionId: ID.connection,
  },
  sourceCreateOnPrem: {
    kind: 'exchange_onprem_journal',
    displayName: 'Head office Exchange',
    networks: ['198.51.100.0/28'],
    requireTls: true,
  },
  created: {
    source: { ...sourceView, status: 'pending_verification', verifiedAt: null, rowVersion: 1 },
    address: 'journal-EXAMPLEEXAMPLEEXAMPLEEXAM@journal.example.com',
    headerToken: null,
  } satisfies CreatedIntakeSourceView,
  sourceUpdate: { expectedRowVersion: 3, status: 'paused' },
  attestation: { code: 'journal.m365.rule_created', attested: true },
  attestations: {
    sourceId: ID.source,
    attestations: sourceView.attestations,
    rowVersion: 4,
  } satisfies AttestationsView,
  wizard: {
    sourceId: ID.source,
    kind: 'microsoft_365_journal',
    steps: [
      { step: 'archiving', status: 'done', blockers: [] },
      { step: 'domains', status: 'done', blockers: [] },
      { step: 'connection', status: 'done', blockers: [] },
      { step: 'configure', status: 'in_progress', blockers: ['attestations_missing'] },
      { step: 'verify', status: 'not_started', blockers: [] },
      { step: 'monitor', status: 'blocked', blockers: ['verify'] },
    ],
    nextAction: { step: 'configure', action: 'configure_journal_rule' },
    missingAttestations: ['journal.m365.ndr_mailbox_set'],
  } satisfies IntakeWizardView,
  status: {
    generatedAt: '2026-11-20T09:45:00.000Z',
    settings: {
      enabled: true,
      entitled: true,
      intakeEntitled: true,
      intakeAvailable: true,
      generation: 3,
    },
    capture: {
      pending: 4,
      capturedOpen: 120,
      closed: 15_210,
      failed: 0,
      lost: 0,
      skipped: 12,
      oldestPendingAt: '2026-11-20T09:44:30.000Z',
    },
    sources: {
      total: 2,
      byStatus: { pending_verification: 1, active: 1, paused: 0, disabled: 0 },
      byHealth: { unknown: 1, healthy: 1, silent: 0, failing: 0, paused: 0 },
    },
    intakeToday: {
      day: '2026-11-20',
      accepted: 1834,
      duplicates: 2,
      bytes: 96_468_221,
      refused: 0,
      droppedProof: 0,
      unwrapFailed: 0,
    },
  } satisfies JournalingStatusView,
} as const;

export const INTAKE_LIST_PARAMETERS: Record<string, string> = {
  status: '`pending_verification`, `active`, `paused`, `disabled`; comma list',
  kind: '`microsoft_365_journal`, `google_workspace_copy`, `exchange_onprem_journal`, `smtp_bcc`',
  health: '`unknown`, `healthy`, `silent`, `failing`, `paused`; comma list',
  sort: '`-id` (newest first)',
  limit: 'Page size, 1-100 (default 25)',
  cursor: '`nextCursor` of the previous page',
};
