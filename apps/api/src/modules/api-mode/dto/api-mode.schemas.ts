import { z } from 'zod';
import { defineListQuery } from '../../../http/listing/list-query';
import { stripControlCharacters } from '../../webhooks/domain/control-chars';

/**
 * Request and response shapes of the API-mode routes (step API-1 D2, D10, D12; ADR-0098..0100).
 * Request schemas are strict. Views never carry a feed cursor (delta link / history id), a Graph
 * subscription id or a client-state hash (N4, N5); copy subjects are withheld and senders masked
 * (ADR-0062).
 */

export const PublicIdSchema = z.uuid();

const isoInstant = z.iso.datetime({ offset: true });
const nullableInstant = isoInstant.nullable();

export const PROTECTION_MODE_VALUES = ['inline', 'api', 'hybrid'] as const;
export const ProtectionModeSchema = z.enum(PROTECTION_MODE_VALUES);

export const FEED_MODES = ['poll', 'notify'] as const;
export const INVENTORY_STATUSES = ['never', 'ok', 'failed', 'unavailable'] as const;
export const HEALTH_STATUSES = ['unknown', 'healthy', 'degraded', 'failing'] as const;
export const MAILBOX_STATUSES = ['active', 'discovered', 'disabled', 'deleted'] as const;
export const COVERAGE_STATES = ['covered', 'gap', 'out_of_scope'] as const;
export const FEED_STATUSES = ['off', 'pending', 'active', 'error', 'throttled', 'revoked'] as const;
export const COPY_SOURCES = ['journal', 'graph', 'gmail'] as const;
export const COPY_STATUSES = [
  'pending',
  'scanned',
  'scan_failed',
  'parse_failed',
  'too_large',
] as const;
export const COPY_VERDICTS = [
  'clean',
  'spam',
  'bulk',
  'phishing',
  'malware',
  'bec',
  'dlp_violation',
  'suspicious',
  'unknown',
] as const;
export const GRANT_STATUSES = [
  'pending_consent',
  'verifying',
  'active',
  'error',
  'revoked',
] as const;
export const PROVIDERS = ['microsoft_365', 'google_workspace'] as const;
export const CONNECTION_STATUSES = [
  'draft',
  'connecting',
  'configuring',
  'active',
  'disabled',
] as const;
export const WIZARD_STEPS = [
  'domains',
  'connection',
  'journal',
  'mailbox_access',
  'feeds',
  'monitor',
] as const;
export const WIZARD_STEP_STATUSES = [
  'not_started',
  'in_progress',
  'done',
  'blocked',
  'skipped',
] as const;

/** Untrusted free text (the change reason): trimmed, control characters removed, 1-500. */
const reasonField = z
  .string()
  .max(2000)
  .transform((v) => stripControlCharacters(v).trim())
  .pipe(z.string().min(1).max(500))
  .describe('Why the mode changes (1-500 characters; stored in the audit row only)');

// ---- protection mode (D2) ----------------------------------------------------------------------

const modeCounts = z.object({
  inline: z.number().int(),
  api: z.number().int(),
  hybrid: z.number().int(),
});

export const OrganizationProtectionModeSchema = z.object({
  mode: ProtectionModeSchema.describe(
    'The organization’s mode: the default of every domain without its own',
  ),
  changedAt: nullableInstant,
  entitled: z.boolean().describe('The plan feature `api_mode_protection` is effective'),
  active: z
    .boolean()
    .describe('Entitled and at least one domain is effective `api` or `hybrid` (API mode active)'),
  domainsByEffectiveMode: modeCounts.describe('Non-deleted domains per effective mode'),
});
export type OrganizationProtectionModeView = z.infer<typeof OrganizationProtectionModeSchema>;

export const DomainProtectionModeSchema = z.object({
  configured: ProtectionModeSchema.nullable().describe('The domain’s own mode; null = inherit'),
  effective: ProtectionModeSchema.describe('configured ?? the organization’s mode'),
  inherited: z.boolean(),
  changedAt: nullableInstant,
});
export type DomainProtectionModeView = z.infer<typeof DomainProtectionModeSchema>;

export const PutOrganizationModeBodySchema = z.strictObject({
  mode: ProtectionModeSchema,
  reason: reasonField,
});
export type PutOrganizationModeBody = z.output<typeof PutOrganizationModeBodySchema>;

export const PutDomainModeBodySchema = z.strictObject({
  mode: z
    .enum([...PROTECTION_MODE_VALUES, 'inherit'])
    .describe('`inherit` clears the domain’s own mode'),
  reason: reasonField,
});
export type PutDomainModeBody = z.output<typeof PutDomainModeBodySchema>;

export const OrganizationModeChangeSchema = OrganizationProtectionModeSchema.extend({
  organizationId: PublicIdSchema,
  changed: z.boolean().describe('false: the mode already had this value (no audit row)'),
  inheritingDomains: z
    .number()
    .int()
    .describe('Domains whose effective mode follows the organization'),
});
export type OrganizationModeChangeView = z.infer<typeof OrganizationModeChangeSchema>;

export const DomainModeChangeSchema = z.object({
  domainId: PublicIdSchema,
  name: z.string(),
  protectionMode: DomainProtectionModeSchema,
  changed: z.boolean().describe('false: the domain already had this value (no audit row)'),
});
export type DomainModeChangeView = z.infer<typeof DomainModeChangeSchema>;

// ---- connections (D12 #4-#9) -----------------------------------------------------------------

const lagSchema = z.object({
  p50Seconds1h: z.number().int().nullable(),
  p95Seconds1h: z.number().int().nullable(),
  p50Seconds24h: z.number().int().nullable(),
  p95Seconds24h: z.number().int().nullable(),
});

const throttlingSchema = z.object({
  events1h: z.number().int().describe('429 and 503 answers in the last hour'),
  events24h: z.number().int(),
});

const coverageSchema = z.object({
  covered: z.number().int(),
  gap: z.number().int(),
  total: z
    .number()
    .int()
    .nullable()
    .describe('In-scope mailboxes of the last inventory (null = unknown: no inventory yet)'),
  percent: z
    .number()
    .nullable()
    .describe('covered / (covered + gap) × 100 (null without inventory)'),
});

const grantSchema = z
  .object({
    profile: z.string(),
    status: z.enum(GRANT_STATUSES),
    authMethod: z.string(),
  })
  .nullable()
  .describe('The `*.mailbox_remediation` grant of the connection (null: none)');

const journalSourceRef = z.object({
  id: PublicIdSchema,
  displayName: z.string(),
  kind: z.string(),
  status: z.string(),
  health: z.string(),
  verified: z.boolean(),
});

export const ApiModeConnectionSchema = z.object({
  id: PublicIdSchema.describe('The 8.2 provider connection public id'),
  apiConnectionId: PublicIdSchema.nullable().describe('The API-mode row (null until first used)'),
  displayName: z.string(),
  provider: z.enum(PROVIDERS),
  status: z.enum(CONNECTION_STATUSES).describe('The 8.2 connection status'),
  bound: z.boolean().describe('The connection is bound to its tenant'),
  feedsEnabled: z.boolean(),
  feedMode: z.enum(FEED_MODES),
  feedsEnabledAt: nullableInstant,
  inventoryStatus: z.enum(INVENTORY_STATUSES),
  inventorySyncedAt: nullableInstant,
  inventoryRequestedAt: nullableInstant,
  mailboxesTotal: z.number().int().nullable(),
  health: z.object({ status: z.enum(HEALTH_STATUSES), changedAt: nullableInstant }),
  throttledUntil: nullableInstant,
  lastErrorCode: z.string().nullable(),
  grant: grantSchema,
  journalSources: z.array(journalSourceRef).describe('Provider journal intake sources bound to it'),
  rowVersion: z
    .number()
    .int()
    .describe('CAS version of the settings (send it with PUT …/settings)'),
});
export type ApiModeConnectionView = z.infer<typeof ApiModeConnectionSchema>;

export const ApiModeConnectionListSchema = z.object({ data: z.array(ApiModeConnectionSchema) });
export type ApiModeConnectionListView = z.infer<typeof ApiModeConnectionListSchema>;

export const ApiModeWizardSchema = z.object({
  steps: z.array(
    z.object({
      step: z.enum(WIZARD_STEPS),
      status: z.enum(WIZARD_STEP_STATUSES),
      blockers: z.array(z.string()),
    }),
  ),
  nextAction: z.object({ step: z.enum(WIZARD_STEPS), action: z.string() }).nullable(),
});

export const HealthCheckSchema = z.object({
  code: z.string(),
  status: z.enum(['pass', 'warn', 'fail']),
  evidence: z.string().nullable(),
});

export const ConnectionCountersSchema = z.object({
  day: z.string().describe('UTC day (YYYY-MM-DD)'),
  journalCopies: z.number().int(),
  feedCopies: z.number().int(),
  duplicates: z.number().int(),
  skippedInternal: z.number().int(),
  tooLarge: z.number().int(),
  providerRequests: z.number().int(),
  throttled429: z.number().int(),
  throttled503: z.number().int(),
  providerErrors: z.number().int(),
  cursorResets: z.number().int(),
  lagCount: z.number().int(),
  lagP95Seconds: z.number().int().nullable(),
});

export const ApiModeConnectionDetailSchema = ApiModeConnectionSchema.extend({
  coverage: coverageSchema,
  wizard: ApiModeWizardSchema,
  healthChecks: z
    .array(HealthCheckSchema)
    .describe('`api-mode-health/1` checks of the last evaluation'),
  counters: z.array(ConnectionCountersSchema).describe('The last 7 UTC days, newest first'),
});
export type ApiModeConnectionDetailView = z.infer<typeof ApiModeConnectionDetailSchema>;

export const ApiModeOverviewSchema = z.object({
  generatedAt: isoInstant,
  entitled: z.boolean(),
  active: z.boolean(),
  organizationMode: ProtectionModeSchema,
  domainsByEffectiveMode: modeCounts,
  coverage: coverageSchema.describe('Summed over the connections (total null when one is unknown)'),
  connectionsByHealth: z.object({
    unknown: z.number().int(),
    healthy: z.number().int(),
    degraded: z.number().int(),
    failing: z.number().int(),
  }),
  lag: lagSchema,
  throttling: throttlingSchema,
  copiesToday: z.number().int().describe('Journal and feed copies recorded since 00:00 UTC'),
  connections: z.array(
    z.object({
      id: PublicIdSchema,
      displayName: z.string(),
      provider: z.enum(PROVIDERS),
      health: z.enum(HEALTH_STATUSES),
      failingChecks: z.array(z.string()),
      coverage: coverageSchema,
      feedsEnabled: z.boolean(),
      feedMode: z.enum(FEED_MODES),
      grantStatus: z.enum(GRANT_STATUSES).nullable(),
      inventoryStatus: z.enum(INVENTORY_STATUSES),
      lag: lagSchema,
      throttling: throttlingSchema,
      copiesToday: z.number().int(),
      throttledUntil: nullableInstant,
    }),
  ),
});
export type ApiModeOverviewView = z.infer<typeof ApiModeOverviewSchema>;

export const UpdateSettingsBodySchema = z.strictObject({
  feedsEnabled: z.boolean(),
  feedMode: z
    .enum(FEED_MODES)
    .optional()
    .describe('`poll` (default) or `notify` (Microsoft 365 with a platform notification URL)'),
  expectedRowVersion: z.number().int().min(1).max(4_294_967_295),
});
export type UpdateSettingsBody = z.output<typeof UpdateSettingsBodySchema>;

export const InventorySyncSchema = z.object({
  connectionId: PublicIdSchema,
  inventoryRequestedAt: isoInstant,
  nextInventoryAt: isoInstant,
});
export type InventorySyncView = z.infer<typeof InventorySyncSchema>;

// ---- mailboxes (D12 #10-#12) -----------------------------------------------------------------

export const MailboxListQuerySchema = defineListQuery({
  filters: {
    connectionId: { type: 'publicId', maxValues: 1 },
    coverage: { type: 'enum', values: COVERAGE_STATES, maxValues: 3 },
    feedStatus: { type: 'enum', values: FEED_STATUSES, maxValues: 6 },
    status: { type: 'enum', values: MAILBOX_STATUSES, maxValues: 4 },
    domainId: { type: 'publicId', maxValues: 1 },
    q: { type: 'string', maxLength: 320, maxValues: 1 },
  },
  sorts: ['-id'],
  defaultSort: '-id',
});
export type MailboxListQuery = z.output<typeof MailboxListQuerySchema>;

export const MAILBOX_LIST_PARAMETERS: Record<string, string> = {
  connectionId: 'The 8.2 provider connection public id',
  coverage: '`covered`, `gap`, `out_of_scope`; comma list',
  feedStatus: '`off`, `pending`, `active`, `error`, `throttled`, `revoked`; comma list',
  status: '`active`, `discovered`, `disabled`, `deleted`; comma list',
  domainId: 'A domain public id',
  q: 'Prefix of an address of the mailbox (primary or alias), case-insensitive',
  sort: '`-id` (newest first)',
  limit: 'Page size, 1-100 (default 25)',
  cursor: '`nextCursor` of the previous page',
};

export const MailboxSchema = z.object({
  id: PublicIdSchema,
  connectionId: PublicIdSchema.describe('The 8.2 provider connection public id'),
  address: z.string().describe('Primary address (lower case)'),
  domain: z.object({ id: PublicIdSchema, name: z.string() }).nullable(),
  status: z.enum(MAILBOX_STATUSES),
  coverage: z.enum(COVERAGE_STATES),
  coverageChangedAt: nullableInstant,
  feedStatus: z.enum(FEED_STATUSES),
  journalLastSeenAt: nullableInstant,
  lastSyncAt: nullableInstant,
  lastErrorCode: z.string().nullable(),
});
export type MailboxView = z.infer<typeof MailboxSchema>;

export const MailboxPageSchema = z.object({
  data: z.array(MailboxSchema),
  nextCursor: z.string().nullable(),
});
export type MailboxPage = z.infer<typeof MailboxPageSchema>;

// ---- detections (D12 #13, #14) ---------------------------------------------------------------

export const DetectionListQuerySchema = defineListQuery({
  filters: {
    verdict: { type: 'enum', values: COPY_VERDICTS, maxValues: 9 },
    status: { type: 'enum', values: COPY_STATUSES, maxValues: 5 },
    source: { type: 'enum', values: COPY_SOURCES, maxValues: 3 },
    mailboxId: { type: 'publicId', maxValues: 1 },
    connectionId: { type: 'publicId', maxValues: 1 },
    minRiskScore: { type: 'int', min: 0, max: 1000, maxValues: 1 },
  },
  sorts: ['-receivedAt'],
  defaultSort: '-receivedAt',
  range: true,
});
export type DetectionListQuery = z.output<typeof DetectionListQuerySchema>;

export const DETECTION_LIST_PARAMETERS: Record<string, string> = {
  verdict:
    '`clean`, `spam`, `bulk`, `phishing`, `malware`, `bec`, `dlp_violation`, `suspicious`, ' +
    '`unknown`; comma list',
  status: '`pending`, `scanned`, `scan_failed`, `parse_failed`, `too_large`; comma list',
  source: '`journal`, `graph`, `gmail` (the copy that was scanned); comma list',
  mailboxId: 'A mailbox public id',
  connectionId: 'The 8.2 provider connection public id',
  minRiskScore: 'Lowest risk score (0-1000)',
  from: 'Start of the receipt window (default `to` − 7 days; at most 31 days)',
  to: 'End of the receipt window (exclusive; default now)',
  sort: '`-receivedAt` (newest first)',
  limit: 'Page size, 1-100 (default 25)',
  cursor: '`nextCursor` of the previous page',
};

export const DetectionSchema = z.object({
  id: PublicIdSchema,
  mailboxId: PublicIdSchema,
  mailboxAddress: z.string(),
  connectionId: PublicIdSchema,
  source: z.enum(COPY_SOURCES),
  seenJournal: z.boolean(),
  seenApi: z.boolean(),
  status: z.enum(COPY_STATUSES),
  verdict: z.enum(COPY_VERDICTS).nullable(),
  riskScore: z.number().int().nullable(),
  verdictAuthority: z.enum(['copy', 'inline']),
  receivedAt: isoInstant,
  providerDeliveredAt: nullableInstant,
  verdictAt: nullableInstant,
  lagMs: z.number().int().nullable(),
  subject: z.null().describe('Always withheld (ADR-0062)'),
  subjectMasked: z.boolean().describe('The copy has a subject'),
  headerFrom: z
    .string()
    .nullable()
    .describe('The header From address, local part masked (ADR-0062)'),
});
export type DetectionView = z.infer<typeof DetectionSchema>;

export const DetectionPageSchema = z.object({
  data: z.array(DetectionSchema),
  nextCursor: z.string().nullable(),
});
export type DetectionPage = z.infer<typeof DetectionPageSchema>;

export const DetectionDetailSchema = DetectionSchema.extend({
  direction: z.enum(['inbound', 'internal']),
  deliveredBasis: z
    .enum(['received_header', 'graph_received', 'gmail_internal', 'ingest'])
    .nullable(),
  reasonCodes: z.array(z.string()).describe('Up to 10 risk reason codes of the copy (codes only)'),
});
export type DetectionDetailView = z.infer<typeof DetectionDetailSchema>;

export const MailboxDetailSchema = MailboxSchema.extend({
  aliases: z.array(z.string()),
  feedStartedAt: nullableInstant,
  notifications: z.object({
    subscribed: z.boolean().describe('A Graph change-notification subscription exists'),
    expiresAt: nullableInstant,
  }),
  lastChangeAt: nullableInstant,
  lastGapAt: nullableInstant,
  consecutiveFailures: z.number().int(),
  recentDetections: z.array(DetectionSchema).describe('Its last 20 copies, newest first'),
});
export type MailboxDetailView = z.infer<typeof MailboxDetailSchema>;

export const MailboxResyncSchema = z.object({
  mailboxId: PublicIdSchema,
  syncRequestedAt: isoInstant,
});
export type MailboxResyncView = z.infer<typeof MailboxResyncSchema>;

// ---- setup guide (D12 #7) --------------------------------------------------------------------

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

export const ApiModeGuideSchema = z.object({
  schema: z.literal('api-mode-guide/1'),
  provider: z.enum(PROVIDERS),
  connection: z.object({ id: PublicIdSchema, displayName: z.string() }),
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
  journalSource: z
    .object({ id: PublicIdSchema, kind: z.string(), addressMasked: z.string() })
    .optional(),
  platformClientId: z.string().optional(),
  permissions: z.array(z.string()),
  generatedAt: isoInstant,
});

// ---- examples (non-secret placeholders) ------------------------------------------------------

const ORG = '0192f3a0-1111-7000-8000-000000000001';
const DOMAIN = '0192f3a0-2222-7000-8000-000000000002';
const CONNECTION = '0192f3a0-3333-7000-8000-000000000003';
const API_CONNECTION = '0192f3a0-4444-7000-8000-000000000004';
const MAILBOX = '0192f3a0-5555-7000-8000-000000000005';
const DETECTION = '0192f3a0-6666-7000-8000-000000000006';
const SOURCE = '0192f3a0-7777-7000-8000-000000000007';
const T = '2026-11-26T09:00:00.000Z';

const counts = { inline: 3, api: 1, hybrid: 0 };
const lag = { p50Seconds1h: 60, p95Seconds1h: 300, p50Seconds24h: 60, p95Seconds24h: 900 };
const coverage = { covered: 118, gap: 2, total: 120, percent: 98.3 };

const organizationMode = {
  mode: 'inline' as const,
  changedAt: null,
  entitled: true,
  active: true,
  domainsByEffectiveMode: counts,
};

const connection = {
  id: CONNECTION,
  apiConnectionId: API_CONNECTION,
  displayName: 'Contoso Microsoft 365',
  provider: 'microsoft_365' as const,
  status: 'active' as const,
  bound: true,
  feedsEnabled: true,
  feedMode: 'poll' as const,
  feedsEnabledAt: T,
  inventoryStatus: 'ok' as const,
  inventorySyncedAt: T,
  inventoryRequestedAt: null,
  mailboxesTotal: 120,
  health: { status: 'healthy' as const, changedAt: T },
  throttledUntil: null,
  lastErrorCode: null,
  grant: {
    profile: 'm365.mailbox_remediation',
    status: 'active' as const,
    authMethod: 'platform_app',
  },
  journalSources: [
    {
      id: SOURCE,
      displayName: 'Contoso journal',
      kind: 'microsoft_365_journal',
      status: 'active',
      health: 'healthy',
      verified: true,
    },
  ],
  rowVersion: 2,
};

const detection = {
  id: DETECTION,
  mailboxId: MAILBOX,
  mailboxAddress: 'alex@contoso.example',
  connectionId: CONNECTION,
  source: 'journal' as const,
  seenJournal: true,
  seenApi: false,
  status: 'scanned' as const,
  verdict: 'phishing' as const,
  riskScore: 870,
  verdictAuthority: 'copy' as const,
  receivedAt: T,
  providerDeliveredAt: '2026-11-26T08:59:40.000Z',
  verdictAt: '2026-11-26T09:00:12.000Z',
  lagMs: 32_000,
  subject: null,
  subjectMasked: true,
  headerFrom: 'b***@fabrikam.example',
};

const mailbox = {
  id: MAILBOX,
  connectionId: CONNECTION,
  address: 'alex@contoso.example',
  domain: { id: DOMAIN, name: 'contoso.example' },
  status: 'active' as const,
  coverage: 'covered' as const,
  coverageChangedAt: T,
  feedStatus: 'active' as const,
  journalLastSeenAt: T,
  lastSyncAt: T,
  lastErrorCode: null,
};

export const API_MODE_EXAMPLES = {
  organizationMode,
  organizationModeUpdate: { mode: 'hybrid', reason: 'Post-delivery protection for every domain' },
  organizationModeChange: {
    ...organizationMode,
    mode: 'hybrid' as const,
    changedAt: T,
    domainsByEffectiveMode: { inline: 0, api: 1, hybrid: 3 },
    organizationId: ORG,
    changed: true,
    inheritingDomains: 3,
  },
  domainModeUpdate: { mode: 'api', reason: 'MX stays at Microsoft 365; protect by API' },
  domainModeChange: {
    domainId: DOMAIN,
    name: 'contoso.example',
    protectionMode: {
      configured: 'api' as const,
      effective: 'api' as const,
      inherited: false,
      changedAt: T,
    },
    changed: true,
  },
  overview: {
    generatedAt: T,
    entitled: true,
    active: true,
    organizationMode: 'inline' as const,
    domainsByEffectiveMode: counts,
    coverage,
    connectionsByHealth: { unknown: 0, healthy: 1, degraded: 0, failing: 0 },
    lag,
    throttling: { events1h: 0, events24h: 3 },
    copiesToday: 412,
    connections: [
      {
        id: CONNECTION,
        displayName: 'Contoso Microsoft 365',
        provider: 'microsoft_365' as const,
        health: 'healthy' as const,
        failingChecks: [],
        coverage,
        feedsEnabled: true,
        feedMode: 'poll' as const,
        grantStatus: 'active' as const,
        inventoryStatus: 'ok' as const,
        lag,
        throttling: { events1h: 0, events24h: 3 },
        copiesToday: 412,
        throttledUntil: null,
      },
    ],
  },
  connection,
  connections: { data: [connection] },
  connectionDetail: {
    ...connection,
    coverage,
    wizard: {
      steps: [
        { step: 'domains' as const, status: 'done' as const, blockers: [] },
        { step: 'connection' as const, status: 'done' as const, blockers: [] },
        { step: 'journal' as const, status: 'done' as const, blockers: [] },
        { step: 'mailbox_access' as const, status: 'done' as const, blockers: [] },
        { step: 'feeds' as const, status: 'done' as const, blockers: [] },
        { step: 'monitor' as const, status: 'done' as const, blockers: [] },
      ],
      nextAction: null,
    },
    healthChecks: [{ code: 'connection.active', status: 'pass' as const, evidence: null }],
    counters: [
      {
        day: '2026-11-26',
        journalCopies: 380,
        feedCopies: 32,
        duplicates: 30,
        skippedInternal: 12,
        tooLarge: 0,
        providerRequests: 940,
        throttled429: 0,
        throttled503: 0,
        providerErrors: 0,
        cursorResets: 0,
        lagCount: 412,
        lagP95Seconds: 300,
      },
    ],
  },
  settingsUpdate: { feedsEnabled: true, feedMode: 'poll', expectedRowVersion: 1 },
  inventorySync: { connectionId: CONNECTION, inventoryRequestedAt: T, nextInventoryAt: T },
  mailbox,
  mailboxPage: { data: [mailbox], nextCursor: null },
  mailboxDetail: {
    ...mailbox,
    aliases: ['a.smith@contoso.example'],
    feedStartedAt: T,
    notifications: { subscribed: false, expiresAt: null },
    lastChangeAt: T,
    lastGapAt: null,
    consecutiveFailures: 0,
    recentDetections: [detection],
  },
  mailboxResync: { mailboxId: MAILBOX, syncRequestedAt: T },
  detection,
  detectionPage: { data: [detection], nextCursor: null },
  detectionDetail: {
    ...detection,
    direction: 'inbound' as const,
    deliveredBasis: 'received_header' as const,
    reasonCodes: ['url.phishing_kit', 'auth.dmarc_fail'],
  },
} as const;
