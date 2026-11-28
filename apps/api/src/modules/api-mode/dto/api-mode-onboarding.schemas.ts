import {
  API_MODE_SCOPE_KINDS,
  apiModeScopeMailboxIdsSchema,
  apiModeScopeSchema,
  DETECT_ONLY_THEN_VALUES,
  REMEDIATION_MODES,
} from '@email-gateway/mailbox-api';
import { z } from 'zod';
import { defineListQuery } from '../../../http/listing/list-query';
import { stripControlCharacters } from '../../webhooks/domain/control-chars';
import {
  CAPABILITY_SUPPORT,
  COVERAGE_GAP_CODES,
  PROTECTION_CAPABILITY_CODES,
} from '../domain/protection-coverage';
import {
  FIRST_COPY_HINT_CODES,
  ONBOARDING_BLOCKERS,
  ONBOARDING_NEXT_ACTIONS,
  ONBOARDING_STEP_KEYS,
  ONBOARDING_STEP_STATUSES,
} from '../domain/domain-onboarding';
import {
  COPY_POLICY_STATES,
  COPY_REMEDIATION_STATES,
  COPY_SOURCES,
  COPY_VERDICTS,
  GRANT_STATUSES,
  HEALTH_STATUSES,
  PROTECTION_MODE_VALUES,
  PROVIDERS,
  PublicIdSchema,
} from './api-mode.schemas';

/**
 * Request and response shapes of the API-mode onboarding routes (step API-4 A10, B6, B8;
 * docs/plan/steps/38-api-mode-parity-onboarding.md, ADR-0107): protection by mode, the domain
 * onboarding state and the per-domain mailbox scope. Requests are strict; views carry ids, names
 * of the caller's own domains and departments (untrusted operator text), codes and counts, never
 * a mailbox address.
 */

const isoInstant = z.iso.datetime({ offset: true });
const nullableInstant = isoInstant.nullable();
const mode = z.enum(PROTECTION_MODE_VALUES);
const count = z.number().int();

// ---- protection by mode (A10) --------------------------------------------------------------

export const ProtectionCoverageQuerySchema = defineListQuery({
  filters: {
    effectiveMode: { type: 'enum', values: PROTECTION_MODE_VALUES, maxValues: 3 },
  },
  sorts: ['-id'],
  defaultSort: '-id',
});
export type ProtectionCoverageQuery = z.output<typeof ProtectionCoverageQuerySchema>;

export const PROTECTION_COVERAGE_PARAMETERS: Record<string, string> = {
  effectiveMode: '`inline`, `api`, `hybrid`; comma list',
  sort: '`-id` (newest domain first)',
  limit: 'Page size, 1-100 (default 25)',
  cursor: '`nextCursor` of the previous page',
};

const capabilitySchema = z.object({
  code: z.enum(PROTECTION_CAPABILITY_CODES),
  inline: z.enum(CAPABILITY_SUPPORT),
  api: z.enum(CAPABILITY_SUPPORT),
  hybrid: z.enum(CAPABILITY_SUPPORT),
  noteCode: z.string().nullable().describe('Why a cell is `partial` / `no` (a fixed code)'),
});

export const DomainCoverageSchema = z.object({
  domainId: PublicIdSchema,
  name: z.string().describe('The domain name (the organization’s own)'),
  status: z.string(),
  effectiveMode: mode,
  inherited: z.boolean().describe('The mode comes from the organization'),
  inline: z.object({
    applies: z.boolean(),
    inboundEnabled: z.boolean(),
    outboundEnabled: z.boolean(),
    mxPointsToGateway: z.boolean().nullable().describe('null: no MX observation yet'),
  }),
  api: z
    .object({
      applies: z.literal(true),
      connection: z
        .object({
          id: PublicIdSchema,
          provider: z.enum(PROVIDERS),
          health: z.enum(HEALTH_STATUSES),
          mailboxAccess: z.enum(['active', 'missing', 'revoked']),
        })
        .nullable(),
      intake: z.object({
        journal: z.enum(['verified', 'pending', 'missing']),
        feeds: z.enum(['active', 'partial', 'off']),
      }),
      scope: z.enum(API_MODE_SCOPE_KINDS),
      mailboxes: z.object({
        inScope: count,
        covered: count,
        gap: count,
        total: count.nullable(),
      }),
      remediation: z.object({
        source: z.enum(['platform_default', 'organization', 'domain']),
        mode: z.enum(REMEDIATION_MODES),
        detectOnlyUntil: nullableInstant,
      }),
      policyEvaluation: z.boolean(),
      lastCopyAt: nullableInstant.describe('Newest journal or feed sighting of its mailboxes'),
    })
    .nullable()
    .describe('null: the domain is inline only'),
  gaps: z.array(z.enum(COVERAGE_GAP_CODES)),
});

export const ProtectionCoverageSchema = z.object({
  entitled: z.boolean().describe('The plan feature `api_mode_protection` is effective'),
  organizationMode: mode,
  totals: z.object({ inline: count, api: count, hybrid: count }),
  capabilities: z
    .array(capabilitySchema)
    .describe('The static capability matrix of the three modes (PROTECTION_MODE_CAPABILITIES)'),
  items: z.array(DomainCoverageSchema),
  nextCursor: z.string().nullable(),
});
export type ProtectionCoverageView = z.infer<typeof ProtectionCoverageSchema>;

// ---- domain onboarding (B8) ----------------------------------------------------------------

const providerCheckSchema = z.object({
  id: z.string(),
  status: z.enum(['pending', 'verified', 'failed', 'expired']),
  result: z.string().nullable(),
  connectionId: PublicIdSchema.nullable(),
  requestedAt: isoInstant,
  checkedAt: nullableInstant,
  expiresAt: isoInstant,
});

export const DomainOnboardingSchema = z.object({
  domainId: PublicIdSchema,
  effectiveMode: mode,
  steps: z.array(
    z.object({
      key: z.enum(ONBOARDING_STEP_KEYS),
      status: z.enum(ONBOARDING_STEP_STATUSES),
      blockers: z.array(z.enum(ONBOARDING_BLOCKERS)),
      nextAction: z.enum(ONBOARDING_NEXT_ACTIONS).nullable(),
    }),
  ),
  ownership: z.object({
    status: z.enum(['pending', 'verified', 'failed']),
    method: z.enum(['dns_txt', 'provider_tenant']).nullable(),
    providerCheck: providerCheckSchema.nullable(),
    providerCheckAvailable: z.boolean(),
  }),
  connection: z
    .object({
      id: PublicIdSchema,
      provider: z.enum(PROVIDERS),
      bound: z.boolean(),
      status: z.enum(['draft', 'connecting', 'configuring', 'active', 'disabled']),
      mailFlowGrant: z.enum(GRANT_STATUSES).nullable(),
      mailboxAccessGrant: z.enum(GRANT_STATUSES).nullable(),
    })
    .nullable()
    .describe('The provider connection the domain is linked to'),
  intake: z.object({
    journalSources: z.array(
      z.object({
        id: PublicIdSchema,
        status: z.enum(['pending_verification', 'active', 'paused', 'disabled']),
        health: z.enum(['unknown', 'healthy', 'silent', 'failing', 'paused']),
      }),
    ),
    feeds: z.object({
      enabled: z.boolean(),
      mode: z.enum(['poll', 'notify']),
      activeMailboxes: count,
      inScopeMailboxes: count,
    }),
  }),
  scope: z.object({ kind: z.enum(API_MODE_SCOPE_KINDS), inScope: count, excluded: count }),
  action: z.object({
    source: z.enum(['platform_default', 'organization', 'domain']),
    mode: z.enum(REMEDIATION_MODES),
    presetKey: z.enum(['p1', 'detectOnlyStart', 'strict']).nullable(),
    detectOnly: z
      .object({ until: isoInstant, then: z.enum(DETECT_ONLY_THEN_VALUES), ended: z.boolean() })
      .nullable(),
  }),
  firstCopy: z.object({
    status: z.enum(['waiting', 'received']),
    copy: z
      .object({
        detectionId: PublicIdSchema,
        receivedAt: isoInstant,
        verdict: z.enum(COPY_VERDICTS).nullable(),
        lagMs: count.nullable(),
        source: z.enum(COPY_SOURCES),
        policyState: z.enum(COPY_POLICY_STATES),
        remediationState: z.enum(COPY_REMEDIATION_STATES),
      })
      .nullable(),
    waitingSinceMinutes: count.nullable(),
    hints: z.array(
      z.object({
        code: z.enum(FIRST_COPY_HINT_CODES),
        severity: z.enum(['info', 'warn']),
        link: z.string().nullable().describe('A portal path, or null'),
      }),
    ),
  }),
});
export type DomainOnboardingResponse = z.infer<typeof DomainOnboardingSchema>;

// ---- scope (B6) ----------------------------------------------------------------------------

export const DomainScopeSchema = z.object({
  domainId: PublicIdSchema,
  kind: z.enum(API_MODE_SCOPE_KINDS),
  departments: z
    .array(
      z.object({
        id: PublicIdSchema,
        name: z.string().nullable().describe('Untrusted operator text; null = deleted'),
        memberCount: count,
      }),
    )
    .describe('The departments of a `departments` scope'),
  selectedMailboxes: count.describe('Mailboxes selected for a `mailboxes` scope'),
  inScope: count.describe('Non-deleted mailboxes of the domain in scope (last evaluation)'),
  excluded: count,
  recomputePending: z
    .boolean()
    .describe('A change is waiting for the mailbox-worker’s next evaluation'),
  rowVersion: count.nullable().describe('CAS version (null: no row; send null to create it)'),
  updatedAt: nullableInstant,
});
export type DomainScopeView = z.infer<typeof DomainScopeSchema>;

/** Untrusted free text: trimmed, control characters removed, 1-500. */
const reasonField = z
  .string()
  .max(2000)
  .transform((v) => stripControlCharacters(v).trim())
  .pipe(z.string().min(1).max(500))
  .describe('Why (1-500 characters; stored in the audit row)');

export const PutDomainScopeBodySchema = z
  .strictObject({
    scope: apiModeScopeSchema.describe(
      '`api-mode-scope/1`: `{ kind: all }`, `{ kind: departments, departmentIds (1-20) }` or ' +
        '`{ kind: mailboxes }`',
    ),
    mailboxIds: apiModeScopeMailboxIdsSchema
      .optional()
      .describe('Kind `mailboxes` only (required there): mailboxes of this domain (≤ 5 000)'),
    reason: reasonField,
    expectedRowVersion: z
      .number()
      .int()
      .min(1)
      .max(4_294_967_295)
      .nullable()
      .describe('The `rowVersion` read (null when no scope row exists: the PUT creates it)'),
  })
  .superRefine((body, ctx) => {
    if (body.scope.kind === 'mailboxes' && body.mailboxIds === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['mailboxIds'],
        message: 'required for kind mailboxes',
      });
    }
    if (body.scope.kind !== 'mailboxes' && body.mailboxIds !== undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['mailboxIds'],
        message: 'only allowed for kind mailboxes',
      });
    }
  });
export type PutDomainScopeBody = z.output<typeof PutDomainScopeBodySchema>;

export const DomainScopeChangeSchema = DomainScopeSchema.extend({
  created: z.boolean(),
  changed: z
    .boolean()
    .describe('The kind or departments changed, or a `mailboxes` selection was written'),
});
export type DomainScopeChangeView = z.infer<typeof DomainScopeChangeSchema>;

// ---- examples (non-secret placeholders) ----------------------------------------------------

const DOMAIN = '0192f3a0-2222-7000-8000-000000000002';
const CONNECTION = '0192f3a0-3333-7000-8000-000000000003';
const SOURCE = '0192f3a0-4444-7000-8000-000000000004';
const DETECTION = '0192f3a0-6666-7000-8000-000000000006';
const DEPARTMENT = '0192f3a0-7777-7000-8000-000000000007';
const MAILBOX = '0192f3a0-5555-7000-8000-000000000005';
const T = '2026-11-27T09:00:00.000Z';

const scopeView = {
  domainId: DOMAIN,
  kind: 'departments' as const,
  departments: [{ id: DEPARTMENT, name: 'Finance', memberCount: 42 }],
  selectedMailboxes: 0,
  inScope: 40,
  excluded: 212,
  recomputePending: false,
  rowVersion: 2,
  updatedAt: T,
};

export const ONBOARDING_EXAMPLES = {
  coverage: {
    entitled: true,
    organizationMode: 'inline' as const,
    totals: { inline: 3, api: 1, hybrid: 1 },
    capabilities: [
      {
        code: 'pre_delivery_blocking' as const,
        inline: 'yes' as const,
        api: 'no' as const,
        hybrid: 'yes' as const,
        noteCode: 'api_acts_after_delivery',
      },
    ],
    items: [
      {
        domainId: DOMAIN,
        name: 'contoso.example',
        status: 'active',
        effectiveMode: 'api' as const,
        inherited: false,
        inline: {
          applies: false,
          inboundEnabled: false,
          outboundEnabled: false,
          mxPointsToGateway: false,
        },
        api: {
          applies: true as const,
          connection: {
            id: CONNECTION,
            provider: 'microsoft_365' as const,
            health: 'healthy' as const,
            mailboxAccess: 'active' as const,
          },
          intake: { journal: 'verified' as const, feeds: 'off' as const },
          scope: 'all' as const,
          mailboxes: { inScope: 250, covered: 248, gap: 2, total: 252 },
          remediation: {
            source: 'domain' as const,
            mode: 'detect_only' as const,
            detectOnlyUntil: '2026-12-04T09:00:00.000Z',
          },
          policyEvaluation: true,
          lastCopyAt: T,
        },
        gaps: ['api_coverage_gaps' as const, 'api_detect_only' as const],
      },
    ],
    nextCursor: null,
  },
  onboarding: {
    domainId: DOMAIN,
    effectiveMode: 'api' as const,
    steps: [
      { key: 'ownership' as const, status: 'done' as const, blockers: [], nextAction: null },
      { key: 'connect' as const, status: 'done' as const, blockers: [], nextAction: null },
      { key: 'intake' as const, status: 'done' as const, blockers: [], nextAction: null },
      { key: 'mailboxes' as const, status: 'done' as const, blockers: [], nextAction: null },
      { key: 'action' as const, status: 'done' as const, blockers: [], nextAction: null },
      {
        key: 'review' as const,
        status: 'in_progress' as const,
        blockers: [],
        nextAction: 'send_test_message' as const,
      },
    ],
    ownership: {
      status: 'verified' as const,
      method: 'provider_tenant' as const,
      providerCheck: {
        id: '4182',
        status: 'verified' as const,
        result: 'verified',
        connectionId: CONNECTION,
        requestedAt: '2026-11-27T08:40:00.000Z',
        checkedAt: '2026-11-27T08:41:00.000Z',
        expiresAt: '2026-11-27T09:40:00.000Z',
      },
      providerCheckAvailable: false,
    },
    connection: {
      id: CONNECTION,
      provider: 'microsoft_365' as const,
      bound: true,
      status: 'active' as const,
      mailFlowGrant: 'active' as const,
      mailboxAccessGrant: 'active' as const,
    },
    intake: {
      journalSources: [{ id: SOURCE, status: 'active' as const, health: 'healthy' as const }],
      feeds: { enabled: false, mode: 'poll' as const, activeMailboxes: 0, inScopeMailboxes: 250 },
    },
    scope: { kind: 'all' as const, inScope: 250, excluded: 0 },
    action: {
      source: 'domain' as const,
      mode: 'detect_only' as const,
      presetKey: 'detectOnlyStart' as const,
      detectOnly: { until: '2026-12-04T09:00:00.000Z', then: 'remind' as const, ended: false },
    },
    firstCopy: {
      status: 'waiting' as const,
      copy: null,
      waitingSinceMinutes: 12,
      hints: [{ code: 'send_test_message' as const, severity: 'info' as const, link: null }],
    },
  },
  firstCopyReceived: {
    detectionId: DETECTION,
    receivedAt: T,
    verdict: 'clean' as const,
    lagMs: 4200,
    source: 'journal' as const,
    policyState: 'evaluated' as const,
    remediationState: 'none' as const,
  },
  scope: scopeView,
  putScope: {
    scope: { kind: 'mailboxes' },
    mailboxIds: [MAILBOX],
    reason: 'Pilot with the finance team first',
    expectedRowVersion: 2,
  },
  scopeChange: {
    ...scopeView,
    kind: 'mailboxes' as const,
    departments: [],
    selectedMailboxes: 1,
    recomputePending: true,
    rowVersion: 3,
    created: false,
    changed: true,
  },
} as const;
