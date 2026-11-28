import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import { toBuilderCatalog } from './builder';

/** Test builders for the policy pages (typed against schema.gen.ts; synthetic values). */
export const POLICY_ID = '01933c3a-1b2c-7d4e-8f00-0000000c0001';
export const OTHER_POLICY_ID = '01933c3a-1b2c-7d4e-8f00-0000000c0009';
export const ADMIN = '01933c3a-1b2c-7d4e-8f00-000000000a01';
export const FINANCE_DEPT = '01933c3a-1b2c-7d4e-8f00-0000000d0001';
export const MESSAGE_ID = '01933c3a-1b2c-7d4e-8f00-00000000a001';

type Catalog = SuccessBody<'PolicyToolsController_catalog_v1'>;

/**
 * The real catalogue snapshot (docs/api/policy-catalog.json, written by WP1's drift check) with
 * a concrete time-zone list in place of its runtime marker.
 */
export const REAL_CATALOG: Catalog = {
  ...(JSON.parse(
    readFileSync(join(__dirname, '../../../../../docs/api/policy-catalog.json'), 'utf8'),
  ) as Catalog),
  timeZones: ['America/New_York', 'Asia/Calcutta', 'Asia/Kolkata', 'Europe/London', 'UTC'],
};
export const REAL_BUILDER_CATALOG = toBuilderCatalog(REAL_CATALOG);

/** Version 2 (published, active): the brief's example (design B5). */
export const DEFINITION_V2 = {
  dslVersion: 'policy-dsl/1',
  direction: 'outbound',
  priority: 10,
  rules: [
    {
      id: 'quarantine-confidential',
      priority: 10,
      description: 'Hold confidential data leaving the organization',
      when: { all: [{ field: 'dlp.categories', op: 'contains_any', value: ['confidential'] }] },
      actions: [{ type: 'QUARANTINE' }, { type: 'ALERT', severity: 'warning' }],
    },
  ],
};

/** Version 3 (draft): a second condition, a second rule and a policy-wide exception. */
export const DEFINITION_V3 = {
  dslVersion: 'policy-dsl/1',
  direction: 'outbound',
  priority: 10,
  rules: [
    {
      id: 'quarantine-confidential',
      priority: 10,
      description: 'Hold confidential data leaving the organization',
      when: {
        all: [
          { field: 'dlp.categories', op: 'contains_any', value: ['confidential'] },
          {
            field: 'recipient.domain',
            op: 'not_in',
            value: ['corp.example'],
            quantifier: 'any',
          },
        ],
      },
      actions: [{ type: 'QUARANTINE' }, { type: 'ALERT', severity: 'warning' }],
    },
    {
      id: 'tag-attachments',
      priority: 20,
      when: { field: 'attachments.count', op: 'gt', value: 0 },
      actions: [{ type: 'TAG', label: 'external-attachment' }],
    },
  ],
  exceptions: [{ field: 'sender.department', op: 'in', value: [FINANCE_DEPT] }],
};

export function policyRow(
  overrides: Partial<ListItem<'PolicyManagementController_list_v1'>> = {},
): ListItem<'PolicyManagementController_list_v1'> {
  return {
    id: POLICY_ID,
    name: 'Inbound threats',
    description: 'Quarantine high-risk inbound mail',
    status: 'active',
    direction: 'inbound',
    priority: 10,
    activeVersionNo: 2,
    latestVersionNo: 3,
    rowVersion: 4,
    createdByUserId: ADMIN,
    updatedByUserId: ADMIN,
    createdAt: '2026-10-01T09:00:00.000Z',
    updatedAt: '2026-11-10T09:00:00.000Z',
    ...overrides,
  };
}

export function policyDetail(
  overrides: Partial<SuccessBody<'PolicyManagementController_get_v1'>> = {},
): SuccessBody<'PolicyManagementController_get_v1'> {
  return {
    ...policyRow(),
    name: 'Confidential data',
    direction: 'outbound',
    activeVersion: {
      versionNo: 2,
      definitionSha256: 'a'.repeat(64),
      ruleCount: 1,
      hasOverrideRules: false,
      publishedAt: '2026-11-01T09:00:00.000Z',
    },
    counts: { drafts: 1, published: 2, superseded: 0, limit: 200 },
    ...overrides,
  };
}

export function versionDetail(
  overrides: Partial<SuccessBody<'PolicyManagementController_getVersion_v1'>> = {},
): SuccessBody<'PolicyManagementController_getVersion_v1'> {
  return {
    policyId: POLICY_ID,
    versionNo: 2,
    status: 'published',
    active: true,
    dslVersion: 'policy-dsl/1',
    definitionSha256: 'a'.repeat(64),
    ruleCount: 1,
    hasOverrideRules: false,
    references: { departmentIds: [], userIds: [] },
    changeNote: 'Tuned thresholds',
    rowVersion: 2,
    createdByUserId: ADMIN,
    updatedByUserId: ADMIN,
    publishedByUserId: ADMIN,
    publishedAt: '2026-11-01T09:00:00.000Z',
    createdAt: '2026-10-30T09:00:00.000Z',
    updatedAt: '2026-11-01T09:00:00.000Z',
    definition: DEFINITION_V2,
    validation: { valid: true, violations: [] },
    ...overrides,
  };
}

/** Version 3: the draft being edited (row version 5). */
export function draftVersion(
  overrides: Partial<SuccessBody<'PolicyManagementController_getVersion_v1'>> = {},
): SuccessBody<'PolicyManagementController_getVersion_v1'> {
  return versionDetail({
    versionNo: 3,
    status: 'draft',
    active: false,
    ruleCount: 2,
    references: null,
    changeNote: 'Second rule and a finance exception',
    rowVersion: 5,
    publishedByUserId: null,
    publishedAt: null,
    definition: DEFINITION_V3,
    ...overrides,
  });
}

export function versionRow(
  versionNo: number,
  overrides: Partial<ListItem<'PolicyManagementController_listVersions_v1'>> = {},
): ListItem<'PolicyManagementController_listVersions_v1'> {
  const base =
    versionNo === 3
      ? draftVersion()
      : versionDetail({
          versionNo,
          active: versionNo === 2,
          status: 'published',
          changeNote: versionNo === 1 ? 'Initial version' : 'Tuned thresholds',
        });
  const { definition, validation, ...row } = base;
  void definition;
  void validation;
  return { ...row, ...overrides };
}

export function execution(
  overrides: Partial<ListItem<'PolicyToolsController_history_v1'>> = {},
): ListItem<'PolicyToolsController_history_v1'> {
  return {
    messageId: MESSAGE_ID,
    receivedAt: '2026-11-12T09:14:03.120Z',
    lifecycleRound: 0,
    scanId: '900001',
    trigger: 'scanned',
    direction: 'inbound',
    disposition: 'quarantine',
    finalAction: 'quarantine',
    decisive: {
      source: 'tenant_rule',
      policyId: POLICY_ID,
      versionNo: 2,
      ruleId: 'block-high-risk',
    },
    actions: [{ type: 'QUARANTINE', status: 'enforced' }],
    matchedRuleCount: 1,
    overrideApplied: false,
    generation: '42',
    inputSha256: 'b'.repeat(64),
    durationUs: 1850,
    evaluatedAt: '2026-11-12T09:14:07.000Z',
    evaluationMode: 'inline',
    ...overrides,
  };
}

export function validateResponse(
  overrides: Partial<SuccessBody<'PolicyToolsController_validate_v1'>> = {},
): SuccessBody<'PolicyToolsController_validate_v1'> {
  return {
    dslVersion: 'policy-dsl/1',
    valid: true,
    violations: [],
    referenceViolations: [],
    ruleCount: 2,
    hasOverrideRules: false,
    references: { departmentIds: [FINANCE_DEPT], userIds: [] },
    definitionSha256: 'e'.repeat(64),
    ...overrides,
  };
}

export const POLICY_SETTINGS: SuccessBody<'PolicySettingsController_get_v1'> = {
  settings: { allowRecommendationOverrides: false, tagging: { platformTagOutbound: false } },
  effective: {
    allowRecommendationOverrides: false,
    notices: { senderNonDelivery: true },
    alerts: { enabled: false },
    tagging: { platformTagHeader: true, platformTagOutbound: false },
  },
  violations: [],
  generation: '42',
  rowVersion: 3,
  settingsSha256: 'f'.repeat(64),
  updatedByUserId: null,
  updatedAt: null,
};

type PlatformView = SuccessBody<'RiskProfilesController_platformProfile_v1'>;
type EffectiveProfile = PlatformView['profile'];
type RiskAction = EffectiveProfile['actions']['none'];
const hardBlock = (enabled: boolean, action: RiskAction) => ({ enabled, action });

/** The platform risk profile `rsk-default/1` (the values of `@email-gateway/risk-scoring`). */
export const PLATFORM_PROFILE: EffectiveProfile = {
  base: 'rsk-default/1',
  thresholds: { low: 100, medium: 300, high: 550, critical: 800 },
  actions: {
    none: 'deliver',
    low: 'deliver',
    medium: 'tag',
    high: 'quarantine',
    critical: 'quarantine',
  },
  groupMultipliersPermille: {
    auth_dmarc: 1000,
    auth_other: 1000,
    spam: 1000,
    reputation_ip: 1000,
    reputation_domain: 1000,
    url_threat: 1000,
    lookalike: 1000,
    credential: 1000,
    url_structure: 1000,
    phishing_content: 1000,
    attachment_malware: 1000,
    attachment_risky: 1000,
    bec_impersonation: 1000,
    bec_identity: 1000,
    bec_intent: 1000,
    bec_history: 1000,
    dlp: 1000,
    coverage: 1000,
    engine_failure: 1000,
    engine_unknown: 1000,
    sandbox: 1000,
  },
  hardBlocks: {
    'hb.malware_attachment': hardBlock(true, 'block'),
    'hb.malware_url': hardBlock(true, 'block'),
    'hb.malware_sandbox': hardBlock(true, 'quarantine'),
    'hb.dlp_block': hardBlock(true, 'block'),
    'hb.known_phishing': hardBlock(true, 'quarantine'),
    'hb.tenant_domain_spoof': hardBlock(true, 'quarantine'),
    'hb.url_tenant_blocked': hardBlock(true, 'quarantine'),
    'hb.bec_malicious': hardBlock(true, 'quarantine'),
    'hb.dmarc_reject': hardBlock(false, 'quarantine'),
  },
  failures: {
    engineFailureWeight: 300,
    groupCap: 600,
    unknownWeight: 60,
    minLevel: 'medium',
    unknownMinLevel: 'low',
    action: 'quarantine',
    unknownAction: 'tag',
  },
  floors: { engineMalicious: 'high', becSuspicious: 'low' },
  trust: { mode: 'reduce_content', contentFactorPermille: 500 },
  ai: { tagOnAiOnlyRaise: true },
};

const TUNABLE = Object.keys(PLATFORM_PROFILE.groupMultipliersPermille).filter(
  (g) => !['attachment_malware', 'engine_failure', 'engine_unknown', 'sandbox'].includes(g),
) as PlatformView['bounds']['tunableGroups'];

export const PLATFORM_VIEW: PlatformView = {
  id: 'rsk-default/1',
  sha256: '6'.repeat(64),
  profile: PLATFORM_PROFILE,
  versions: { scorer: 'risk-score/1', signalMap: 'risk-signals/1', input: 'risk-input/1' },
  bounds: {
    thresholds: {
      low: { min: 50, max: 250 },
      medium: { min: 200, max: 450 },
      high: { min: 400, max: 700 },
      critical: { min: 650, max: 950 },
    },
    thresholdMinGap: 50,
    actions: {
      none: ['deliver'],
      low: ['deliver', 'tag'],
      medium: ['tag', 'require_approval', 'quarantine'],
      high: ['require_approval', 'quarantine', 'block'],
      critical: ['quarantine', 'block'],
    },
    groupMultiplierPermille: { min: 500, max: 2000 },
    tunableGroups: TUNABLE,
    lockedGroups: ['attachment_malware', 'engine_failure', 'engine_unknown', 'sandbox'],
    failures: {
      engineFailureWeight: { min: 200, max: 600 },
      groupCap: { min: 300, max: 1000 },
      unknownWeight: { min: 30, max: 200 },
      minLevel: ['medium', 'high', 'critical'],
      unknownMinLevel: ['low', 'medium', 'high'],
      action: ['require_approval', 'quarantine'],
      unknownAction: ['tag', 'require_approval', 'quarantine'],
    },
    floors: { engineMalicious: ['high', 'critical'], becSuspicious: ['low', 'medium', 'high'] },
    trustContentFactorPermille: { min: 250, max: 1000 },
    raiseOnly: ['failures.minLevel', 'floors.engineMalicious'],
  },
  groups: [],
  signals: [],
  hardBlocks: [
    {
      id: 'hb.dlp_block',
      verdict: 'dlp_violation',
      defaultEnabled: true,
      defaultAction: 'block',
      control: 'locked',
      allowedActions: ['block'],
      firesWhen: 'dlp action block',
    },
    {
      id: 'hb.known_phishing',
      verdict: 'phishing',
      defaultEnabled: true,
      defaultAction: 'quarantine',
      control: 'may_disable',
      allowedActions: ['block', 'quarantine'],
      firesWhen: 'signal url_known_phishing',
    },
    {
      id: 'hb.dmarc_reject',
      verdict: 'phishing',
      defaultEnabled: false,
      defaultAction: 'quarantine',
      control: 'may_enable',
      allowedActions: ['block', 'quarantine'],
      firesWhen: 'inbound, signal auth_dmarc_reject',
    },
  ],
  notice: 'Step 5.1 recommends and never enforces (test notice).',
};

export const RISK_VERSION_ID = '01933c3a-1b2c-7d4e-8f00-0000000e0003';
export const RISK_ACTIVE_ID = '01933c3a-1b2c-7d4e-8f00-0000000e0002';

export function riskVersion(
  overrides: Partial<SuccessBody<'RiskProfilesController_getVersion_v1'>> = {},
): SuccessBody<'RiskProfilesController_getVersion_v1'> {
  const stored = { groupMultipliersPermille: { url_threat: 1200 }, thresholds: { high: 500 } };
  return {
    id: RISK_VERSION_ID,
    versionNo: 3,
    status: 'draft',
    baseProfile: 'rsk-default/1',
    overridesSha256: '1'.repeat(64),
    profileSha256: null,
    changeNote: 'Stricter on links',
    rowVersion: 4,
    active: false,
    createdByUserId: ADMIN,
    updatedByUserId: ADMIN,
    publishedByUserId: null,
    publishedAt: null,
    createdAt: '2026-11-10T09:00:00.000Z',
    updatedAt: '2026-11-11T09:00:00.000Z',
    overrides: stored,
    resolved: {
      valid: true,
      profileId: `rsk-default/1+t:${RISK_VERSION_ID}#3`,
      sha256: '2'.repeat(64),
      effectiveProfile: {
        ...PLATFORM_PROFILE,
        thresholds: { ...PLATFORM_PROFILE.thresholds, high: 500 },
        groupMultipliersPermille: {
          ...PLATFORM_PROFILE.groupMultipliersPermille,
          url_threat: 1200,
        },
      },
      violations: [],
    },
    ...overrides,
  };
}

export function riskVersionRow(
  versionNo: number,
  overrides: Partial<ListItem<'RiskProfilesController_listVersions_v1'>> = {},
): ListItem<'RiskProfilesController_listVersions_v1'> {
  const {
    overrides: stored,
    resolved,
    ...row
  } = riskVersion({
    id:
      versionNo === 3
        ? RISK_VERSION_ID
        : versionNo === 2
          ? RISK_ACTIVE_ID
          : `01933c3a-1b2c-7d4e-8f00-0000000e000${versionNo}`,
    versionNo,
    status: versionNo === 3 ? 'draft' : 'published',
    active: versionNo === 2,
    publishedAt: versionNo === 3 ? null : '2026-11-01T09:00:00.000Z',
  });
  void stored;
  void resolved;
  return { ...row, ...overrides };
}

export const RISK_PROFILE: SuccessBody<'RiskProfilesController_profile_v1'> = {
  id: '01933c3a-1b2c-7d4e-8f00-0000000e0000',
  profileVersion: 7,
  platformProfile: 'rsk-default/1',
  active: {
    source: 'tenant',
    versionId: RISK_ACTIVE_ID,
    versionNo: 2,
    profileId: `rsk-default/1+t:${RISK_ACTIVE_ID}#2`,
    sha256: 'c'.repeat(64),
    fallback: null,
    violations: [],
  },
  effectiveProfile: PLATFORM_PROFILE,
  counts: { drafts: 1, published: 2, limit: 200 },
  updatedByUserId: null,
  updatedAt: null,
};

export const PLATFORM_RISK_PROFILE: SuccessBody<'RiskProfilesController_profile_v1'> = {
  ...RISK_PROFILE,
  id: null,
  profileVersion: 0,
  active: {
    source: 'platform',
    versionId: null,
    versionNo: null,
    profileId: 'rsk-default/1',
    sha256: 'c'.repeat(64),
    fallback: null,
    violations: [],
  },
  counts: { drafts: 0, published: 0, limit: 200 },
};

/** A `GET /policies/executions`-style empty page. */
export const EMPTY_PAGE = { data: [], nextCursor: null };

export const DEPARTMENTS_PAGE = {
  data: [
    {
      id: FINANCE_DEPT,
      name: 'Finance',
      description: null,
      memberCount: 3,
      rowVersion: 1,
      createdByUserId: ADMIN,
      updatedByUserId: ADMIN,
      createdAt: '2026-10-01T09:00:00.000Z',
      updatedAt: '2026-10-01T09:00:00.000Z',
    },
  ],
  nextCursor: null,
};

export const USERS_PAGE = {
  data: [
    {
      id: ADMIN,
      email: 'admin@alpha.example.test',
      displayName: 'Dana Admin',
      status: 'active' as const,
      statusReason: null,
      roles: [{ key: 'organization_admin', name: 'Organization admin' }],
      mfaEnabled: true,
      emailVerified: true,
      lockedUntil: null,
      lastLoginAt: null,
      createdAt: '2026-10-01T09:00:00.000Z',
      updatedAt: '2026-10-01T09:00:00.000Z',
    },
  ],
  nextCursor: null,
};
