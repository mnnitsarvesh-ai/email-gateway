import type { ListItem, SuccessBody } from '@/lib/api/types';

/** Test builders for the policy pages (typed against schema.gen.ts; synthetic values). */
export const POLICY_ID = '01933c3a-1b2c-7d4e-8f00-0000000c0001';
const ADMIN = '01933c3a-1b2c-7d4e-8f00-000000000a01';

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
    activeVersion: {
      versionNo: 2,
      definitionSha256: 'a'.repeat(64),
      ruleCount: 2,
      hasOverrideRules: false,
      publishedAt: '2026-11-01T09:00:00.000Z',
    },
    counts: { drafts: 1, published: 1, superseded: 1, limit: 50 },
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
    references: null,
    changeNote: 'Tuned thresholds',
    rowVersion: 1,
    createdByUserId: ADMIN,
    updatedByUserId: ADMIN,
    publishedByUserId: ADMIN,
    publishedAt: '2026-11-01T09:00:00.000Z',
    createdAt: '2026-10-30T09:00:00.000Z',
    updatedAt: '2026-11-01T09:00:00.000Z',
    definition: {
      dslVersion: 'policy-dsl/1',
      direction: 'inbound',
      rules: [
        {
          id: 'warn',
          when: { field: 'risk.level', op: 'in', value: ['high'] },
          actions: [{ type: 'WARN', text: '<script>window.__pwned=3</script>' }],
        },
      ],
    },
    validation: { valid: true, violations: [] },
    ...overrides,
  };
}

export function versionRow(
  versionNo: number,
): ListItem<'PolicyManagementController_listVersions_v1'> {
  const { definition, validation, ...row } = versionDetail({
    versionNo,
    active: versionNo === 2,
    status: versionNo === 3 ? 'draft' : versionNo === 2 ? 'published' : 'superseded',
  });
  void definition;
  void validation;
  return row;
}

export function execution(
  overrides: Partial<ListItem<'PolicyToolsController_history_v1'>> = {},
): ListItem<'PolicyToolsController_history_v1'> {
  return {
    messageId: '01933c3a-1b2c-7d4e-8f00-00000000a001',
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
    ...overrides,
  };
}

export const CATALOG: SuccessBody<'PolicyToolsController_catalog_v1'> = {
  versions: { dsl: 'policy-dsl/1', input: 'policy-input/1', evaluator: 'policy-eval/2' },
  platformDefault: { id: 'platform-default/1', description: 'Follow the risk recommendation.' },
  fields: [
    {
      name: 'risk.score',
      type: 'int',
      scope: 'message',
      ops: ['gt', 'gte', 'between'],
      quantified: false,
      authenticatedIdentity: false,
      senderIdentity: null,
      aiDerived: false,
      directions: ['inbound', 'outbound', 'internal'],
      values: null,
      ordered: false,
      min: 0,
      max: 1000,
      description: 'Risk score of the round.',
    },
    {
      name: 'attachments.type_family',
      type: 'enum',
      scope: 'attachments',
      ops: ['in', 'not_in'],
      quantified: true,
      authenticatedIdentity: false,
      senderIdentity: null,
      aiDerived: false,
      directions: ['inbound'],
      values: ['document', 'executable'],
      ordered: false,
      min: null,
      max: null,
      description: 'Detected type family of each attachment.',
    },
  ],
  operators: ['in', 'not_in', 'gt', 'gte', 'between', 'regex'],
  actions: ['ALLOW', 'QUARANTINE', 'TAG'],
  nonTerminalActions: ['TAG'],
  dispositions: ['allow', 'quarantine'],
  limits: { maxPolicies: 50 },
  settingsDefaults: {
    allowRecommendationOverrides: false,
    notices: { senderNonDelivery: true },
    alerts: { enabled: true },
    tagging: { platformTagHeader: true, platformTagOutbound: false },
  },
  enforcement: 'Dispositions are enforced.',
};

export const POLICY_SETTINGS: SuccessBody<'PolicySettingsController_get_v1'> = {
  settings: {},
  effective: {
    allowRecommendationOverrides: true,
    recipientSplit: true,
    notices: { senderNonDelivery: true },
    alerts: { enabled: false },
    tagging: { platformTagHeader: true, platformTagOutbound: false },
  },
  violations: [],
  generation: '42',
  rowVersion: 3,
  settingsSha256: null,
  updatedByUserId: null,
  updatedAt: null,
};

const hardBlock = { enabled: true, action: 'quarantine' as const };
export const RISK_PROFILE: SuccessBody<'RiskProfilesController_profile_v1'> = {
  id: null,
  profileVersion: 0,
  platformProfile: 'rsk-default/1',
  active: {
    source: 'platform',
    versionId: null,
    versionNo: null,
    profileId: 'rsk-default/1',
    sha256: 'c'.repeat(64),
    fallback: null,
    violations: [],
  },
  effectiveProfile: {
    base: 'rsk-default/1',
    thresholds: { low: 150, medium: 300, high: 600, critical: 800 },
    actions: {
      none: 'deliver',
      low: 'deliver',
      medium: 'tag',
      high: 'quarantine',
      critical: 'block',
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
      'hb.malware_attachment': hardBlock,
      'hb.malware_url': hardBlock,
      'hb.malware_sandbox': hardBlock,
      'hb.dlp_block': hardBlock,
      'hb.known_phishing': hardBlock,
      'hb.tenant_domain_spoof': hardBlock,
      'hb.url_tenant_blocked': hardBlock,
      'hb.bec_malicious': hardBlock,
      'hb.dmarc_reject': { enabled: false, action: 'quarantine' },
    },
    failures: {
      engineFailureWeight: 200,
      groupCap: 400,
      unknownWeight: 100,
      minLevel: 'medium',
      unknownMinLevel: 'low',
      action: 'quarantine',
      unknownAction: 'tag',
    },
    floors: { engineMalicious: 'high', becSuspicious: 'medium' },
    trust: { mode: 'off', contentFactorPermille: 1000 },
    ai: { tagOnAiOnlyRaise: true },
  },
  counts: { drafts: 0, published: 0, limit: 20 },
  updatedByUserId: null,
  updatedAt: null,
};
