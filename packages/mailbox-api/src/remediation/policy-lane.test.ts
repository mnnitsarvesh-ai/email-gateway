import { describe, expect, it } from 'vitest';
import { CLAWBACK_STRENGTH_ORDER, actionStrength } from '../clawback/vocabulary';
import { evaluateApiModeHealth, evaluatePolicyHealth } from '../health';
import {
  API_MAILBOX_SCOPE_STATES,
  API_MODE_SCOPE_KINDS,
  API_MODE_SCOPE_MAX_DEPARTMENTS,
  API_MODE_SCOPE_MAX_MAILBOXES,
  apiModeScopeMailboxIdsSchema,
  apiModeScopeSchema,
  DEFAULT_API_MODE_SCOPE,
  initialScopeState,
  mailboxInScope,
} from '../scope';
import {
  API_MODE_DETECT_ONLY_DEFAULT_DAYS,
  defaultDetectOnly,
  DETECT_ONLY_THEN_VALUES,
  detectOnlyDue,
  detectOnlySchema,
  validateDetectOnly,
} from './detect-only';
import {
  buildDecisionRecord,
  decideRemediation,
  DEFAULT_REMEDIATION_POLICY,
  parseRemediationPolicy,
  REMEDIATION_PRESETS,
  remediationDecisionRecordSchema,
  remediationDecisionRecordV1Schema,
  remediationLanes,
  resolveEffectivePolicy,
  USE_POLICY_MAPPING,
  type RemediationInput,
  type RemediationPolicy,
} from './policy';
import {
  copyDetectionOf,
  DEFAULT_POLICY_MAPPING,
  effectivePolicyMapping,
  POLICY_MAPPING_KEYS,
  POLICY_OUTCOME_ACTION_TYPES,
  POLICY_OUTCOME_DECISION_SOURCES,
  POLICY_OUTCOME_DISPOSITIONS,
  POLICY_OUTCOME_DLP_ACTIONS,
  policyEntryExplanation,
  policyEntryKind,
  policyEntryReason,
  POLICY_DEFAULT_BEC_REASON,
  policyLaneOf,
  policyMappingRuleId,
  recommendationOnlyOf,
  policyOutcomeFactsSchema,
  POST_DELIVERY_ACTION_MAP,
  POST_DELIVERY_EFFECTS,
  postDeliveryEntries,
  postDeliveryStatusOf,
  threatVerdictOf,
  type PolicyOutcomeFacts,
} from './policy-outcome';
import {
  API_COPY_DIRECTIONS,
  API_COPY_POLICY_STATES,
  POLICY_EVALUATION_MODES,
  REMEDIATION_ACTION_STRENGTH_ORDER,
  remediationActionStrength,
} from './vocabulary';

const RULE_REF = '0190f0f0-0000-7000-8000-0000000000a1#3/block-sender';

function outcome(overrides: Partial<PolicyOutcomeFacts> = {}): PolicyOutcomeFacts {
  return {
    disposition: 'allow',
    tagged: false,
    overrideApplied: false,
    decisionSource: 'platform_default',
    decisiveRuleRef: null,
    floorReasons: [],
    dlpAction: null,
    actionTypes: ['ALLOW'],
    ...overrides,
  };
}

function input(overrides: {
  copy?: Partial<RemediationInput['copy']>;
  risk?: RemediationInput['risk'];
  policyOutcome?: PolicyOutcomeFacts | null;
  context?: Partial<RemediationInput['context']>;
}): RemediationInput {
  return {
    copy: {
      status: 'scanned',
      verdict: 'clean',
      riskScore: 120,
      verdictAuthority: 'copy',
      ...overrides.copy,
    },
    risk: overrides.risk === undefined ? { level: 'none', hardBlocks: [] } : overrides.risk,
    policyOutcome: overrides.policyOutcome === undefined ? null : overrides.policyOutcome,
    context: {
      provider: 'microsoft_365',
      grantActive: true,
      remediationPaused: false,
      domainEffectiveMode: 'api',
      mailboxStatus: 'active',
      ...overrides.context,
    },
  };
}

const OFF = { hardDeleteEnabled: false };
const P1 = DEFAULT_REMEDIATION_POLICY;
const MALWARE_HB = {
  copy: { verdict: 'malware' as const, riskScore: 950 },
  risk: { level: 'critical' as const, hardBlocks: ['hb.malware_attachment'] },
};
const SUSPICIOUS_LEVEL_ONLY = {
  copy: { verdict: 'suspicious' as const, riskScore: 520 },
  risk: { level: 'medium' as const, hardBlocks: [] },
};
const policyWith = (
  mapping: Record<string, string> | undefined,
  mode: RemediationPolicy['mode'] = 'enforce',
): RemediationPolicy => ({
  mode,
  document: {
    ...structuredClone(P1.document),
    ...(mapping === undefined ? {} : { policyMapping: mapping }),
  },
});

describe('API-4 vocabularies', () => {
  it('pins the policy-lane lists (mirrors of policy-dsl and the WP1 enums)', () => {
    expect(POLICY_OUTCOME_DISPOSITIONS).toEqual([
      'allow',
      'require_approval',
      'quarantine',
      'reject',
    ]);
    expect(POLICY_OUTCOME_DECISION_SOURCES).toEqual(['tenant_rule', 'platform_default', 'floor']);
    expect(POLICY_OUTCOME_ACTION_TYPES).toEqual([
      'ALLOW',
      'REJECT',
      'QUARANTINE',
      'TAG',
      'WARN',
      'REQUIRE_APPROVAL',
      'URL_REWRITE',
      'ARCHIVE',
      'ALERT',
    ]);
    expect(POLICY_OUTCOME_DLP_ACTIONS).toEqual([
      'allow',
      'alert',
      'require_approval',
      'quarantine',
      'block',
    ]);
    expect(POLICY_MAPPING_KEYS).toEqual([
      'quarantine',
      'require_approval',
      'reject',
      'allow_tagged',
    ]);
    expect(API_COPY_DIRECTIONS).toEqual(['inbound', 'internal', 'outbound']);
    expect(API_COPY_POLICY_STATES).toEqual([
      'none',
      'evaluated',
      'inline',
      'disabled',
      'failed',
      'not_applicable',
    ]);
    expect(POLICY_EVALUATION_MODES).toEqual(['inline', 'detect']);
    expect(API_MODE_SCOPE_KINDS).toEqual(['all', 'departments', 'mailboxes']);
    expect(API_MAILBOX_SCOPE_STATES).toEqual(['in_scope', 'excluded']);
    expect(DETECT_ONLY_THEN_VALUES).toEqual(['remind', 'enforce']);
  });

  it('shares one strength order with the clawback (none < tag < … < hard_delete)', () => {
    expect(CLAWBACK_STRENGTH_ORDER).toBe(REMEDIATION_ACTION_STRENGTH_ORDER);
    expect(remediationActionStrength('none')).toBe(-1);
    expect(REMEDIATION_ACTION_STRENGTH_ORDER.map(remediationActionStrength)).toEqual([
      0, 1, 2, 3, 4,
    ]);
    expect(REMEDIATION_ACTION_STRENGTH_ORDER.map(actionStrength)).toEqual([0, 1, 2, 3, 4]);
  });
});

describe('policyMapping (A4.2)', () => {
  it('is optional: stored documents and presets stay valid and get the defaults', () => {
    for (const preset of Object.values(REMEDIATION_PRESETS)) {
      expect(preset.document.policyMapping).toBeUndefined();
      expect(parseRemediationPolicy(preset.document).ok).toBe(true);
    }
    expect(effectivePolicyMapping(undefined)).toEqual({
      quarantine: 'move_quarantine',
      require_approval: 'move_quarantine',
      reject: 'move_quarantine',
      allow_tagged: 'tag',
    });
    expect(DEFAULT_POLICY_MAPPING).toEqual(effectivePolicyMapping({}));
    expect(Object.isFrozen(DEFAULT_POLICY_MAPPING)).toBe(true);
    expect(effectivePolicyMapping({ reject: 'soft_delete', allow_tagged: 'none' })).toEqual({
      quarantine: 'move_quarantine',
      require_approval: 'move_quarantine',
      reject: 'soft_delete',
      allow_tagged: 'none',
    });
  });

  it('accepts every allowed value and is strict', () => {
    for (const action of ['move_quarantine', 'move_junk', 'soft_delete', 'tag', 'none']) {
      const parsed = parseRemediationPolicy({
        ...P1.document,
        policyMapping: { quarantine: action, require_approval: action, reject: action },
      });
      expect(parsed.ok).toBe(true);
    }
    expect(parseRemediationPolicy({ ...P1.document, policyMapping: { other: 'tag' } }).ok).toBe(
      false,
    );
  });

  it.each([
    [{ quarantine: 'hard_delete' }],
    [{ reject: 'hard_delete' }],
    [{ require_approval: 'hard_delete' }],
    [{ allow_tagged: 'move_quarantine' }],
    [{ allow_tagged: 'hard_delete' }],
  ])('refuses %j (never hard delete; tagged allow only tag/none)', (mapping) => {
    expect(parseRemediationPolicy({ ...P1.document, policyMapping: mapping }).ok).toBe(false);
  });

  it('refuses when.policyDispositions with use_policy_mapping', () => {
    const parsed = parseRemediationPolicy({
      v: 1,
      rules: [
        { id: 'r', when: { verdicts: ['spam'], policyDispositions: ['reject'] }, action: 'tag' },
      ],
    });
    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(USE_POLICY_MAPPING).toBe('use_policy_mapping');
    const issue = parsed.issues.find((i) => i.path.join('.') === 'rules.0.when.policyDispositions');
    expect(issue?.message).toBe('use_policy_mapping');
  });
});

describe('recommendationOnlyOf (A4.3 step 3, review fix)', () => {
  const base = {
    disposition: 'quarantine' as const,
    decisionSource: 'platform_default' as const,
    decisiveReason: 'policy.default.risk_quarantine',
    floorDisposition: null,
    tagOrigins: [] as const,
  };

  it.each([
    ['platform default restating the risk recommendation', base, true],
    ['tenant rule', { ...base, decisionSource: 'tenant_rule' as const }, false],
    ['raised floor', { ...base, decisionSource: 'floor' as const }, false],
    [
      'floor binding at the same level (DLP, hard block)',
      { ...base, floorDisposition: 'quarantine' as const },
      false,
    ],
    [
      'floor binding below the disposition',
      { ...base, floorDisposition: 'require_approval' as const },
      true,
    ],
    ['deterministic BEC hold (D2)', { ...base, decisiveReason: POLICY_DEFAULT_BEC_REASON }, false],
    ['untagged allow', { ...base, disposition: 'allow' as const }, false],
    [
      'allow with only the platform risk tag',
      { ...base, disposition: 'allow' as const, tagOrigins: ['platform_default' as const] },
      true,
    ],
    [
      'allow with a tenant TAG',
      {
        ...base,
        disposition: 'allow' as const,
        tagOrigins: ['platform_default' as const, 'tenant_rule' as const],
      },
      false,
    ],
    [
      'allow with the floor dlp-alert TAG',
      { ...base, disposition: 'allow' as const, tagOrigins: ['floor' as const] },
      false,
    ],
  ])('%s', (_name, args, expected) => {
    expect(recommendationOnlyOf(args)).toBe(expected);
  });

  it('policyLaneOf ignores a recommendation-only outcome; absent reads as false', () => {
    const mapping = effectivePolicyMapping(undefined);
    expect(
      policyLaneOf(outcome({ disposition: 'reject', recommendationOnly: true }), mapping),
    ).toBeNull();
    expect(policyLaneOf(outcome({ disposition: 'reject' }), mapping)).toEqual({
      key: 'reject',
      action: 'move_quarantine',
    });
    expect(
      policyOutcomeFactsSchema.parse(outcome({ recommendationOnly: true })).recommendationOnly,
    ).toBe(true);
    expect(policyOutcomeFactsSchema.parse(outcome()).recommendationOnly).toBeUndefined();
  });
});

describe('PolicyOutcomeFacts (A4.1)', () => {
  it('validates the shape strictly', () => {
    const full = outcome({
      disposition: 'reject',
      decisionSource: 'tenant_rule',
      decisiveRuleRef: RULE_REF,
      floorReasons: ['policy.floor.dlp_block'],
      dlpAction: 'block',
      actionTypes: ['REJECT', 'ALERT'],
    });
    expect(policyOutcomeFactsSchema.parse(full)).toEqual(full);
    expect(policyOutcomeFactsSchema.safeParse({ ...full, extra: 1 }).success).toBe(false);
    expect(policyOutcomeFactsSchema.safeParse({ ...full, decisiveRuleRef: 'x' }).success).toBe(
      false,
    );
    expect(
      policyOutcomeFactsSchema.safeParse({
        ...full,
        floorReasons: Array.from({ length: 9 }, (_, i) => `policy.floor.r${i}`),
      }).success,
    ).toBe(false);
    expect(
      policyOutcomeFactsSchema.safeParse({ ...full, actionTypes: ['TAG', 'TAG'] }).success,
    ).toBe(false);
  });
});

describe('decideRemediation: the two lanes (A4.3)', () => {
  it.each([
    // [name, input, policy, expected]
    [
      'not scanned → none even with a policy reject',
      input({ copy: { status: 'scan_failed' }, policyOutcome: outcome({ disposition: 'reject' }) }),
      P1,
      { outcome: 'none' },
    ],
    ['API-2 unchanged: clean verdict, no outcome → none', input({}), P1, { outcome: 'none' }],
    [
      'API-2 unchanged: malware hard block, no outcome → verdict rule',
      input({ ...MALWARE_HB }),
      P1,
      {
        outcome: 'act',
        action: 'move_quarantine',
        ruleId: 'p1-high-confidence-malware-phishing-hb',
        simulated: false,
        notes: [],
      },
    ],
    [
      'clean verdict + policy reject → quarantine folder (policy lane)',
      input({ policyOutcome: outcome({ disposition: 'reject', decisionSource: 'tenant_rule' }) }),
      P1,
      {
        outcome: 'act',
        action: 'move_quarantine',
        ruleId: 'policy-mapping:reject',
        simulated: false,
        notes: [],
      },
    ],
    [
      'clean verdict + policy require_approval → quarantine folder',
      input({ policyOutcome: outcome({ disposition: 'require_approval' }) }),
      P1,
      {
        outcome: 'act',
        action: 'move_quarantine',
        ruleId: 'policy-mapping:require_approval',
        simulated: false,
        notes: [],
      },
    ],
    [
      'tagged allow → tag',
      input({ policyOutcome: outcome({ tagged: true, actionTypes: ['ALLOW', 'TAG'] }) }),
      P1,
      {
        outcome: 'act',
        action: 'tag',
        ruleId: 'policy-mapping:allow_tagged',
        simulated: false,
        notes: [],
      },
    ],
    ['plain allow → none', input({ policyOutcome: outcome() }), P1, { outcome: 'none' }],
    [
      'tagged allow mapped to none → none',
      input({ policyOutcome: outcome({ tagged: true }) }),
      policyWith({ allow_tagged: 'none' }),
      { outcome: 'none' },
    ],
    [
      'malware + tenant TAG: the stronger verdict action wins',
      input({ ...MALWARE_HB, policyOutcome: outcome({ tagged: true }) }),
      P1,
      {
        outcome: 'act',
        action: 'move_quarantine',
        ruleId: 'p1-high-confidence-malware-phishing-hb',
        simulated: false,
        notes: [],
      },
    ],
    [
      'suspicious (tag) + policy quarantine: the stronger policy action wins',
      input({ ...SUSPICIOUS_LEVEL_ONLY, policyOutcome: outcome({ disposition: 'quarantine' }) }),
      P1,
      {
        outcome: 'act',
        action: 'move_quarantine',
        ruleId: 'policy-mapping:quarantine',
        simulated: false,
        notes: [],
      },
    ],
    [
      'tie (both move_quarantine) → the verdict lane',
      input({ ...MALWARE_HB, policyOutcome: outcome({ disposition: 'quarantine' }) }),
      P1,
      {
        outcome: 'act',
        action: 'move_quarantine',
        ruleId: 'p1-high-confidence-malware-phishing-hb',
        simulated: false,
        notes: [],
      },
    ],
    [
      'tie (both tag) → the verdict lane',
      input({ ...SUSPICIOUS_LEVEL_ONLY, policyOutcome: outcome({ tagged: true }) }),
      P1,
      { outcome: 'act', action: 'tag', ruleId: 'p1-suspicious', simulated: false, notes: [] },
    ],
    [
      'tenant allow override on a level-only suspicious verdict → skip policy_allow_override',
      input({
        ...SUSPICIOUS_LEVEL_ONLY,
        policyOutcome: outcome({
          overrideApplied: true,
          decisionSource: 'tenant_rule',
          decisiveRuleRef: RULE_REF,
        }),
      }),
      P1,
      {
        outcome: 'skip',
        reason: 'policy_allow_override',
        ruleId: 'p1-suspicious',
        action: 'tag',
      },
    ],
    [
      'allow override with a tagged allow → the policy tag (verdict lane suppressed)',
      input({
        ...MALWARE_HB,
        policyOutcome: outcome({
          tagged: true,
          overrideApplied: true,
          decisionSource: 'tenant_rule',
        }),
      }),
      P1,
      {
        outcome: 'act',
        action: 'tag',
        ruleId: 'policy-mapping:allow_tagged',
        simulated: false,
        notes: [],
      },
    ],
    [
      'allow override on a clean verdict → none (nothing to suppress)',
      input({ policyOutcome: outcome({ overrideApplied: true, decisionSource: 'tenant_rule' }) }),
      P1,
      { outcome: 'none' },
    ],
    [
      'hard block: the floor keeps the disposition (no override) → the verdict rule acts',
      input({
        ...MALWARE_HB,
        policyOutcome: outcome({
          disposition: 'quarantine',
          decisionSource: 'floor',
          floorReasons: ['policy.floor.hard_block'],
        }),
      }),
      P1,
      {
        outcome: 'act',
        action: 'move_quarantine',
        ruleId: 'p1-high-confidence-malware-phishing-hb',
        simulated: false,
        notes: [],
      },
    ],
    [
      'an override not decided by a tenant rule never suppresses',
      input({
        ...SUSPICIOUS_LEVEL_ONLY,
        policyOutcome: outcome({ overrideApplied: true, decisionSource: 'platform_default' }),
      }),
      P1,
      { outcome: 'act', action: 'tag', ruleId: 'p1-suspicious', simulated: false, notes: [] },
    ],
    [
      'outbound copy → skip outbound_not_remediable',
      input({
        copy: { direction: 'outbound' },
        policyOutcome: outcome({ disposition: 'reject', dlpAction: 'block' }),
      }),
      P1,
      {
        outcome: 'skip',
        reason: 'outbound_not_remediable',
        ruleId: 'policy-mapping:reject',
        action: 'move_quarantine',
      },
    ],
    [
      'outbound before inline authority and scope',
      input({
        copy: { direction: 'outbound', verdictAuthority: 'inline' },
        policyOutcome: outcome({ disposition: 'reject' }),
        context: { mailboxInScope: false },
      }),
      P1,
      {
        outcome: 'skip',
        reason: 'outbound_not_remediable',
        ruleId: 'policy-mapping:reject',
        action: 'move_quarantine',
      },
    ],
    [
      'mailbox out of scope → skip out_of_scope',
      input({ ...MALWARE_HB, context: { mailboxInScope: false } }),
      P1,
      {
        outcome: 'skip',
        reason: 'out_of_scope',
        ruleId: 'p1-high-confidence-malware-phishing-hb',
        action: 'move_quarantine',
      },
    ],
    [
      'mailboxInScope true or absent → unchanged',
      input({ ...MALWARE_HB, context: { mailboxInScope: true } }),
      P1,
      {
        outcome: 'act',
        action: 'move_quarantine',
        ruleId: 'p1-high-confidence-malware-phishing-hb',
        simulated: false,
        notes: [],
      },
    ],
    [
      'inline authority → skip inline_authority (policy lane too)',
      input({
        copy: { verdictAuthority: 'inline' },
        policyOutcome: outcome({ disposition: 'quarantine' }),
      }),
      P1,
      {
        outcome: 'skip',
        reason: 'inline_authority',
        ruleId: 'policy-mapping:quarantine',
        action: 'move_quarantine',
      },
    ],
    [
      'internal copy with internal mail off → skip internal_mail_disabled',
      input({
        copy: { direction: 'internal' },
        policyOutcome: outcome({ disposition: 'quarantine', dlpAction: 'quarantine' }),
        context: { internalMailEnabled: false },
      }),
      P1,
      {
        outcome: 'skip',
        reason: 'internal_mail_disabled',
        ruleId: 'policy-mapping:quarantine',
        action: 'move_quarantine',
      },
    ],
    [
      'detect-only → simulated policy-lane act',
      input({ policyOutcome: outcome({ disposition: 'reject' }) }),
      policyWith(undefined, 'detect_only'),
      {
        outcome: 'act',
        action: 'move_quarantine',
        ruleId: 'policy-mapping:reject',
        simulated: true,
        notes: [],
      },
    ],
    [
      'paused → skip remediation_paused',
      input({
        policyOutcome: outcome({ disposition: 'reject' }),
        context: { remediationPaused: true },
      }),
      P1,
      {
        outcome: 'skip',
        reason: 'remediation_paused',
        ruleId: 'policy-mapping:reject',
        action: 'move_quarantine',
      },
    ],
    [
      'no grant → skip no_mailbox_access',
      input({ policyOutcome: outcome({ disposition: 'reject' }), context: { grantActive: false } }),
      P1,
      {
        outcome: 'skip',
        reason: 'no_mailbox_access',
        ruleId: 'policy-mapping:reject',
        action: 'move_quarantine',
      },
    ],
    [
      'tenant mapping reject → soft_delete',
      input({ policyOutcome: outcome({ disposition: 'reject' }) }),
      policyWith({ reject: 'soft_delete' }),
      {
        outcome: 'act',
        action: 'soft_delete',
        ruleId: 'policy-mapping:reject',
        simulated: false,
        notes: [],
      },
    ],
    [
      'review fix: a platform-default quarantine restating the spam recommendation never raises STRICT spam → Junk',
      input({
        copy: { verdict: 'spam', riskScore: 600 },
        risk: { level: 'medium', hardBlocks: [] },
        policyOutcome: outcome({ disposition: 'quarantine', recommendationOnly: true }),
      }),
      REMEDIATION_PRESETS.strict,
      {
        outcome: 'act',
        action: 'move_junk',
        ruleId: 'strict-spam-junk',
        simulated: false,
        notes: [],
      },
    ],
    [
      'review fix: P1 has no spam rule, so a recommendation-only quarantine of a spam copy is none',
      input({
        copy: { verdict: 'spam', riskScore: 600 },
        risk: { level: 'medium', hardBlocks: [] },
        policyOutcome: outcome({ disposition: 'quarantine', recommendationOnly: true }),
      }),
      P1,
      { outcome: 'none' },
    ],
    [
      'review fix: the platform risk tag of a clean copy is not tagged again',
      input({
        policyOutcome: outcome({ tagged: true, actionTypes: ['TAG'], recommendationOnly: true }),
      }),
      P1,
      { outcome: 'none' },
    ],
    [
      'review fix: a tenant rule quarantine still raises STRICT spam → Junk',
      input({
        copy: { verdict: 'spam', riskScore: 600 },
        risk: { level: 'medium', hardBlocks: [] },
        policyOutcome: outcome({
          disposition: 'quarantine',
          decisionSource: 'tenant_rule',
          decisiveRuleRef: RULE_REF,
          recommendationOnly: false,
        }),
      }),
      REMEDIATION_PRESETS.strict,
      {
        outcome: 'act',
        action: 'move_quarantine',
        ruleId: 'policy-mapping:quarantine',
        simulated: false,
        notes: [],
      },
    ],
    [
      'tenant mapping quarantine → none: the verdict lane alone decides',
      input({ ...SUSPICIOUS_LEVEL_ONLY, policyOutcome: outcome({ disposition: 'quarantine' }) }),
      policyWith({ quarantine: 'none' }),
      { outcome: 'act', action: 'tag', ruleId: 'p1-suspicious', simulated: false, notes: [] },
    ],
  ] as const)('%s', (_name, given, policy, expected) => {
    expect(decideRemediation(given, policy, OFF)).toEqual(expected);
  });

  it('records lanes for the decision record', () => {
    expect(
      remediationLanes(
        input({
          ...SUSPICIOUS_LEVEL_ONLY,
          policyOutcome: outcome({ overrideApplied: true, decisionSource: 'tenant_rule' }),
        }),
        P1.document,
      ),
    ).toEqual({
      verdict: { ruleId: 'p1-suspicious', action: 'tag' },
      policy: null,
      winner: null,
      suppressedBy: 'policy_allow_override',
    });
    expect(policyMappingRuleId('allow_tagged')).toBe('policy-mapping:allow_tagged');
  });
});

describe('decision record v2 (A4.4) and the v1/v2 reader union', () => {
  const effective = resolveEffectivePolicy({ organization: null, domains: [] }, null);

  it('writes /2 with the policy outcome, lanes and post-delivery list', () => {
    const facts = outcome({
      disposition: 'reject',
      decisionSource: 'tenant_rule',
      decisiveRuleRef: RULE_REF,
      actionTypes: ['REJECT', 'TAG', 'ALERT'],
    });
    const given = input({ policyOutcome: facts });
    const decision = decideRemediation(given, effective.policy, OFF);
    const record = buildDecisionRecord(effective, given, decision);
    expect(record).toMatchObject({
      v: 2,
      ruleId: 'policy-mapping:reject',
      policyOutcome: facts,
      lanes: {
        verdict: null,
        policy: { key: 'reject', action: 'move_quarantine' },
        winner: 'policy',
        suppressedBy: null,
      },
      postDelivery: [
        { type: 'REJECT', status: 'requested', reason: 'mapped_to_mailbox_action' },
        { type: 'TAG', status: 'requested', reason: 'mapped_to_mailbox_action' },
        { type: 'ALERT', status: 'requested', reason: null },
        { type: 'SENDER_NOTICE', status: 'not_applicable', reason: 'post_delivery_no_bounce' },
        { type: 'HEADER_EDIT', status: 'not_applicable', reason: 'post_delivery_no_header_edit' },
      ],
    });
    expect(remediationDecisionRecordSchema.parse(record)).toEqual(record);
    // A not-scanned copy records no lanes.
    const failed = input({ copy: { status: 'scan_failed' }, policyOutcome: facts });
    expect(buildDecisionRecord(effective, failed, { outcome: 'none' }).lanes).toEqual({
      verdict: null,
      policy: null,
      winner: null,
      suppressedBy: null,
    });
  });

  it('records the suppressed verdict lane of an allow override', () => {
    const given = input({
      ...SUSPICIOUS_LEVEL_ONLY,
      policyOutcome: outcome({ overrideApplied: true, decisionSource: 'tenant_rule' }),
    });
    const record = buildDecisionRecord(
      effective,
      given,
      decideRemediation(given, effective.policy, OFF),
    );
    expect(record.ruleId).toBe('p1-suspicious');
    expect(record.lanes.suppressedBy).toBe('policy_allow_override');
    expect(record.postDelivery).toEqual([
      { type: 'ALLOW', status: 'recorded', reason: 'already_delivered' },
    ]);
  });

  it('outbound records every non-ALERT effect as outbound_already_sent', () => {
    const given = input({
      copy: { direction: 'outbound' },
      policyOutcome: outcome({ disposition: 'reject', actionTypes: ['REJECT', 'ALERT'] }),
    });
    const record = buildDecisionRecord(
      effective,
      given,
      decideRemediation(given, effective.policy, OFF),
    );
    expect(record.postDelivery).toEqual([
      { type: 'REJECT', status: 'not_applicable', reason: 'outbound_already_sent' },
      { type: 'ALERT', status: 'requested', reason: null },
      { type: 'SENDER_NOTICE', status: 'not_applicable', reason: 'outbound_already_sent' },
    ]);
  });

  it('the union still reads /1 records and refuses unknown versions', () => {
    const v1 = {
      v: 1,
      policy: {
        scope: 'platform_default',
        publicId: null,
        rowVersion: null,
        sha256: 'a'.repeat(64),
      },
      mode: 'enforce',
      ruleId: 'p1-suspicious',
      inputs: {
        verdict: 'suspicious',
        riskScore: 500,
        level: 'medium',
        hardBlocks: [],
        verdictAuthority: 'copy',
      },
      policyOutcome: null,
      notes: [],
    };
    expect(remediationDecisionRecordV1Schema.parse(v1)).toEqual(v1);
    expect(remediationDecisionRecordSchema.parse(v1)).toEqual(v1);
    expect(remediationDecisionRecordSchema.safeParse({ ...v1, lanes: null }).success).toBe(false);
    expect(remediationDecisionRecordSchema.safeParse({ ...v1, v: 3 }).success).toBe(false);
    expect(
      remediationDecisionRecordSchema.safeParse({ ...v1, policyOutcome: outcome() }).success,
    ).toBe(false);
  });
});

describe('POST_DELIVERY_ACTION_MAP (A5)', () => {
  it('pins the table', () => {
    expect(POST_DELIVERY_EFFECTS).toEqual([
      ...POLICY_OUTCOME_ACTION_TYPES,
      'SENDER_NOTICE',
      'HEADER_EDIT',
      'ENCRYPT',
      'REDIRECT',
    ]);
    expect(POST_DELIVERY_ACTION_MAP).toEqual({
      ALLOW: { status: 'recorded', reason: 'already_delivered' },
      QUARANTINE: { status: 'requested', reason: 'mapped_to_mailbox_action' },
      REQUIRE_APPROVAL: { status: 'requested', reason: 'mapped_to_mailbox_action' },
      REJECT: { status: 'requested', reason: 'mapped_to_mailbox_action' },
      SENDER_NOTICE: { status: 'not_applicable', reason: 'post_delivery_no_bounce' },
      TAG: { status: 'requested', reason: 'mapped_to_mailbox_action' },
      WARN: { status: 'requested', reason: 'mapped_to_mailbox_action' },
      HEADER_EDIT: { status: 'not_applicable', reason: 'post_delivery_no_header_edit' },
      URL_REWRITE: { status: 'not_applicable', reason: 'post_delivery_no_rewrite' },
      ARCHIVE: { status: 'not_applicable', reason: 'archive_follows_journaling' },
      ALERT: { status: 'requested', reason: null },
      ENCRYPT: { status: 'not_applicable', reason: 'post_delivery_no_encrypt' },
      REDIRECT: { status: 'not_applicable', reason: 'post_delivery_no_redirect' },
    });
    expect(Object.isFrozen(POST_DELIVERY_ACTION_MAP)).toBe(true);
  });

  it.each(POST_DELIVERY_EFFECTS.map((e) => [e]))('%s: inbound/internal as the table', (effect) => {
    expect(postDeliveryStatusOf(effect, 'inbound')).toEqual(POST_DELIVERY_ACTION_MAP[effect]);
    expect(postDeliveryStatusOf(effect, 'internal')).toEqual(POST_DELIVERY_ACTION_MAP[effect]);
    expect(postDeliveryStatusOf(effect, 'outbound')).toEqual(
      effect === 'ALERT'
        ? { status: 'requested', reason: null }
        : { status: 'not_applicable', reason: 'outbound_already_sent' },
    );
  });

  it('lists derived effects and caps at nine', () => {
    expect(postDeliveryEntries(['WARN'], 'inbound').map((e) => e.type)).toEqual([
      'WARN',
      'HEADER_EDIT',
    ]);
    expect(
      postDeliveryEntries([...POLICY_OUTCOME_ACTION_TYPES], 'inbound').length,
    ).toBeLessThanOrEqual(9);
  });
});

describe('policy-lane mailbox entries (A5, R9.1 extension)', () => {
  it('require_approval creates a review entry, everything else a quarantine entry', () => {
    expect(policyEntryKind('require_approval')).toBe('review');
    for (const key of ['quarantine', 'reject', 'allow_tagged'] as const) {
      expect(policyEntryKind(key)).toBe('quarantine');
    }
    expect(policyEntryKind(null)).toBe('quarantine');
  });

  it('reason: verdict mapping on the same action, dlp floor, else policy', () => {
    const base = {
      verdictReason: 'malware' as const,
      policyLaneAction: 'move_quarantine' as const,
    };
    expect(
      policyEntryReason({
        ...base,
        verdictLaneAction: 'move_quarantine',
        outcome: outcome({ disposition: 'quarantine' }),
      }),
    ).toBe('malware');
    expect(
      policyEntryReason({
        ...base,
        verdictLaneAction: null,
        outcome: outcome({
          disposition: 'reject',
          decisionSource: 'floor',
          floorReasons: ['policy.floor.dlp_block'],
        }),
      }),
    ).toBe('dlp');
    expect(
      policyEntryReason({
        ...base,
        verdictLaneAction: 'tag',
        outcome: outcome({ disposition: 'reject', decisionSource: 'tenant_rule' }),
      }),
    ).toBe('policy');
    expect(policyEntryExplanation(RULE_REF)).toBe(
      `Removed from the mailbox by the tenant policy (API mode; rule ${RULE_REF})`,
    );
    expect(policyEntryExplanation(null)).toContain('rule platform default');
  });
});

describe('copyDetectionOf (A8.1)', () => {
  it.each([
    ['clean, no policy', 'clean', null, null, false, null, null],
    ['unknown verdict', 'unknown', null, null, false, null, null],
    ['spam', 'spam', null, null, true, 'spam', null],
    ['bulk', 'bulk', null, null, true, 'spam', null],
    ['suspicious', 'suspicious', null, null, true, 'suspicious', null],
    ['phishing', 'phishing', null, null, true, 'malicious', null],
    ['malware', 'malware', null, null, true, 'malicious', null],
    ['bec', 'bec', null, null, true, 'malicious', null],
    ['dlp_violation verdict alone is not a threat', 'dlp_violation', null, null, false, null, null],
    ['dlp allow', 'clean', null, 'allow', false, null, null],
    ['dlp alert', 'clean', null, 'alert', true, null, 'alert'],
    ['dlp block', 'clean', null, 'block', true, null, 'block'],
    ['policy reject', 'clean', outcome({ disposition: 'reject' }), null, true, null, null],
    ['policy tagged', 'clean', outcome({ tagged: true }), null, true, null, null],
    ['policy plain allow', 'clean', outcome(), null, false, null, null],
  ] as const)('%s', (_n, verdict, policyOutcome, dlpAction, isDetection, threat, dlp) => {
    expect(copyDetectionOf({ verdict, policyOutcome, dlpAction })).toEqual({
      isDetection,
      threatVerdict: threat,
      dlpAction: dlp,
    });
  });

  it('defaults the DLP action to the policy outcome', () => {
    expect(
      copyDetectionOf({ verdict: 'clean', policyOutcome: outcome({ dlpAction: 'quarantine' }) }),
    ).toEqual({ isDetection: true, threatVerdict: null, dlpAction: 'quarantine' });
    expect(threatVerdictOf(null)).toBeNull();
  });
});

describe('api-mode-scope/1 (B6)', () => {
  const uuid = (n: number) => `0190f0f0-0000-7000-8000-${n.toString().padStart(12, '0')}`;

  it('accepts the three kinds strictly', () => {
    expect(apiModeScopeSchema.parse({ kind: 'all' })).toEqual({ kind: 'all' });
    expect(apiModeScopeSchema.parse({ kind: 'mailboxes' })).toEqual({ kind: 'mailboxes' });
    expect(apiModeScopeSchema.parse({ kind: 'departments', departmentIds: [uuid(1)] })).toEqual({
      kind: 'departments',
      departmentIds: [uuid(1)],
    });
    expect(DEFAULT_API_MODE_SCOPE).toEqual({ kind: 'all' });
  });

  it.each([
    [{ kind: 'all', departmentIds: [] }],
    [{ kind: 'departments', departmentIds: [] }],
    [{ kind: 'departments' }],
    [{ kind: 'departments', departmentIds: ['not-a-uuid'] }],
    [{ kind: 'departments', departmentIds: [uuid(1), uuid(1)] }],
    [
      {
        kind: 'departments',
        departmentIds: Array.from({ length: API_MODE_SCOPE_MAX_DEPARTMENTS + 1 }, (_, i) =>
          uuid(i),
        ),
      },
    ],
    [{ kind: 'groups' }],
  ])('refuses %j', (value) => {
    expect(apiModeScopeSchema.safeParse(value).success).toBe(false);
  });

  it('bounds the selected mailboxes', () => {
    expect(API_MODE_SCOPE_MAX_MAILBOXES).toBe(5000);
    expect(apiModeScopeMailboxIdsSchema.safeParse([uuid(1)]).success).toBe(true);
    expect(apiModeScopeMailboxIdsSchema.safeParse([]).success).toBe(false);
    expect(
      apiModeScopeMailboxIdsSchema.safeParse(
        Array.from({ length: API_MODE_SCOPE_MAX_MAILBOXES + 1 }, (_, i) => uuid(i)),
      ).success,
    ).toBe(false);
  });

  it.each([
    ['all', false, 'excluded', true],
    ['all', true, 'in_scope', true],
    ['mailboxes', true, 'excluded', true],
    ['mailboxes', false, 'in_scope', false],
    ['departments', false, 'in_scope', true],
    ['departments', true, 'excluded', false],
  ] as const)('mailboxInScope(%s, selected %s, state %s) = %s', (kind, sel, state, expected) => {
    expect(mailboxInScope(kind, { scopeSelected: sel, scopeState: state })).toBe(expected);
  });

  it('new mailboxes: excluded for mailboxes scopes, protected otherwise', () => {
    expect(initialScopeState('mailboxes')).toBe('excluded');
    expect(initialScopeState('departments')).toBe('in_scope');
    expect(initialScopeState('all')).toBe('in_scope');
  });
});

describe('detect-only start period (B7)', () => {
  const NOW = new Date('2026-11-27T10:00:00.000Z');
  const at = (ms: number) => new Date(NOW.getTime() + ms).toISOString();
  const HOUR = 3_600_000;
  const DAY = 24 * HOUR;

  it('schema is strict', () => {
    expect(detectOnlySchema.safeParse({ until: at(DAY), then: 'remind' }).success).toBe(true);
    expect(detectOnlySchema.safeParse({ until: at(DAY), then: 'later' }).success).toBe(false);
    expect(detectOnlySchema.safeParse({ until: 'tomorrow', then: 'remind' }).success).toBe(false);
    expect(detectOnlySchema.safeParse({ until: at(DAY), then: 'remind', extra: 1 }).success).toBe(
      false,
    );
  });

  it.each([
    ['null always accepted', null, 'enforce', { ok: true, period: null }],
    ['absent always accepted', undefined, 'detect_only', { ok: true, period: null }],
    [
      'exactly now + 1 h',
      { until: at(HOUR), then: 'remind' },
      'detect_only',
      { ok: true, period: { until: new Date(at(HOUR)), then: 'remind' } },
    ],
    [
      'exactly now + 30 d',
      { until: at(30 * DAY), then: 'enforce' },
      'detect_only',
      { ok: true, period: { until: new Date(at(30 * DAY)), then: 'enforce' } },
    ],
    [
      'below 1 h',
      { until: at(HOUR - 1), then: 'remind' },
      'detect_only',
      { ok: false, code: 'api_mode_detect_only_invalid', reason: 'until_too_soon' },
    ],
    [
      'in the past',
      { until: at(-DAY), then: 'remind' },
      'detect_only',
      { ok: false, code: 'api_mode_detect_only_invalid', reason: 'until_too_soon' },
    ],
    [
      'beyond 30 d',
      { until: at(30 * DAY + 1), then: 'remind' },
      'detect_only',
      { ok: false, code: 'api_mode_detect_only_invalid', reason: 'until_too_late' },
    ],
    [
      'with mode enforce',
      { until: at(DAY), then: 'remind' },
      'enforce',
      { ok: false, code: 'api_mode_detect_only_invalid', reason: 'mode_not_detect_only' },
    ],
  ] as const)('%s', (_n, value, mode, expected) => {
    expect(validateDetectOnly(value, mode, NOW)).toEqual(expected);
  });

  it('defaults to 7 days then remind', () => {
    expect(API_MODE_DETECT_ONLY_DEFAULT_DAYS).toBe(7);
    expect(defaultDetectOnly(NOW)).toEqual({ until: new Date(at(7 * DAY)), then: 'remind' });
  });

  it.each([
    ['ended, remind', 'detect_only', -1, 'remind', null, { then: 'remind', severity: 'low' }],
    [
      'ended now, enforce',
      'detect_only',
      0,
      'enforce',
      null,
      { then: 'enforce', severity: 'medium' },
    ],
    ['not ended', 'detect_only', 1, 'remind', null, null],
    ['already notified', 'detect_only', -1, 'remind', new Date(0), null],
    ['enforce policy', 'enforce', -1, 'remind', null, null],
    ['no period', 'detect_only', null, null, null, null],
  ] as const)('detectOnlyDue: %s', (_n, mode, offset, then, notified, expected) => {
    expect(
      detectOnlyDue(
        {
          mode,
          detectOnlyUntil: offset === null ? null : new Date(NOW.getTime() + offset),
          detectOnlyThen: then,
          detectOnlyNotifiedAt: notified,
        },
        NOW,
      ),
    ).toEqual(expected);
  });
});

describe('policy.errors_1h health check (A11)', () => {
  it.each([
    [0, 0, 'pass'],
    [5, 4, 'pass'], // 9 attempts: not rated
    [9, 1, 'warn'], // 10 % > 5 %
    [19, 1, 'pass'], // exactly 5 %
    [94, 6, 'warn'],
    [5, 5, 'warn'], // exactly 50 %: not above the fail threshold
    [4, 6, 'fail'], // 60 %
    [0, 10, 'fail'],
  ])('evaluations %i, errors %i → %s', (evaluations1h, errors1h, status) => {
    expect(evaluatePolicyHealth({ evaluations1h, errors1h }).status).toBe(status);
  });

  it('is appended last only with the policy block', () => {
    const base = {
      connection: { active: true, bound: true },
      journal: { verifiedSource: true, sourceHealth: 'healthy' as const },
      grantStatus: 'active' as const,
      feeds: { enabled: false, feedMailboxes: 0, activeMailboxes: 0, errorMailboxes: 0 },
      coverage: { inventoryOk: false, inScopeMailboxes: 0, covered: 0, gap: 0 },
      lagP95SecondsLastHour: null,
      throttleEventsLastHour: 0,
      apiModeDomainsWithGatewayMx: 0,
    };
    const cfg = {
      coverageWarnPercent: 95,
      coverageFailPercent: 50,
      lagWarnSeconds: 900,
      lagFailSeconds: 3600,
      throttleWarnPerHour: 20,
    };
    expect(evaluateApiModeHealth(base, cfg).checks.map((c) => c.code)).not.toContain(
      'policy.errors_1h',
    );
    const failing = evaluateApiModeHealth(
      { ...base, policy: { evaluations1h: 2, errors1h: 18 } },
      cfg,
    );
    expect(failing.checks.at(-1)).toMatchObject({ code: 'policy.errors_1h', status: 'fail' });
    expect(failing.status).toBe('failing');
    expect(failing.failingChecks).toEqual(['policy.errors_1h']);
    expect(failing.checks.at(-1)?.evidence).toBe(
      '90% of 20 policy evaluations failed in the last hour (18 failed)',
    );
  });
});
