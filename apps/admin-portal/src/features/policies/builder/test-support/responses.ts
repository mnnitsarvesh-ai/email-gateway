import type { PolicyTestResponse } from '../facts';

/** A realistic `POST /policies/test` answer for the result view (synthetic ids; test-only). */
export const EDITED_POLICY = '01933c3a-1b2c-7d4e-8f00-0000000c0001';
export const OTHER_POLICY = '01933c3a-1b2c-7d4e-8f00-0000000c0002';
const RULE_REF = `${EDITED_POLICY}#3/quarantine-confidential`;

export const TEST_RESPONSE: PolicyTestResponse = {
  invalidVersions: [
    {
      policyId: OTHER_POLICY,
      versionNo: 1,
      violations: [
        { path: 'rules[0].when.field', code: 'unknown_field', message: 'Unknown field' },
      ],
    },
  ],
  lifecycleDisposition: 'quarantine',
  recipientDecisions: [
    {
      rcptSeq: 0,
      disposition: 'quarantine',
      source: 'tenant_rule',
      decisiveRuleRef: RULE_REF,
      reasonCodes: ['policy.decision.tenant_rule'],
    },
    {
      rcptSeq: 1,
      disposition: 'allow',
      source: 'platform_default',
      decisiveRuleRef: null,
      reasonCodes: ['policy.default.risk_deliver'],
    },
  ],
  recipientSplit: true,
  result: {
    status: 'evaluated',
    disposition: 'quarantine',
    finalVerdict: 'dlp_violation',
    riskScore: 120,
    decisive: {
      source: 'tenant_rule',
      policyPublicId: EDITED_POLICY,
      versionNo: 3,
      ruleId: 'quarantine-confidential',
      reason: 'policy.decision.tenant_rule',
    },
    actions: [
      {
        type: 'QUARANTINE',
        origin: 'tenant_rule',
        applicability: 'applies',
        ruleRefs: [RULE_REF],
        params: {},
      },
      {
        type: 'ALERT',
        origin: 'tenant_rule',
        applicability: 'applies',
        ruleRefs: [RULE_REF],
        params: { severity: 'warning' },
      },
      {
        type: 'TAG',
        origin: 'floor',
        applicability: 'not_applicable',
        ruleRefs: [],
        params: { label: 'dlp-alert' },
      },
    ],
    clamps: [],
    delivery: null,
    explanation: {
      lines: [{ code: 'decisive_rule', params: { ref: RULE_REF, disposition: 'quarantine' } }],
      text: `Decision: quarantine.\nDecided by rule ${RULE_REF}.`,
    },
    floor: { disposition: 'allow', reasons: ['policy.floor.dlp_alert'], tag: true },
    inputSha256: 'b'.repeat(64),
    matchedRules: [
      {
        ref: RULE_REF,
        policyPublicId: EDITED_POLICY,
        versionNo: 3,
        ruleId: 'quarantine-confidential',
        disposition: 'quarantine',
        override: false,
        actionTypes: ['QUARANTINE', 'ALERT'],
      },
    ],
    notices: { senderNonDelivery: false },
    override: null,
    reasonCodes: ['policy.decision.tenant_rule', 'policy.floor.dlp_alert'],
    recommendation: {
      disposition: 'allow',
      levelOnly: true,
      revisions: [0],
      riskAction: 'deliver',
      tag: false,
    },
    round: { direction: 'outbound', lifecycleRound: 0, scanId: null, trigger: 'scanned' },
    trace: [
      {
        ref: RULE_REF,
        result: 'matched',
        at: 'when',
        path: 'rules[0].when.all[0]',
        field: 'dlp.categories',
        op: 'contains_any',
      },
      {
        ref: `${OTHER_POLICY}#1/other-rule`,
        result: 'not_matched',
        at: 'when',
        path: 'rules[0].when',
        field: 'auth.spf',
        op: 'equals',
      },
      {
        ref: `${OTHER_POLICY}#1/later`,
        result: 'not_evaluated',
        at: null,
        path: null,
        field: null,
        op: null,
      },
    ],
    traceTruncated: false,
    versions: {
      dsl: 'policy-dsl/1',
      evaluator: 'policy-eval/2',
      input: 'policy-input/1',
      generation: '42',
      platformDefault: 'pol-default/1',
      policies: [{ policyPublicId: EDITED_POLICY, versionNo: 3, definitionSha256: 'c'.repeat(64) }],
      snapshotSha256: 'd'.repeat(64),
      tzdata: '2025b',
    },
  },
};
