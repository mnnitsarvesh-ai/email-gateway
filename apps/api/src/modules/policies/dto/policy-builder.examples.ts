import { canonicalJson, sha256Hex } from '@email-gateway/policy-dsl';

/**
 * Explicit OpenAPI examples of the step 7.3 policy builder routes (§4.2, §4.3,
 * docs/plan/steps/22-policy-builder.md). Illustrative values only (documentation, never served);
 * every id is a placeholder; `definitionSha256` is the real hash of the example definition.
 */

const FINANCE_DEPARTMENT = '0193a1b2-7c3d-7e4f-8a5b-00000000d001';
const POLICY_ID = '0193a1b2-7c3d-7e4f-8a5b-00000000a001';
const OTHER_POLICY_ID = '0193a1b2-7c3d-7e4f-8a5b-00000000a002';

/** The brief's example: hold confidential data leaving the organization, alert administrators. */
const definition = {
  dslVersion: 'policy-dsl/1',
  direction: 'outbound',
  priority: 100,
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
            op: 'domain_in',
            value: ['partner.example'],
            quantifier: 'any',
          },
        ],
      },
      unless: [{ field: 'sender.department', op: 'in', value: [FINANCE_DEPARTMENT] }],
      actions: [{ type: 'QUARANTINE' }, { type: 'ALERT', severity: 'warning' }],
    },
  ],
};

const invalidDefinition = {
  ...definition,
  rules: [
    {
      ...definition.rules[0]!,
      when: { field: 'attachment.filename', op: 'regex', value: ['(a+)+\\1'], quantifier: 'any' },
    },
  ],
};

const stored = (
  disposition: string,
  source: string,
  policyId: string | null,
  versionNo: number | null,
  ruleId: string | null,
  evaluatedAt: string,
) => ({ disposition, source, policyId, versionNo, ruleId, evaluatedAt });

export const POLICY_BUILDER_EXAMPLES = {
  validateBody: { definition },
  validateInvalidBody: { definition: invalidDefinition },
  validated: {
    dslVersion: 'policy-dsl/1',
    valid: true,
    violations: [],
    referenceViolations: [
      {
        path: 'rules[0].unless[0].value[0]',
        code: 'department_unknown',
        message: 'Unknown department of the organization',
      },
    ],
    ruleCount: 1,
    hasOverrideRules: false,
    references: { departmentIds: [FINANCE_DEPARTMENT], userIds: [] },
    definitionSha256: sha256Hex(canonicalJson(definition)),
  },
  sampleBody: { target: 'active', sample: { limit: 25 } },
  sampleVersionBody: {
    target: { policyId: POLICY_ID, versionNo: 3 },
    sample: {
      from: '2026-11-09T00:00:00.000Z',
      to: '2026-11-16T00:00:00.000Z',
      direction: 'outbound',
      limit: 50,
    },
  },
  sample: {
    target: { kind: 'version', policyId: POLICY_ID, versionNo: 3 },
    window: { from: '2026-11-09T00:00:00.000Z', to: '2026-11-16T00:00:00.000Z' },
    limit: 50,
    evaluated: 2,
    skipped: 1,
    truncated: false,
    exhausted: true,
    summary: {
      changed: 1,
      unchanged: 1,
      stored: { allow: 2, require_approval: 0, quarantine: 0, reject: 0 },
      dryRun: { allow: 1, require_approval: 0, quarantine: 1, reject: 0 },
      transitions: [{ from: 'allow', to: 'quarantine', count: 1 }],
    },
    items: [
      {
        messageId: '0193a1b2-7c3d-7e4f-8a5b-00000000e003',
        receivedAt: '2026-11-15T16:42:10.512Z',
        direction: 'outbound',
        lifecycleRound: 0,
        scanId: '901233',
        trigger: 'scanned',
        outcome: 'evaluated',
        stored: stored('allow', 'platform_default', null, null, null, '2026-11-15T16:42:14.020Z'),
        dryRun: {
          disposition: 'quarantine',
          lifecycleDisposition: 'quarantine',
          source: 'tenant_rule',
          policyId: POLICY_ID,
          versionNo: 3,
          ruleId: 'quarantine-confidential',
          matchedRuleCount: 1,
          actionTypes: ['QUARANTINE', 'ALERT'],
          recipientSplit: false,
          overrideApplied: false,
        },
        dispositionChanged: true,
        decisiveChanged: true,
      },
      {
        messageId: '0193a1b2-7c3d-7e4f-8a5b-00000000e002',
        receivedAt: '2026-11-15T09:03:51.007Z',
        direction: 'outbound',
        lifecycleRound: 1,
        scanId: '901107',
        trigger: 'scanned',
        outcome: 'evaluated',
        stored: stored(
          'allow',
          'tenant_rule',
          OTHER_POLICY_ID,
          1,
          'tag-external',
          '2026-11-15T09:03:55.311Z',
        ),
        dryRun: {
          disposition: 'allow',
          lifecycleDisposition: 'allow',
          source: 'tenant_rule',
          policyId: OTHER_POLICY_ID,
          versionNo: 1,
          ruleId: 'tag-external',
          matchedRuleCount: 1,
          actionTypes: ['ALLOW', 'TAG'],
          recipientSplit: false,
          overrideApplied: false,
        },
        dispositionChanged: false,
        decisiveChanged: false,
      },
      {
        messageId: '0193a1b2-7c3d-7e4f-8a5b-00000000e001',
        receivedAt: '2026-11-14T22:17:05.900Z',
        direction: 'outbound',
        lifecycleRound: 0,
        scanId: '900861',
        trigger: 'scan_failed',
        outcome: 'not_complete',
        stored: stored('quarantine', 'floor', null, null, null, '2026-11-14T22:47:06.112Z'),
        dryRun: null,
        dispositionChanged: false,
        decisiveChanged: false,
      },
    ],
    invalidVersions: [],
  },
} as const;
