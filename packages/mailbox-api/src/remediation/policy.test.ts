import { describe, expect, it } from 'vitest';
import { remediationActionKey } from './keys';
import {
  buildDecisionRecord,
  canonicalJson,
  canonicalPolicySha256,
  decideRemediation,
  DEFAULT_REMEDIATION_POLICY,
  hardDeleteRuleIds,
  parseRemediationPolicy,
  REMEDIATION_PRESETS,
  remediationDecisionRecordSchema,
  remediationPolicySchema,
  resolveEffectivePolicy,
  UNSUPPORTED_UNTIL_POLICY_EVALUATION,
  type RemediationInput,
  type RemediationPolicy,
  type RemediationPolicyDocument,
  type StoredRemediationPolicy,
} from './policy';
import {
  COPY_REMEDIATION_STATES,
  MESSAGE_VERDICTS,
  REMEDIATION_ACTION_KINDS,
  REMEDIATION_FAILURE_CODES,
  REMEDIATION_RESULT_CODES,
  REMEDIATION_SKIP_REASONS,
  REMEDIATION_STATUSES,
  REMEDIATION_TRIGGERS,
  RISK_LEVELS,
} from './vocabulary';

const doc = (rules: unknown[], extra: Record<string, unknown> = {}) => ({ v: 1, rules, ...extra });
const rule = (id: string, when: Record<string, unknown>, action = 'tag') => ({ id, when, action });

function issues(value: unknown) {
  const result = remediationPolicySchema.safeParse(value);
  return result.success ? [] : result.error.issues;
}

describe('vocabularies (mirror the Prisma enums)', () => {
  it('pins every list', () => {
    expect(MESSAGE_VERDICTS).toEqual([
      'clean',
      'spam',
      'bulk',
      'phishing',
      'malware',
      'bec',
      'dlp_violation',
      'suspicious',
      'unknown',
    ]);
    expect(RISK_LEVELS).toEqual(['none', 'low', 'medium', 'high', 'critical']);
    expect(REMEDIATION_ACTION_KINDS).toEqual([
      'move_quarantine',
      'move_junk',
      'tag',
      'soft_delete',
      'hard_delete',
      'restore_inbox',
      'remove_tag',
    ]);
    expect(REMEDIATION_TRIGGERS).toEqual(['policy', 'admin', 'release', 'end_user', 'system']);
    expect(REMEDIATION_STATUSES).toEqual([
      'pending',
      'in_progress',
      'succeeded',
      'failed',
      'skipped',
      'simulated',
      'cancelled',
    ]);
    expect(COPY_REMEDIATION_STATES).toEqual([
      'none',
      'pending',
      'simulated',
      'remediated',
      'restored',
      'failed',
      'skipped',
    ]);
    expect(REMEDIATION_SKIP_REASONS).toEqual([
      'inline_authority',
      'out_of_scope',
      'hard_delete_disabled',
      'remediation_paused',
      'no_mailbox_access',
    ]);
    expect(REMEDIATION_RESULT_CODES).toEqual([
      'already_in_target',
      'hard_delete_unsupported_provider',
      'message_not_found',
      'mailbox_access_revoked',
      'provider_forbidden',
      'provider_rejected',
      'provider_unavailable',
      'integrity_mismatch',
      'entry_not_releasing',
      'internal_error',
    ]);
    for (const code of REMEDIATION_FAILURE_CODES) expect(REMEDIATION_RESULT_CODES).toContain(code);
  });
});

describe('remediationPolicySchema (api-remediation-policy/1)', () => {
  it('accepts the default, every preset and a full rule', () => {
    expect(issues(DEFAULT_REMEDIATION_POLICY.document)).toEqual([]);
    for (const preset of Object.values(REMEDIATION_PRESETS))
      expect(issues(preset.document)).toEqual([]);
    expect(
      issues(
        doc(
          [
            rule(
              'full_rule-1',
              {
                verdicts: ['spam', 'bulk'],
                minLevel: 'low',
                maxLevel: 'high',
                hardBlock: false,
                minScore: 0,
              },
              'move_junk',
            ),
          ],
          { remediateScanFailures: false },
        ),
      ),
    ).toEqual([]);
  });

  it.each([
    ['no rules', doc([])],
    ['17 rules', doc(Array.from({ length: 17 }, (_, i) => rule(`r${i}`, { verdicts: ['spam'] })))],
    ['wrong version', { v: 2, rules: [rule('a', { verdicts: ['spam'] })] }],
    ['unknown top-level key', doc([rule('a', { verdicts: ['spam'] })], { extra: true })],
    ['unknown rule key', doc([{ ...rule('a', { verdicts: ['spam'] }), priority: 1 }])],
    ['unknown when key', doc([rule('a', { verdicts: ['spam'], subject: 'x' })])],
    ['id with upper case', doc([rule('Rule', { verdicts: ['spam'] })])],
    ['id too long', doc([rule('a'.repeat(49), { verdicts: ['spam'] })])],
    ['empty id', doc([rule('', { verdicts: ['spam'] })])],
    ['empty verdicts', doc([rule('a', { verdicts: [] })])],
    ['clean verdict', doc([rule('a', { verdicts: ['clean'] })])],
    ['unknown verdict', doc([rule('a', { verdicts: ['unknown'] })])],
    ['duplicate verdicts', doc([rule('a', { verdicts: ['spam', 'spam'] })])],
    ['level none', doc([rule('a', { verdicts: ['spam'], minLevel: 'none' })])],
    ['max below min', doc([rule('a', { verdicts: ['spam'], minLevel: 'high', maxLevel: 'low' })])],
    ['score above 1000', doc([rule('a', { verdicts: ['spam'], minScore: 1001 })])],
    ['score not integer', doc([rule('a', { verdicts: ['spam'], minScore: 1.5 })])],
    ['unknown action', doc([rule('a', { verdicts: ['spam'] }, 'bounce')])],
    ['reversal as action', doc([rule('a', { verdicts: ['spam'] }, 'restore_inbox')])],
    [
      'scan failures true',
      doc([rule('a', { verdicts: ['spam'] })], { remediateScanFailures: true }),
    ],
  ])('refuses %s', (_label, value) => {
    expect(issues(value).length).toBeGreaterThan(0);
  });

  it('refuses duplicate rule ids with a coded issue', () => {
    const found = issues(
      doc([rule('a', { verdicts: ['spam'] }), rule('a', { verdicts: ['bulk'] })]),
    );
    expect(found).toEqual([
      expect.objectContaining({
        code: 'custom',
        message: 'duplicate_rule_id',
        path: ['rules', 1, 'id'],
      }),
    ]);
  });

  it('refuses the reserved when.policyDispositions with unsupported_until_policy_evaluation', () => {
    const found = issues(
      doc([rule('a', { verdicts: ['spam'], policyDispositions: ['quarantine'] })]),
    );
    expect(found).toHaveLength(1);
    expect(found[0]).toMatchObject({
      code: 'custom',
      message: UNSUPPORTED_UNTIL_POLICY_EVALUATION,
      params: { code: UNSUPPORTED_UNTIL_POLICY_EVALUATION },
      path: ['rules', 0, 'when', 'policyDispositions'],
    });
  });

  it('allows maxLevel = minLevel and parses through parseRemediationPolicy', () => {
    const value = doc([rule('a', { verdicts: ['phishing'], minLevel: 'high', maxLevel: 'high' })]);
    const parsed = parseRemediationPolicy(value);
    expect(parsed).toEqual({ ok: true, document: value });
    expect(parseRemediationPolicy({}).ok).toBe(false);
    expect(
      hardDeleteRuleIds(
        doc([rule('x', { verdicts: ['malware'] }, 'hard_delete')]) as RemediationPolicyDocument,
      ),
    ).toEqual(['x']);
  });
});

describe('default policy and presets (R2.3)', () => {
  it('P1 has exactly the four rows, mode enforce, and is frozen', () => {
    expect(DEFAULT_REMEDIATION_POLICY).toEqual({
      mode: 'enforce',
      document: {
        v: 1,
        rules: [
          {
            id: 'p1-high-confidence-malware-phishing-hb',
            when: { verdicts: ['malware', 'phishing'], hardBlock: true },
            action: 'move_quarantine',
          },
          {
            id: 'p1-high-confidence-malware-phishing',
            when: { verdicts: ['malware', 'phishing'], minLevel: 'critical' },
            action: 'move_quarantine',
          },
          {
            id: 'p1-other-malware-phishing',
            when: { verdicts: ['malware', 'phishing'] },
            action: 'tag',
          },
          { id: 'p1-suspicious', when: { verdicts: ['suspicious', 'bec'] }, action: 'tag' },
        ],
      },
    });
    expect(Object.isFrozen(DEFAULT_REMEDIATION_POLICY.document.rules[0]!.when.verdicts)).toBe(true);
  });

  it('presets: p1, detect-only start (same rules), strict (+ spam → Junk); no hard delete', () => {
    expect(REMEDIATION_PRESETS.p1).toEqual(DEFAULT_REMEDIATION_POLICY);
    expect(REMEDIATION_PRESETS.detectOnlyStart).toEqual({
      mode: 'detect_only',
      document: DEFAULT_REMEDIATION_POLICY.document,
    });
    expect(REMEDIATION_PRESETS.strict.mode).toBe('enforce');
    expect(REMEDIATION_PRESETS.strict.document.rules.at(-1)).toEqual({
      id: 'strict-spam-junk',
      when: { verdicts: ['spam'] },
      action: 'move_junk',
    });
    for (const preset of Object.values(REMEDIATION_PRESETS)) {
      expect(hardDeleteRuleIds(preset.document)).toEqual([]);
    }
  });
});

function input(overrides: {
  copy?: Partial<RemediationInput['copy']>;
  risk?: RemediationInput['risk'];
  context?: Partial<RemediationInput['context']>;
}): RemediationInput {
  return {
    copy: {
      status: 'scanned',
      verdict: 'malware',
      riskScore: 950,
      verdictAuthority: 'copy',
      ...overrides.copy,
    },
    risk:
      overrides.risk === undefined
        ? { level: 'critical', hardBlocks: ['hb.malware_attachment'] }
        : overrides.risk,
    policyOutcome: null,
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

const ON = { hardDeleteEnabled: true };
const OFF = { hardDeleteEnabled: false };
const P1 = DEFAULT_REMEDIATION_POLICY;

describe('decideRemediation (R2.2)', () => {
  it.each([
    [
      'malware + hard block → quarantine (hb rule)',
      input({}),
      'move_quarantine',
      'p1-high-confidence-malware-phishing-hb',
    ],
    [
      'phishing critical, no hard block → quarantine',
      input({ copy: { verdict: 'phishing' }, risk: { level: 'critical', hardBlocks: [] } }),
      'move_quarantine',
      'p1-high-confidence-malware-phishing',
    ],
    [
      'phishing high → tag',
      input({ copy: { verdict: 'phishing' }, risk: { level: 'high', hardBlocks: [] } }),
      'tag',
      'p1-other-malware-phishing',
    ],
    ['malware without risk row → tag', input({ risk: null }), 'tag', 'p1-other-malware-phishing'],
    ['suspicious → tag', input({ copy: { verdict: 'suspicious' } }), 'tag', 'p1-suspicious'],
    ['bec → tag', input({ copy: { verdict: 'bec' } }), 'tag', 'p1-suspicious'],
  ])('P1: %s', (_label, given, action, ruleId) => {
    expect(decideRemediation(given, P1, OFF)).toEqual({
      outcome: 'act',
      action,
      ruleId,
      simulated: false,
      notes: [],
    });
  });

  it.each([
    ['clean', input({ copy: { verdict: 'clean' } })],
    ['unknown', input({ copy: { verdict: 'unknown' } })],
    ['null verdict', input({ copy: { verdict: null } })],
    ['scan_failed', input({ copy: { status: 'scan_failed' } })],
    ['pending', input({ copy: { status: 'pending' } })],
    ['too_large', input({ copy: { status: 'too_large' } })],
    ['spam under P1 (no rule)', input({ copy: { verdict: 'spam' } })],
    ['bulk under P1', input({ copy: { verdict: 'bulk' } })],
    ['dlp_violation under P1', input({ copy: { verdict: 'dlp_violation' } })],
    // Step 1 comes before every gate: inline/paused/no grant never turn a none into a skip.
    ['clean inline copy', input({ copy: { verdict: 'clean', verdictAuthority: 'inline' } })],
  ])('none: %s', (_label, given) => {
    expect(decideRemediation(given, P1, ON)).toEqual({ outcome: 'none' });
  });

  it('a matching rule with action none is none (explicit no-op)', () => {
    const policy: RemediationPolicy = {
      mode: 'enforce',
      document: {
        v: 1,
        rules: [
          { id: 'ignore-low', when: { verdicts: ['malware'], maxLevel: 'low' }, action: 'none' },
          { id: 'rest', when: { verdicts: ['malware'] }, action: 'move_quarantine' },
        ],
      },
    };
    expect(
      decideRemediation(input({ risk: { level: 'low', hardBlocks: [] } }), policy, OFF),
    ).toEqual({ outcome: 'none' });
    expect(
      decideRemediation(input({ risk: { level: 'medium', hardBlocks: [] } }), policy, OFF),
    ).toMatchObject({ outcome: 'act', ruleId: 'rest' });
  });

  it('bounds: null level fails min/max, empty hard blocks fail hardBlock true, null score fails minScore', () => {
    const only = (when: Record<string, unknown>): RemediationPolicy => ({
      mode: 'enforce',
      document: {
        v: 1,
        rules: [{ id: 'r', when: { verdicts: ['malware'], ...when }, action: 'tag' }],
      },
    });
    const act = (given: RemediationInput, when: Record<string, unknown>) =>
      decideRemediation(given, only(when), OFF).outcome;
    expect(act(input({ risk: null }), { minLevel: 'low' })).toBe('none');
    expect(act(input({ risk: { level: null, hardBlocks: [] } }), { maxLevel: 'critical' })).toBe(
      'none',
    );
    expect(
      act(input({ risk: { level: 'medium', hardBlocks: [] } }), {
        minLevel: 'medium',
        maxLevel: 'high',
      }),
    ).toBe('act');
    expect(act(input({ risk: { level: 'critical', hardBlocks: [] } }), { maxLevel: 'high' })).toBe(
      'none',
    );
    expect(act(input({ risk: { level: 'high', hardBlocks: [] } }), { hardBlock: true })).toBe(
      'none',
    );
    expect(act(input({ risk: null }), { hardBlock: false })).toBe('act');
    expect(act(input({}), { hardBlock: false })).toBe('none');
    expect(act(input({ copy: { riskScore: null } }), { minScore: 0 })).toBe('none');
    expect(act(input({ copy: { riskScore: 500 } }), { minScore: 500 })).toBe('act');
    expect(act(input({ copy: { riskScore: 499 } }), { minScore: 500 })).toBe('none');
  });

  it('applies the gates in order 3 → 9', () => {
    const skip = (reason: string, action = 'move_quarantine') => ({
      outcome: 'skip',
      reason,
      ruleId: 'p1-high-confidence-malware-phishing-hb',
      action,
    });
    // (3) inline beats every later gate.
    expect(
      decideRemediation(
        input({
          copy: { verdictAuthority: 'inline' },
          context: { domainEffectiveMode: 'inline', remediationPaused: true, grantActive: false },
        }),
        P1,
        OFF,
      ),
    ).toEqual(skip('inline_authority'));
    // (4) out of scope: domain not api/hybrid, or mailbox disabled/deleted.
    for (const context of [
      { domainEffectiveMode: 'inline' as const },
      { domainEffectiveMode: null },
      { mailboxStatus: 'disabled' as const },
      { mailboxStatus: 'deleted' as const },
    ]) {
      expect(
        decideRemediation(input({ context: { ...context, grantActive: false } }), P1, OFF),
      ).toEqual(skip('out_of_scope'));
    }
    expect(
      decideRemediation(
        input({ context: { domainEffectiveMode: 'hybrid', mailboxStatus: 'discovered' } }),
        P1,
        OFF,
      ).outcome,
    ).toBe('act');
    // (5) hard delete without the platform setting, even in detect-only.
    const hard: RemediationPolicy = {
      mode: 'detect_only',
      document: {
        v: 1,
        rules: [{ id: 'hd', when: { verdicts: ['malware'] }, action: 'hard_delete' }],
      },
    };
    expect(decideRemediation(input({}), hard, OFF)).toEqual({
      outcome: 'skip',
      reason: 'hard_delete_disabled',
      ruleId: 'hd',
      action: 'hard_delete',
    });
    // (6) detect-only → simulated before paused / no grant.
    expect(
      decideRemediation(
        input({ context: { remediationPaused: true, grantActive: false } }),
        REMEDIATION_PRESETS.detectOnlyStart,
        OFF,
      ),
    ).toEqual({
      outcome: 'act',
      action: 'move_quarantine',
      ruleId: 'p1-high-confidence-malware-phishing-hb',
      simulated: true,
      notes: [],
    });
    // (7) paused before (8) no grant.
    expect(
      decideRemediation(
        input({ context: { remediationPaused: true, grantActive: false } }),
        P1,
        OFF,
      ),
    ).toEqual(skip('remediation_paused'));
    expect(decideRemediation(input({ context: { grantActive: false } }), P1, OFF)).toEqual(
      skip('no_mailbox_access'),
    );
  });

  it('notes the Google hard-delete fallback (enforce and detect-only)', () => {
    const hard = (mode: 'enforce' | 'detect_only'): RemediationPolicy => ({
      mode,
      document: {
        v: 1,
        rules: [{ id: 'hd', when: { verdicts: ['malware'] }, action: 'hard_delete' }],
      },
    });
    expect(
      decideRemediation(input({ context: { provider: 'google_workspace' } }), hard('enforce'), ON),
    ).toEqual({
      outcome: 'act',
      action: 'hard_delete',
      ruleId: 'hd',
      simulated: false,
      notes: ['hard_delete_falls_back_to_trash'],
    });
    expect(
      decideRemediation(
        input({ context: { provider: 'google_workspace' } }),
        hard('detect_only'),
        ON,
      ),
    ).toMatchObject({ simulated: true, notes: ['hard_delete_falls_back_to_trash'] });
    expect(decideRemediation(input({}), hard('enforce'), ON)).toMatchObject({ notes: [] });
  });

  it('strict preset moves spam to Junk; P1 rules still win for malware', () => {
    expect(
      decideRemediation(input({ copy: { verdict: 'spam' } }), REMEDIATION_PRESETS.strict, OFF),
    ).toMatchObject({
      outcome: 'act',
      action: 'move_junk',
      ruleId: 'strict-spam-junk',
    });
    expect(decideRemediation(input({}), REMEDIATION_PRESETS.strict, OFF)).toMatchObject({
      action: 'move_quarantine',
    });
  });
});

describe('resolveEffectivePolicy (R2.6)', () => {
  const docOf = (id: string): RemediationPolicyDocument => ({
    v: 1,
    rules: [{ id, when: { verdicts: ['spam'] }, action: 'tag' }],
  });
  const org: StoredRemediationPolicy = {
    publicId: '0190dddd-0000-7000-8000-0000000000a1',
    domainId: null,
    mode: 'detect_only',
    document: docOf('org'),
    rowVersion: 3,
  };
  const domain: StoredRemediationPolicy = {
    publicId: '0190dddd-0000-7000-8000-0000000000a2',
    domainId: 42n,
    mode: 'enforce',
    document: docOf('dom'),
    rowVersion: 1,
  };

  it('domain row → organization row → platform default', () => {
    expect(resolveEffectivePolicy({ organization: org, domains: [domain] }, '42')).toEqual({
      scope: 'domain',
      policy: { mode: 'enforce', document: domain.document },
      publicId: domain.publicId,
      rowVersion: 1,
    });
    expect(resolveEffectivePolicy({ organization: org, domains: [domain] }, 7)).toEqual({
      scope: 'organization',
      policy: { mode: 'detect_only', document: org.document },
      publicId: org.publicId,
      rowVersion: 3,
    });
    expect(resolveEffectivePolicy({ organization: org, domains: [domain] }, null).scope).toBe(
      'organization',
    );
    expect(resolveEffectivePolicy({ organization: null, domains: [domain] }, 42)).toMatchObject({
      scope: 'domain',
    });
    expect(resolveEffectivePolicy({ organization: null, domains: [domain] }, 1)).toEqual({
      scope: 'platform_default',
      policy: DEFAULT_REMEDIATION_POLICY,
      publicId: null,
      rowVersion: null,
    });
  });
});

describe('canonical hash and decision record (R2.4)', () => {
  it('hashes canonical JSON (key order does not matter, content does)', () => {
    const a = {
      v: 1 as const,
      rules: [
        { id: 'a', when: { verdicts: ['spam' as const], minScore: 1 }, action: 'tag' as const },
      ],
    };
    const b = JSON.parse(
      '{"rules":[{"action":"tag","when":{"minScore":1,"verdicts":["spam"]},"id":"a"}],"v":1}',
    ) as RemediationPolicyDocument;
    expect(canonicalJson(a)).toBe(
      '{"rules":[{"action":"tag","id":"a","when":{"minScore":1,"verdicts":["spam"]}}],"v":1}',
    );
    expect(canonicalPolicySha256(a)).toBe(canonicalPolicySha256(b));
    expect(canonicalPolicySha256(a)).toMatch(/^[0-9a-f]{64}$/);
    expect(
      canonicalPolicySha256({ ...a, rules: [{ ...a.rules[0]!, action: 'move_junk' }] }),
    ).not.toBe(canonicalPolicySha256(a));
    expect(() => canonicalJson({ x: Number.NaN })).toThrow();
  });

  it('records provenance, inputs (≤ 9 hard blocks) and notes; validates against its schema', () => {
    const effective = resolveEffectivePolicy({ organization: null, domains: [] }, null);
    const given = input({
      risk: { level: 'critical', hardBlocks: Array.from({ length: 12 }, (_, i) => `hb.x${i}`) },
    });
    const decision = decideRemediation(given, effective.policy, OFF);
    const record = buildDecisionRecord(effective, given, decision);
    expect(record).toEqual({
      v: 1,
      policy: {
        scope: 'platform_default',
        publicId: null,
        rowVersion: null,
        sha256: canonicalPolicySha256(DEFAULT_REMEDIATION_POLICY.document),
      },
      mode: 'enforce',
      ruleId: 'p1-high-confidence-malware-phishing-hb',
      inputs: {
        verdict: 'malware',
        riskScore: 950,
        level: 'critical',
        hardBlocks: Array.from({ length: 9 }, (_, i) => `hb.x${i}`),
        verdictAuthority: 'copy',
      },
      policyOutcome: null,
      notes: [],
    });
    expect(remediationDecisionRecordSchema.parse(record)).toEqual(record);
    const skipped = buildDecisionRecord(
      effective,
      given,
      decideRemediation(input({ context: { grantActive: false } }), effective.policy, OFF),
    );
    expect(skipped.ruleId).toBe('p1-high-confidence-malware-phishing-hb');
    expect(buildDecisionRecord(effective, given, { outcome: 'none' }).ruleId).toBeNull();
  });
});

describe('remediationActionKey (§5 identifiers)', () => {
  const COPY = '0190dddd-0000-7000-8000-0000000000c1';
  it('matches the vectors of hex SHA-256("api-remediation/1\\0<copy>\\0<action>\\0<generation>")', () => {
    expect(remediationActionKey(COPY, 'move_quarantine', 0)).toBe(
      '5a17d37e48f69127c9f9469986c00d98e7bec968097b132760c785cd64ec6ae5',
    );
    expect(remediationActionKey(COPY, 'move_quarantine', 1)).toBe(
      '8cdc14ddc1226a7d44d5bf0b50b04032dab0a365fc90e3d9a35195b071867247',
    );
    expect(remediationActionKey(COPY, 'restore_inbox', 0)).toBe(
      '9f08e2e6b7ae49b3b6640ffa0acbee80b78439a4418ef3362aaefe2793876997',
    );
  });

  it('refuses invalid inputs', () => {
    expect(() => remediationActionKey('not-a-uuid', 'tag', 0)).toThrow(RangeError);
    expect(() => remediationActionKey(COPY, 'bounce' as never, 0)).toThrow(RangeError);
    expect(() => remediationActionKey(COPY, 'tag', -1)).toThrow(RangeError);
    expect(() => remediationActionKey(COPY, 'tag', 65_536)).toThrow(RangeError);
    expect(() => remediationActionKey(COPY, 'tag', 1.5)).toThrow(RangeError);
  });
});
