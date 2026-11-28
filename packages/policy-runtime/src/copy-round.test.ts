import type { Prisma } from '@email-gateway/database';
import { policyOutcomeFactsSchema } from '@email-gateway/mailbox-api';
import {
  compileSnapshot,
  POLICY_DEFAULT_PLATFORM_ID,
  PolicyInputError,
} from '@email-gateway/policy-dsl';
import { describe, expect, it, vi } from 'vitest';
import {
  detectActionStatus,
  detectRowData,
  evaluateCopyRound,
  policyOutcomeOf,
  type CopyRoundDeps,
  type CopyRoundEvaluated,
  type CopyRoundRef,
} from './copy-round';
import { EMPTY_DIRECTORY } from './directory.repository';
import { InconsistentPolicyReadError } from './errors';
import type { RoundFacts, RoundRef } from './facts.repository';
import type { SnapshotLookup } from './snapshot.repository';
import { cleanFacts, cleanRiskRow, definition, POLICY_A, RULES } from './testing/fixtures';

const RECEIVED = new Date('2026-11-27T09:59:00.000Z');
const NOW = new Date('2026-11-27T10:00:05.000Z');
const REF: CopyRoundRef = {
  messageId: 100n,
  receivedAt: RECEIVED,
  organizationId: 7n,
  round: 0,
  trigger: 'scanned',
  scanId: 900n,
};
const tx = {} as Prisma.TransactionClient;

function snapshot(
  policies: Array<{ rules: unknown[]; direction?: 'inbound' | 'outbound' | 'any' }> = [],
  settings: unknown = null,
): SnapshotLookup {
  const source = policies.map((p, i) => {
    const d = definition(p.direction ?? 'inbound', p.rules);
    return {
      publicId: POLICY_A,
      versionNo: i + 1,
      definition: d.definition,
      definitionSha256: d.definitionSha256,
    };
  });
  const compiled = compileSnapshot({
    generation: '3',
    settings,
    platformDefaultId: POLICY_DEFAULT_PLATFORM_ID,
    policies: source,
  });
  return {
    compiled,
    policyVersionIds: Object.fromEntries(
      source.map((s, i) => [`${s.publicId}#${s.versionNo}`, String(50 + i)]),
    ),
    cache: 'miss',
    invalidVersions: compiled.invalid.length,
  };
}

function deps(options: {
  facts?: RoundFacts | (() => Promise<RoundFacts>);
  snapshot?: SnapshotLookup;
  directory?: CopyRoundDeps['directory'];
}) {
  const reads: RoundRef[] = [];
  let clock = 1_000_000_000n;
  const d: CopyRoundDeps = {
    facts: {
      read: vi.fn((_tx: unknown, ref: RoundRef) => {
        reads.push(ref);
        const f = options.facts ?? cleanFacts();
        return typeof f === 'function' ? f() : Promise.resolve(f);
      }),
    },
    snapshots: { get: vi.fn(() => Promise.resolve(options.snapshot ?? snapshot())) },
    directory: options.directory ?? { resolve: vi.fn(() => Promise.resolve(EMPTY_DIRECTORY)) },
    hrtime: () => (clock += 2_500_000n),
  };
  return { deps: d, reads };
}

async function evaluated(
  options: Parameters<typeof deps>[0] = {},
  ref: CopyRoundRef = REF,
): Promise<CopyRoundEvaluated> {
  const result = await evaluateCopyRound(tx, deps(options).deps, ref);
  if (result.status !== 'evaluated') throw new Error(`not evaluated: ${result.code}`);
  return result;
}

describe('evaluateCopyRound (A2)', () => {
  it('evaluates the copy round with the engine runtime: facts, snapshot, directory, evaluator', async () => {
    const { deps: d, reads } = deps({ snapshot: snapshot([{ rules: [RULES.quarantineInbound] }]) });
    const result = await evaluateCopyRound(tx, d, REF);
    expect(result.status).toBe('evaluated');
    if (result.status !== 'evaluated') return;
    // Never an older round: the message row's round must equal the copy's.
    expect(reads).toEqual([{ ...REF, olderRoundAllowed: false }]);
    expect(result.perRecipient.message.disposition).toBe('quarantine');
    expect(result.perRecipient.message.decisive).toMatchObject({
      source: 'tenant_rule',
      policyPublicId: POLICY_A,
      ruleId: 'quarantine-all',
    });
    expect(result.meta).toEqual({
      generation: '3',
      snapshotSha256: result.perRecipient.message.versions.snapshotSha256,
      platformDefaultId: POLICY_DEFAULT_PLATFORM_ID,
      policyVersions: result.perRecipient.message.versions.policies,
      policyVersionIds: { [`${POLICY_A}#1`]: '50' },
      invalidVersions: 0,
      cache: 'miss',
    });
    expect(result.durationUs).toBe(2500);
    expect(result.input.trigger).toBe('scanned');
  });

  it('a malformed fact row (PolicyInputError from the reads) → failed policy_input_invalid', async () => {
    const { deps: d } = deps({
      facts: () => Promise.reject(new PolicyInputError('scan round is not final')),
    });
    await expect(evaluateCopyRound(tx, d, REF)).resolves.toEqual({
      status: 'failed',
      code: 'policy_input_invalid',
    });
  });

  it('a malformed row caught by the input builder → failed policy_input_invalid', async () => {
    const facts = cleanFacts();
    const broken: RoundFacts = { ...facts, dlp: { ...facts.dlp!, categories: 'not-a-list' } };
    const { deps: d } = deps({ facts: broken });
    await expect(evaluateCopyRound(tx, d, REF)).resolves.toEqual({
      status: 'failed',
      code: 'policy_input_invalid',
    });
  });

  it('an evaluator exception → failed evaluator_error', async () => {
    const good = snapshot();
    const broken: SnapshotLookup = {
      ...good,
      compiled: { ...good.compiled, settings: undefined as never },
    };
    const { deps: d } = deps({ snapshot: broken });
    await expect(evaluateCopyRound(tx, d, REF)).resolves.toEqual({
      status: 'failed',
      code: 'evaluator_error',
    });
  });

  it('an inconsistent read throws (the ledger transaction rolls back and is retried)', async () => {
    const { deps: d } = deps({
      facts: () => Promise.reject(new InconsistentPolicyReadError('message', 'round echo')),
    });
    await expect(evaluateCopyRound(tx, d, REF)).rejects.toBeInstanceOf(InconsistentPolicyReadError);
    const dir = deps({
      snapshot: snapshot([{ rules: [RULES.departmentException(POLICY_A)] }]),
      directory: {
        resolve: () =>
          Promise.reject(new InconsistentPolicyReadError('members', 'department echo')),
      },
    });
    await expect(evaluateCopyRound(tx, dir.deps, REF)).rejects.toBeInstanceOf(
      InconsistentPolicyReadError,
    );
  });

  it('a database error propagates (retryable, never a failed evaluation)', async () => {
    const { deps: d } = deps({ facts: () => Promise.reject(new Error('connection lost')) });
    await expect(evaluateCopyRound(tx, d, REF)).rejects.toThrow('connection lost');
  });

  it('reads the sender ATO facts for outbound rounds (same AtoFactsSource rule as 8.4 D23)', async () => {
    const ato = {
      read: vi.fn(() =>
        Promise.resolve({
          accountKnown: true,
          riskScore: 80,
          riskLevel: 'high',
          incidentSeverity: null,
          incidentStatus: null,
        }),
      ),
      notApplicable: vi.fn(),
    };
    const outbound = cleanFacts({ direction: 'outbound', recipients: ['carol@partner.example'] });
    const authenticated: RoundFacts = { ...outbound };
    const { deps: d } = deps({ facts: authenticated });
    const result = await evaluateCopyRound(tx, { ...d, atoFacts: ato }, REF);
    expect(result.status).toBe('evaluated');
    // Without an authenticated sender the source is told "not applicable" (no read).
    expect(ato.read.mock.calls.length + ato.notApplicable.mock.calls.length).toBe(1);
  });
});

describe('policyOutcomeOf (A4.1)', () => {
  it('message level and recipient level of an unsplit evaluation', async () => {
    const e = await evaluated({ snapshot: snapshot([{ rules: [RULES.quarantineInbound] }]) });
    const message = policyOutcomeOf(e, null);
    expect(message).toEqual({
      disposition: 'quarantine',
      tagged: false,
      overrideApplied: false,
      decisionSource: 'tenant_rule',
      decisiveRuleRef: `${POLICY_A}#1/quarantine-all`,
      floorReasons: [],
      dlpAction: 'allow',
      actionTypes: ['QUARANTINE'],
      recommendationOnly: false,
    });
    expect(policyOutcomeOf(e, 0)).toEqual(message);
    expect(policyOutcomeFactsSchema.parse(message)).toEqual(message);
  });

  it('a tagged allow is tagged; the platform default has no rule ref', async () => {
    const tagged = await evaluated({ snapshot: snapshot([{ rules: [RULES.tagExternal] }]) });
    expect(policyOutcomeOf(tagged, 0)).toMatchObject({
      disposition: 'allow',
      tagged: true,
      actionTypes: expect.arrayContaining(['TAG']),
    });
    const clean = await evaluated();
    expect(policyOutcomeOf(clean, 0)).toMatchObject({
      disposition: 'allow',
      tagged: false,
      decisionSource: 'platform_default',
      decisiveRuleRef: null,
    });
  });

  it('per recipient of a split evaluation (Q5 decisions), message level for null', async () => {
    const facts = cleanFacts({ recipients: ['bob@corp.example', 'eve@corp.example'] });
    const rule = {
      id: 'hold-eve',
      priority: 5,
      when: { field: 'recipient.address', op: 'in', value: ['eve@corp.example'] },
      actions: [{ type: 'QUARANTINE' }],
    };
    const e = await evaluated({
      facts,
      snapshot: snapshot([{ rules: [rule] }], { recipientSplit: true }),
    });
    expect(e.perRecipient.split).toBe(true);
    expect(policyOutcomeOf(e, 0).disposition).toBe('allow');
    expect(policyOutcomeOf(e, 1)).toMatchObject({
      disposition: 'quarantine',
      decisiveRuleRef: `${POLICY_A}#1/hold-eve`,
    });
    expect(policyOutcomeOf(e, null).disposition).toBe(e.perRecipient.message.disposition);
  });

  it('carries the DLP action only when the DLP final is definite, and the floor reasons', async () => {
    const facts = cleanFacts();
    const blocked: RoundFacts = {
      ...facts,
      dlp: { action: 'block', verdict: 'suspicious', coverage: 'complete', categories: [] },
    };
    const e = await evaluated({ facts: blocked });
    expect(policyOutcomeOf(e, 0)).toMatchObject({
      disposition: 'reject',
      decisionSource: 'floor',
      floorReasons: ['policy.floor.dlp_block'],
      dlpAction: 'block',
    });
    const skipped: RoundFacts = {
      ...facts,
      finals: facts.finals.map((f) => (f.engine === 'dlp' ? { ...f, outcome: 'skipped' } : f)),
    };
    const s = await evaluated({ facts: skipped });
    expect(policyOutcomeOf(s, 0).dlpAction).toBeNull();
  });
});

describe('policyOutcomeOf recommendationOnly (A4.3 step 3, review fix)', () => {
  const spamRisk = cleanRiskRow({
    score: 70,
    level: 'medium',
    verdict: 'spam',
    recommendedAction: 'quarantine',
  });

  it('a platform-default quarantine that restates the risk recommendation feeds no policy lane', async () => {
    const e = await evaluated({ facts: cleanFacts({ risk: [spamRisk] }) });
    expect(policyOutcomeOf(e, 0)).toMatchObject({
      disposition: 'quarantine',
      decisionSource: 'platform_default',
      recommendationOnly: true,
    });
  });

  it('the platform risk tag on an allow is a restatement; a tenant TAG is not', async () => {
    const tagRisk = cleanRiskRow({ level: 'low', recommendedAction: 'tag' });
    const platformTag = await evaluated({ facts: cleanFacts({ risk: [tagRisk] }) });
    expect(policyOutcomeOf(platformTag, 0)).toMatchObject({
      disposition: 'allow',
      tagged: true,
      recommendationOnly: true,
    });
    const tenantTag = await evaluated({
      facts: cleanFacts({ risk: [tagRisk] }),
      snapshot: snapshot([{ rules: [RULES.tagExternal] }]),
    });
    expect(policyOutcomeOf(tenantTag, 0)).toMatchObject({
      tagged: true,
      recommendationOnly: false,
    });
    const clean = await evaluated();
    expect(policyOutcomeOf(clean, 0)).toMatchObject({ tagged: false, recommendationOnly: false });
  });

  it('a tenant rule, a raised floor or a floor binding at the same level is never a restatement', async () => {
    const tenant = await evaluated({
      facts: cleanFacts({ risk: [spamRisk] }),
      snapshot: snapshot([{ rules: [RULES.quarantineInbound] }]),
    });
    expect(policyOutcomeOf(tenant, 0)).toMatchObject({
      decisionSource: 'tenant_rule',
      recommendationOnly: false,
    });
    const raised = cleanFacts();
    const blocked = await evaluated({
      facts: {
        ...raised,
        dlp: { action: 'block', verdict: 'suspicious', coverage: 'complete', categories: [] },
      },
    });
    expect(policyOutcomeOf(blocked, 0)).toMatchObject({
      decisionSource: 'floor',
      recommendationOnly: false,
    });
    const spam = cleanFacts({ risk: [spamRisk] });
    const dlpSameLevel = await evaluated({
      facts: {
        ...spam,
        dlp: { action: 'quarantine', verdict: 'suspicious', coverage: 'complete', categories: [] },
      },
    });
    expect(policyOutcomeOf(dlpSameLevel, 0)).toMatchObject({
      disposition: 'quarantine',
      decisionSource: 'platform_default',
      floorReasons: ['policy.floor.dlp_quarantine'],
      recommendationOnly: false,
    });
  });
});

describe('detectRowData (A1, A2, A5)', () => {
  it('builds a detect row: mode detect, nothing delivered, post-delivery statuses', async () => {
    const e = await evaluated({
      snapshot: snapshot([{ rules: [RULES.rejectAny('inbound'), RULES.archiveAlert] }]),
    });
    const data = detectRowData(e, REF, NOW);
    expect(data).toMatchObject({
      evaluationMode: 'detect',
      messageId: 100n,
      receivedAt: RECEIVED,
      organizationId: 7n,
      evaluationSeq: 0,
      scanId: 900n,
      trigger: 'scanned',
      direction: 'inbound',
      disposition: 'reject',
      decisionSource: 'tenant_rule',
      decisivePolicyVersionId: 50n,
      decisivePolicyPublicId: POLICY_A,
      decisiveRuleId: 'reject-all',
      action: 'discard',
      deliveredObject: 'none',
      objectKey: null,
      delivery: undefined,
      durationUs: e.durationUs,
      evaluatedAt: NOW,
      inputSha256: e.perRecipient.message.inputSha256,
      recipientSplit: false,
    });
    expect(data.actions).toEqual([
      expect.objectContaining({ type: 'REJECT', status: 'requested' }),
    ]);
    // Non-terminal actions of an allowed copy: TAG requested (mapped to the mailbox tag),
    // ARCHIVE not applicable (journaling decides), ALERT requested or recorded (tenant alerts).
    const tagged = await evaluated({
      snapshot: snapshot([{ rules: [RULES.tagExternal, RULES.archiveAlert] }]),
    });
    const row = detectRowData(tagged, REF, NOW);
    expect(row).toMatchObject({ disposition: 'allow', action: 'tag', deliveredObject: 'none' });
    const statuses = Object.fromEntries(
      (row.actions as Array<{ type: string; status: string; params: { notify?: boolean } }>).map(
        (a) => [a.type, a.status],
      ),
    );
    const alert = (row.actions as Array<{ type: string; params: { notify?: boolean } }>).find(
      (a) => a.type === 'ALERT',
    );
    expect(statuses).toMatchObject({
      ALLOW: 'recorded',
      TAG: 'requested',
      ARCHIVE: 'not_applicable',
      ALERT: alert?.params.notify === true ? 'requested' : 'recorded',
    });
  });

  it('outbound: every action but ALERT is not applicable (already sent)', async () => {
    const facts = cleanFacts({ direction: 'outbound', recipients: ['carol@partner.example'] });
    const e = await evaluated({
      facts,
      snapshot: snapshot([{ rules: [RULES.rejectAny('outbound')], direction: 'outbound' }]),
    });
    const data = detectRowData(e, REF, NOW);
    expect(data.action).toBe('reject');
    expect((data.actions as Array<{ type: string; status: string }>)[0]).toMatchObject({
      type: 'REJECT',
      status: 'not_applicable',
    });
  });

  it('statuses: not-applicable actions stay so, ALERT without notification is recorded', () => {
    const base = { params: {}, origin: 'tenant_rule' as const, ruleRefs: [] };
    expect(
      detectActionStatus({ ...base, type: 'TAG', applicability: 'not_applicable' }, 'inbound'),
    ).toBe('not_applicable');
    expect(
      detectActionStatus({ ...base, type: 'ALERT', applicability: 'applies' }, 'inbound'),
    ).toBe('recorded');
    expect(
      detectActionStatus(
        { ...base, params: { notify: true }, type: 'ALERT', applicability: 'applies' },
        'outbound',
      ),
    ).toBe('requested');
    expect(
      detectActionStatus({ ...base, type: 'URL_REWRITE', applicability: 'applies' }, 'inbound'),
    ).toBe('not_applicable');
    expect(
      detectActionStatus({ ...base, type: 'ALLOW', applicability: 'applies' }, 'inbound'),
    ).toBe('recorded');
  });

  it('refuses a ref of another round', async () => {
    const e = await evaluated();
    expect(() => detectRowData(e, { ...REF, round: 1 }, NOW)).toThrow(RangeError);
  });

  it('stores the ATO block exactly as used (absent → no column)', async () => {
    const e = await evaluated({ facts: cleanFacts({ risk: [cleanRiskRow()] }) });
    expect('atoFacts' in detectRowData(e, REF, NOW)).toBe(false);
  });
});
