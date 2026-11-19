import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildPipeline, Fixtures } from './support/fixtures';

/**
 * Step 8.4 D23 (ADR-0073), §10.2: ATO policy facts on the real writer. A tenant rule
 * `ato.risk_level gte high → QUARANTINE` holds outbound mail of a high-risk synthetic mailbox
 * account and not of a low one; inbound mail and organizations without ATO get no facts; the
 * block is stored with the evaluation; the floor is unchanged. Synthetic organizations only
 * (`it-pe-*`), with ATO rows inserted directly (the ato-worker is never involved).
 */
const fx = new Fixtures();
let high: bigint;
let low: bigint;
let off: bigint;
let modeOff: bigint;
let pipeline: ReturnType<typeof buildPipeline>;

const HOLD_HIGH_RISK = {
  dslVersion: 'policy-dsl/1',
  direction: 'outbound',
  priority: 100,
  rules: [
    {
      id: 'ato-high-risk-hold',
      priority: 10,
      when: { field: 'ato.risk_level', op: 'gte', value: 'high' },
      actions: [{ type: 'QUARANTINE' }],
    },
  ],
};

beforeAll(async () => {
  high = await fx.organization('ato-high');
  low = await fx.organization('ato-low');
  off = await fx.organization('ato-off');
  modeOff = await fx.organization('ato-mode-off');
  await fx.enableAto(high);
  await fx.enableAto(low, 'monitor');
  await fx.enableAto(modeOff, 'off');
  // The outbound fixture sender is bob@corp.example.
  await fx.atoAccount(
    high,
    'Bob@Corp.Example',
    { score: 72, level: 'high' },
    {
      severity: 'high',
      status: 'confirmed',
    },
  );
  await fx.atoAccount(low, 'bob@corp.example', { score: 12, level: 'low' });
  await fx.atoAccount(modeOff, 'bob@corp.example', { score: 90, level: 'critical' });
  // An account of another organization with the same address never leaks into `off`.
  for (const org of [high, low, off, modeOff]) {
    await fx.publish(org, 'hold high-risk senders', HOLD_HIGH_RISK);
  }
  pipeline = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('ato') });
});

afterAll(async () => {
  await fx.cleanup();
});

async function evaluateOutbound(org: bigint, direction: 'outbound' | 'internal' = 'outbound') {
  const message = await fx.message(org, { direction, recipients: ['carol@remote.example'] });
  expect(await pipeline.consumer.handler(fx.scanned(message))).toBe('handled');
  const [row] = await fx.evaluations(message);
  return { message, row: row! };
}

describe('ATO policy facts in the delivery gate (step 8.4 D23)', () => {
  it('holds outbound mail of a high-risk account and stores the facts it used', async () => {
    const { message, row } = await evaluateOutbound(high);
    expect(row).toMatchObject({
      disposition: 'quarantine',
      decisionSource: 'tenant_rule',
      decisiveRuleId: 'ato-high-risk-hold',
    });
    expect(row.atoFacts).toEqual({
      version: 'ato-policy-facts/1',
      accountKnown: true,
      riskScore: 72,
      riskLevel: 'high',
      incidentSeverity: 'high',
      incidentStatus: 'confirmed',
    });
    expect(row.inputVersion).toBe('policy-input/1');
    expect((await fx.lifecycle(message)).status).toBe('quarantined');
  });

  it('internal mail of the same account gets the facts too (this outbound-only policy does not apply)', async () => {
    const { row } = await evaluateOutbound(high, 'internal');
    expect(row.direction).toBe('internal');
    expect(row.disposition).toBe('allow');
    expect(row.atoFacts).toMatchObject({ riskLevel: 'high', incidentStatus: 'confirmed' });
  });

  it('delivers outbound mail of a low-risk account (facts stored, rule not matched)', async () => {
    const { row } = await evaluateOutbound(low);
    expect(row.disposition).toBe('allow');
    expect(row.atoFacts).toEqual({
      version: 'ato-policy-facts/1',
      accountKnown: true,
      riskScore: 12,
      riskLevel: 'low',
      incidentSeverity: null,
      incidentStatus: null,
    });
  });

  it('an unmonitored sender of an ATO-enabled organization is accountKnown false, score 0, low', async () => {
    const other = await fx.organization('ato-unmonitored');
    await fx.enableAto(other);
    await fx.publish(other, 'hold high-risk senders', HOLD_HIGH_RISK);
    const { row } = await evaluateOutbound(other);
    expect(row.disposition).toBe('allow');
    expect(row.atoFacts).toMatchObject({ accountKnown: false, riskScore: 0, riskLevel: 'low' });
  });

  it('no facts without the feature, with mode off, or for inbound mail (the rule never matches)', async () => {
    for (const org of [off, modeOff]) {
      const { row } = await evaluateOutbound(org);
      expect(row.disposition, String(org)).toBe('allow');
      expect(row.atoFacts, String(org)).toBeNull();
    }
    const inbound = await fx.message(high, { direction: 'inbound' });
    expect(await pipeline.consumer.handler(fx.scanned(inbound))).toBe('handled');
    const [row] = await fx.evaluations(inbound);
    expect(row!.atoFacts).toBeNull();
    expect(row!.disposition).toBe('allow');
  });

  it('the floor is unchanged: same floor for the same round with and without ATO facts', async () => {
    const withFacts = await evaluateOutbound(low);
    const withoutFacts = await evaluateOutbound(off);
    expect(withFacts.row.floor).toEqual(withoutFacts.row.floor);
    expect(withFacts.row.recommendation).toEqual(withoutFacts.row.recommendation);
  });

  it('counts the reads (policy_ato_facts_total, policy_ato_facts_seconds)', async () => {
    const text = await pipeline.registry.metrics();
    expect(text).toMatch(/policy_ato_facts_total\{result="resolved"[^}]*\} [1-9]/);
    expect(text).toMatch(/policy_ato_facts_total\{result="unknown_account"[^}]*\} [1-9]/);
    expect(text).toMatch(/policy_ato_facts_total\{result="disabled"[^}]*\} [1-9]/);
    expect(text).toMatch(/policy_ato_facts_total\{result="not_applicable"[^}]*\} [1-9]/);
    expect(text).toMatch(/policy_ato_facts_seconds_count\{[^}]*\} [1-9]/);
  });
});
