import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { validatePolicyDefinition } from './definition';
import { POLICY_FIELDS } from './fields';
import { input, run, snapshotOf, type Def } from './fixtures.test-support';
import { evaluatePolicyPerRecipient } from './per-recipient';
import { intendedActionStatuses, lifecycleOutcome, type PolicyEvaluationResult } from './result';
import { syntheticFactsSchema, type SyntheticFacts } from './synthetic';

/**
 * docs/architecture/policy-dsl.md is checked against the library: the field table equals
 * `POLICY_FIELDS`, every JSON block is a valid policy or valid synthetic facts, and every worked
 * example produces the result the document states.
 */
const DOC = readFileSync(resolve(__dirname, '../../../docs/architecture/policy-dsl.md'), 'utf8');

const jsonBlocks = (text: string): unknown[] =>
  [...text.matchAll(/```json\n([\s\S]*?)```/g)].map((m) => JSON.parse(m[1]!) as unknown);

interface Check {
  settings?: unknown;
  violations?: Array<[string, string]>;
  expect?: {
    disposition?: string;
    source?: string;
    reason?: string;
    override?: boolean;
    excepted?: string;
    headers?: string[];
    subjectPrefix?: string;
    actions?: string[];
    statuses?: string[];
    floor?: string[];
    clamp?: string;
    finalAction?: string;
  };
}

const examples = DOC.split(/^### Example /m)
  .slice(1)
  .map((full): { title: string; policy: Def; facts: SyntheticFacts; check: Check } => {
    // A section ends at the next level-2 heading (§12 and later are not part of example 12).
    const section = full.split(/^## /m)[0]!;
    const title = section.split('\n', 1)[0]!;
    const check = /<!-- check: (\{[\s\S]*?\}) -->/.exec(section);
    const blocks = jsonBlocks(section);
    return {
      title,
      policy: blocks[0] as Def,
      facts: (blocks[1] as SyntheticFacts | undefined) ?? {},
      check: JSON.parse(check![1]!) as Check,
    };
  });

describe('docs/architecture/policy-dsl.md', () => {
  it('the field table equals POLICY_FIELDS', () => {
    const table = DOC.split('<!-- field-table:start -->')[1]!.split('<!-- field-table:end -->')[0]!;
    const rows = table
      .split('\n')
      .filter((l) => l.startsWith('| `'))
      .map((l) => l.split(' | ').map((c) => c.replace(/^\| /, '').replace(/ \|$/, '').trim()));
    expect(rows.map((r) => r[0]!.replace(/`/g, ''))).toEqual(Object.keys(POLICY_FIELDS));
    for (const [cell, type, scope, ops, identity, ai] of rows) {
      const name = cell!.replace(/`/g, '') as keyof typeof POLICY_FIELDS;
      const def = POLICY_FIELDS[name];
      expect(type, name).toBe(def.type);
      expect(scope, name).toBe(def.scope);
      expect(
        ops!.split(', ').map((o) => o.replace(/`/g, '')),
        name,
      ).toEqual([...def.ops]);
      expect(identity, name).toBe(
        def.senderIdentity === 'raw'
          ? 'raw (unauthenticated)'
          : def.senderIdentity === 'authenticated'
            ? 'authenticated'
            : '',
      );
      expect(ai, name).toBe(def.aiDerived ? 'yes' : '');
    }
  });
  it('every JSON block is a valid policy or valid synthetic facts', () => {
    const blocks = jsonBlocks(DOC);
    expect(blocks.length).toBeGreaterThanOrEqual(23);
    for (const block of blocks) {
      if (typeof block === 'object' && block !== null && 'dslVersion' in block) {
        const r = validatePolicyDefinition(block);
        // Example 12 is the documented refusal.
        if (!r.ok)
          expect((block as unknown as { rules: Array<{ id: string }> }).rules[0]!.id).toBe(
            'spoofable-allow',
          );
      } else {
        expect(syntheticFactsSchema.safeParse(block).success, JSON.stringify(block)).toBe(true);
      }
    }
  });
  it('has at least ten worked examples, each with a check', () => {
    expect(examples.filter((e) => e.check.expect).length).toBeGreaterThanOrEqual(10);
  });
  for (const ex of examples) {
    it(`example ${ex.title}`, () => {
      if (ex.check.violations) {
        const r = validatePolicyDefinition(ex.policy);
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.violations.map((v) => [v.path, v.code])).toEqual(ex.check.violations);
        return;
      }
      const result = run(ex.facts, [ex.policy], { settings: ex.check.settings ?? null });
      assertExpect(result, ex.facts, ex.check.expect!);
    });
  }
});

function assertExpect(
  r: PolicyEvaluationResult,
  facts: SyntheticFacts,
  e: NonNullable<Check['expect']>,
) {
  if (e.disposition) expect(r.disposition).toBe(e.disposition);
  if (e.source) expect(r.decisive.source).toBe(e.source);
  if (e.reason) expect(r.decisive.reason).toBe(e.reason);
  if (e.override !== undefined) expect(r.override !== null).toBe(e.override);
  if (e.excepted)
    expect(r.trace.some((t) => t.result === 'excepted' && t.at === e.excepted)).toBe(true);
  if (e.headers)
    expect((r.delivery?.headers ?? []).map((h) => `${h.name}: ${h.value}`)).toEqual(e.headers);
  if (e.subjectPrefix) expect(r.delivery?.subjectPrefix).toBe(e.subjectPrefix);
  if (e.actions) expect(r.actions.map((a) => a.type)).toEqual(e.actions);
  if (e.statuses) expect(intendedActionStatuses(r)).toEqual(e.statuses);
  if (e.floor) expect(r.floor.reasons).toEqual(e.floor);
  if (e.clamp) expect(r.clamps[0]?.reason).toBe(e.clamp);
  if (e.finalAction)
    expect(lifecycleOutcome(r, facts.direction ?? 'inbound').finalAction).toBe(e.finalAction);
}

describe('the variants stated in the prose of the worked examples', () => {
  const byTitle = (prefix: string) => examples.find((e) => e.title.startsWith(prefix))!;
  it('1: without the setting the recommendation stands (override_disabled)', () => {
    const ex = byTitle('1:');
    const r = run(ex.facts, [ex.policy]);
    expect(r.disposition).toBe('quarantine');
    expect(r.clamps[0]!.reason).toBe('override_disabled');
  });
  it('2: a recipient outside finance → quarantine', () => {
    const ex = byTitle('2:');
    const r = run(
      { ...ex.facts, recipients: [...ex.facts.recipients!, { address: 'other@corp.example' }] },
      [ex.policy],
    );
    expect(r.disposition).toBe('quarantine');
  });
  it('3: body banner requested, ALERT requested', () => {
    const ex = byTitle('3:');
    const r = run(ex.facts, [ex.policy]);
    expect(r.delivery!.bodyBanner).toBe('requested');
    expect(intendedActionStatuses(r)).toEqual(['enforced', 'enforced', 'requested']);
  });
  it('4: final action require_approval', () => {
    const ex = byTitle('4:');
    expect(lifecycleOutcome(run(ex.facts, [ex.policy]), 'outbound')).toMatchObject({
      to: 'held_for_review',
      finalAction: 'require_approval',
    });
  });
  it('5: one week earlier (18:30 EST) is delivered', () => {
    const ex = byTitle('5:');
    expect(
      run({ ...ex.facts, evaluationTime: '2026-03-02T23:30:00.000Z' }, [ex.policy]).disposition,
    ).toBe('allow');
  });
  it('6: without the hard block → allow with tag via-appliance', () => {
    const ex = byTitle('6:');
    const r = run({ client: ex.facts.client }, [ex.policy]);
    expect(r.disposition).toBe('allow');
    expect(r.delivery!.headers).toEqual([{ name: 'X-EG-Policy-Tag', value: 'via-appliance' }]);
    expect(lifecycleOutcome(run(ex.facts, [ex.policy]), 'inbound').finalAction).toBe('discard');
  });
  it('7: outbound → reject with a sender notice', () => {
    const ex = byTitle('7:');
    const r = run({ ...ex.facts, direction: 'outbound' }, [ex.policy]);
    expect(lifecycleOutcome(r, 'outbound').finalAction).toBe('reject');
    expect(r.notices.senderNonDelivery).toBe(true);
  });
  it('9: rewritten → allow with the rewritten copy', () => {
    const ex = byTitle('9:');
    const r = run({ ...ex.facts, urlRewriteStatus: 'rewritten', urlRewriteSkipReason: null }, [
      ex.policy,
    ]);
    expect(r.disposition).toBe('allow');
    expect(r.delivery!.urlRewrite.rewritten).toBe(true);
  });
  it('10: the sender.department leaf is unknown inbound', () => {
    const ex = byTitle('10:');
    const r = run({ ...ex.facts, recipients: [{ address: 'x@corp.example' }] }, [ex.policy]);
    expect(r.trace[0]!.result).toBe('unknown');
  });
});

interface SplitCheck {
  message: string;
  split: boolean;
  lifecycle: string;
  decisions: Array<[number, string]>;
  counts: Record<string, number>;
  headers?: string[];
}

const splitExamples = DOC.split(/^### Split example /m)
  .slice(1)
  .map((full) => {
    const section = full.split(/^## /m)[0]!;
    const blocks = jsonBlocks(section);
    return {
      title: section.split('\n', 1)[0]!,
      policy: blocks[0] as Def,
      facts: blocks[1] as SyntheticFacts,
      check: JSON.parse(/<!-- split-check: (\{[\s\S]*?\}) -->/.exec(section)![1]!) as SplitCheck,
    };
  });

describe('docs/architecture/policy-dsl.md §13 split examples (step 5.3)', () => {
  it('has two split examples', () => expect(splitExamples).toHaveLength(2));
  for (const ex of splitExamples) {
    it(`split example ${ex.title}`, () => {
      const compiled = snapshotOf([ex.policy]);
      expect(compiled.invalid).toEqual([]);
      const e = evaluatePolicyPerRecipient(input(ex.facts), compiled);
      expect(e.message.disposition).toBe(ex.check.message);
      expect(e.split).toBe(ex.check.split);
      expect(e.lifecycleDisposition).toBe(ex.check.lifecycle);
      expect(e.recipientDecisions.map((d) => [d.rcptSeq, d.disposition])).toEqual(
        ex.check.decisions,
      );
      expect(e.counts).toEqual(ex.check.counts);
      if (ex.check.headers) {
        expect(
          (e.mergedDeliveryActions.edits?.headers ?? []).map((h) => `${h.name}: ${h.value}`),
        ).toEqual(ex.check.headers);
      }
      expect(e.message.explanation.text).not.toContain('@');
    });
  }
  it('split example 1 without recipientSplit: both quarantined', () => {
    const ex = splitExamples[0]!;
    const e = evaluatePolicyPerRecipient(
      input(ex.facts),
      snapshotOf([ex.policy], { settings: { recipientSplit: false } }),
    );
    expect(e.split).toBe(false);
    expect(e.lifecycleDisposition).toBe('quarantine');
  });
  it('split example 2 with a malware hard block: every recipient is held by the floor', () => {
    const ex = splitExamples[1]!;
    const e = evaluatePolicyPerRecipient(
      input({
        ...ex.facts,
        risk: {
          rev0: {
            score: 950,
            level: 'critical',
            verdict: 'malware',
            recommendedAction: 'block',
            hardBlocks: [{ id: 'hb.malware_attachment', action: 'block' }],
          },
        },
      }),
      snapshotOf([ex.policy]),
    );
    expect(e.recipientDecisions.map((d) => d.disposition)).toEqual(['reject', 'reject']);
  });
});
