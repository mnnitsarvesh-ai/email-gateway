import { describe, expect, it } from 'vitest';
import { diffDefinitions, isUnchanged, lineDiff, type LineDiff } from './diff';
import { SeededRandom } from './test-support/random';
import { TEST_CATALOG } from './test-support/catalog';
import { BRIEF_EXAMPLE } from './test-support/documents';

const apply = (diff: LineDiff) => ({
  a: diff.filter((d) => d.op !== 'insert').map((d) => d.text),
  b: diff.filter((d) => d.op !== 'delete').map((d) => d.text),
  edits: diff.filter((d) => d.op !== 'equal').length,
});

/** Minimal edit count through the LCS (O(NM), test oracle only). */
function minimalEdits(a: readonly string[], b: readonly string[]): number {
  const dp = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
  for (let i = a.length - 1; i >= 0; i -= 1) {
    for (let j = b.length - 1; j >= 0; j -= 1) {
      dp[i]![j] = a[i] === b[j] ? dp[i + 1]![j + 1]! + 1 : Math.max(dp[i + 1]![j]!, dp[i]![j + 1]!);
    }
  }
  return a.length + b.length - 2 * dp[0]![0]!;
}

describe('lineDiff (Myers)', () => {
  it('handles the edge cases', () => {
    expect(lineDiff([], [])).toEqual([]);
    expect(lineDiff([], ['a', 'b'])).toEqual([
      { op: 'insert', text: 'a' },
      { op: 'insert', text: 'b' },
    ]);
    expect(lineDiff(['a', 'b'], [])).toEqual([
      { op: 'delete', text: 'a' },
      { op: 'delete', text: 'b' },
    ]);
    expect(lineDiff(['a', 'b'], ['a', 'b'])).toEqual([
      { op: 'equal', text: 'a' },
      { op: 'equal', text: 'b' },
    ]);
    expect(lineDiff(['a'], ['b'])).toEqual([
      { op: 'delete', text: 'a' },
      { op: 'insert', text: 'b' },
    ]);
    expect(lineDiff(['a', 'b', 'c'], ['a', 'x', 'c'])).toEqual([
      { op: 'equal', text: 'a' },
      { op: 'delete', text: 'b' },
      { op: 'insert', text: 'x' },
      { op: 'equal', text: 'c' },
    ]);
    // Repeated lines and a reorder.
    const d = lineDiff(['x', 'x', 'y'], ['y', 'x', 'x']);
    expect(apply(d)).toEqual({ a: ['x', 'x', 'y'], b: ['y', 'x', 'x'], edits: 2 });
  });

  it('is a minimal edit script on 300 seeded random pairs', () => {
    const rng = new SeededRandom(42);
    for (let i = 0; i < 300; i += 1) {
      const alphabet = ['a', 'b', 'c', 'd'].slice(0, 1 + rng.int(4));
      const a = Array.from({ length: rng.int(14) }, () => rng.pick(alphabet));
      const b = Array.from({ length: rng.int(14) }, () => rng.pick(alphabet));
      const result = apply(lineDiff(a, b));
      expect(result.a, `pair ${i}`).toEqual(a);
      expect(result.b, `pair ${i}`).toEqual(b);
      expect(result.edits, `pair ${i}`).toBe(minimalEdits(a, b));
    }
  });

  it('stays fast on long inputs with few changes', () => {
    const a = Array.from({ length: 20_000 }, (_, i) => `line ${i}`);
    const b = [...a];
    b.splice(10_000, 1, 'changed');
    b.push('tail');
    const started = Date.now();
    const result = apply(lineDiff(a, b));
    expect(Date.now() - started).toBeLessThan(2_000);
    expect(result.edits).toBe(3);
  });
});

const policy = (rules: unknown[], extra: Record<string, unknown> = {}) => ({
  dslVersion: 'policy-dsl/1',
  direction: 'outbound',
  priority: 10,
  rules,
  ...extra,
});

describe('diffDefinitions (design B10)', () => {
  it('reports nothing for identical definitions', () => {
    const diff = diffDefinitions(BRIEF_EXAMPLE, structuredClone(BRIEF_EXAMPLE), TEST_CATALOG);
    expect(diff.policy).toEqual([]);
    expect(diff.counts).toEqual({ added: 0, removed: 0, changed: 0 });
    expect(diff.rules.map((r) => r.change)).toEqual(['unchanged']);
    expect(isUnchanged(diff.json)).toBe(true);
  });

  it('aligns rules by id: added, removed, changed with property and line diffs', () => {
    const base = BRIEF_EXAMPLE.rules[0]!;
    const a = policy([
      base,
      {
        id: 'old',
        priority: 30,
        when: { field: 'auth.spf', op: 'equals', value: 'fail' },
        actions: [{ type: 'TAG', label: 'spf' }],
      },
    ]);
    const b = policy(
      [
        {
          ...base,
          priority: 5,
          enabled: false,
          when: {
            all: [
              {
                field: 'dlp.categories',
                op: 'contains_any',
                value: ['confidential', 'source_code'],
              },
            ],
          },
          actions: [{ type: 'QUARANTINE' }, { type: 'ALERT', severity: 'critical' }],
          stop: true,
        },
        {
          id: 'new',
          priority: 20,
          when: { field: 'urls.count', op: 'gt', value: 0 },
          actions: [{ type: 'URL_REWRITE' }],
        },
      ],
      { direction: 'any', priority: 20 },
    );
    const diff = diffDefinitions(a, b, TEST_CATALOG);
    expect(diff.policy).toEqual([
      { property: 'direction', before: 'Outbound', after: 'Any' },
      { property: 'priority', before: '10', after: '20' },
    ]);
    expect(diff.counts).toEqual({ added: 1, removed: 1, changed: 1 });
    expect(diff.rules.map((r) => [r.ruleId, r.change])).toEqual([
      ['quarantine-confidential', 'changed'],
      ['new', 'added'],
      ['old', 'removed'],
    ]);
    const changed = diff.rules[0]!;
    expect(changed.properties).toEqual([
      { property: 'priority', before: '10', after: '5' },
      { property: 'enabled', before: 'Not set', after: 'Disabled' },
      { property: 'stop', before: 'Not set', after: 'Stop' },
    ]);
    // The policy direction is a policy-level change, not a line of every rule.
    expect(changed.when).toEqual([
      { op: 'delete', text: 'DLP data categories contain any of Confidential' },
      { op: 'insert', text: 'DLP data categories contain any of Confidential, Source code' },
    ]);
    expect(changed.then).toEqual([
      { op: 'equal', text: 'Quarantine' },
      { op: 'delete', text: 'AND Alert administrators (severity: warning)' },
      { op: 'insert', text: 'AND Alert administrators (severity: critical)' },
    ]);
    expect(diff.rules[1]!.when.every((l) => l.op === 'insert')).toBe(true);
    expect(diff.rules[2]!.then).toEqual([{ op: 'delete', text: 'Tag (label: "spf")' }]);
    expect(diff.json.some((l) => l.op === 'insert' && l.text.includes('"source_code"'))).toBe(true);
  });

  it('shows every list item in diffs (no "and N more" hiding a change)', () => {
    const values = Array.from({ length: 8 }, (_, i) => `d${i}.example`);
    const rule = (v: string[]) => ({
      id: 'r',
      priority: 1,
      when: { field: 'recipient.domain', op: 'in', value: v },
      actions: [{ type: 'ARCHIVE' }],
    });
    const diff = diffDefinitions(
      policy([rule(values)]),
      policy([rule([...values.slice(0, 7), 'other.example'])]),
      TEST_CATALOG,
    );
    expect(diff.rules[0]!.change).toBe('changed');
    expect(
      diff.rules[0]!.when.some((l) => l.op === 'insert' && l.text.includes('other.example')),
    ).toBe(true);
  });

  it('reports policy-wide exception changes', () => {
    const exceptions = [{ field: 'sender.trusted', op: 'is', value: true }];
    const diff = diffDefinitions(BRIEF_EXAMPLE, { ...BRIEF_EXAMPLE, exceptions }, TEST_CATALOG);
    expect(diff.policy).toEqual([
      { property: 'exceptions', before: 'None', after: 'Trusted sender is Yes' },
    ]);
    expect(diff.rules[0]!.change).toBe('unchanged');
  });

  it('falls back to the JSON diff when a side is not an editable document', () => {
    const diff = diffDefinitions({ dslVersion: null, legacy: true }, BRIEF_EXAMPLE, TEST_CATALOG);
    expect(diff.rules).toEqual([]);
    expect(diff.policy).toEqual([]);
    expect(diff.json.some((l) => l.op === 'delete' && l.text.includes('"legacy"'))).toBe(true);
  });
});
