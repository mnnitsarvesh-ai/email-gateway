import { describe, expect, it } from 'vitest';
import {
  buildDefinition,
  canonicalJson,
  canonicalPrettyJson,
  documentBytes,
  emptyDefinition,
  nextRuleId,
  nextRulePriority,
  parseDefinition,
  type BuilderDefinition,
} from './model';
import { keyForPath } from './paths';
import { TEST_CATALOG } from './test-support/catalog';
import { BRIEF_EXAMPLE, docsPolicyBlocks } from './test-support/documents';
import { randomDocument, SeededRandom } from './test-support/random';

function roundTrip(doc: unknown): Record<string, unknown> {
  const parsed = parseDefinition(doc);
  if (!parsed.ok) throw new Error(`refused: ${parsed.reason} at ${parsed.path}`);
  return buildDefinition(parsed.model).definition;
}

function model(doc: unknown): BuilderDefinition {
  const parsed = parseDefinition(doc);
  if (!parsed.ok) throw new Error(`refused: ${parsed.reason} at ${parsed.path}`);
  return parsed.model;
}

describe('parseDefinition / buildDefinition: exact round trip (design B3)', () => {
  const blocks = docsPolicyBlocks();

  it('finds the policy JSON blocks of docs/architecture/policy-dsl.md', () => {
    // 12 worked examples + 2 split examples carry a dslVersion.
    expect(blocks.length).toBeGreaterThanOrEqual(14);
  });

  it.each(blocks.map((b) => [b.index, b.doc] as const))(
    'round-trips JSON block %i of the DSL reference exactly',
    (_index, doc) => {
      const built = roundTrip(doc);
      expect(built).toStrictEqual(doc);
      expect(canonicalJson(built)).toBe(canonicalJson(doc));
      // Idempotent: a second pass changes nothing.
      expect(roundTrip(built)).toStrictEqual(doc);
    },
  );

  it("round-trips the brief's example", () => {
    expect(roundTrip(BRIEF_EXAMPLE)).toStrictEqual(BRIEF_EXAMPLE);
  });

  it('round-trips 240 seeded random documents (values carried through unvalidated)', () => {
    const rng = new SeededRandom(7_302);
    for (let i = 0; i < 240; i += 1) {
      const doc = randomDocument(rng, TEST_CATALOG);
      const built = roundTrip(doc);
      expect(built, `document ${i}`).toStrictEqual(doc);
      expect(canonicalJson(built), `document ${i}`).toBe(canonicalJson(doc));
      expect(roundTrip(built), `document ${i} (second pass)`).toStrictEqual(doc);
    }
  });

  it('keeps optional-key presence: absent is not the default value', () => {
    const base = {
      dslVersion: 'policy-dsl/1',
      direction: 'inbound',
      priority: 1,
      rules: [
        {
          id: 'a',
          priority: 1,
          when: { field: 'auth.spf', op: 'equals', value: 'fail' },
          actions: [{ type: 'TAG', label: 'x' }],
        },
        {
          id: 'b',
          priority: 2,
          enabled: true,
          when: { all: [] },
          unless: [],
          actions: [{ type: 'TAG', label: 'x', addHeader: true }],
          stop: false,
          override: false,
        },
      ],
      exceptions: [],
    };
    const built = roundTrip(base);
    expect(built).toStrictEqual(base);
    const rules = built.rules as Array<Record<string, unknown>>;
    expect('enabled' in rules[0]!).toBe(false);
    expect('unless' in rules[0]!).toBe(false);
    expect(rules[1]!.unless).toEqual([]);
    expect(rules[1]!.enabled).toBe(true);
    const actions = rules[0]!.actions as Array<Record<string, unknown>>;
    expect('addHeader' in actions[0]!).toBe(false);
    expect(built.exceptions).toEqual([]);
    const without = { ...base } as Record<string, unknown>;
    delete without.exceptions;
    expect('exceptions' in roundTrip(without)).toBe(false);
  });

  it('keeps NOT as a node of its own (nested NOTs survive)', () => {
    const doc = {
      dslVersion: 'policy-dsl/1',
      direction: 'any',
      priority: 5,
      rules: [
        {
          id: 'r',
          priority: 0,
          when: { not: { not: { any: [{ not: { field: 'urls.count', op: 'gt', value: 0 } }] } } },
          actions: [{ type: 'ARCHIVE' }],
        },
      ],
    };
    expect(roundTrip(doc)).toStrictEqual(doc);
    const when = model(doc).rules[0]!.when;
    expect(when.kind).toBe('not');
    expect(when.kind === 'not' && when.child.kind).toBe('not');
  });

  it('copies values (the model never aliases the input document)', () => {
    const doc = structuredClone(BRIEF_EXAMPLE);
    const parsed = model(doc);
    doc.rules[0]!.when.all[0]!.value.push('mutated');
    expect(buildDefinition(parsed).definition).toStrictEqual(BRIEF_EXAMPLE);
  });
});

describe('parseDefinition refusals', () => {
  const valid = () => structuredClone(BRIEF_EXAMPLE) as unknown as Record<string, unknown>;

  it('refuses non-objects', () => {
    for (const doc of [null, undefined, 'x', 5, [], [BRIEF_EXAMPLE]]) {
      expect(parseDefinition(doc)).toEqual({ ok: false, reason: 'not_object', path: '' });
    }
  });

  it('refuses other DSL versions, including legacy null rows', () => {
    for (const dslVersion of [null, undefined, 'policy-dsl/2', 1]) {
      const doc = { ...valid(), dslVersion };
      expect(parseDefinition(doc)).toEqual({
        ok: false,
        reason: 'unsupported_version',
        path: 'dslVersion',
      });
    }
  });

  it('refuses unknown keys anywhere with their path (never drops them)', () => {
    const cases: Array<[(doc: Record<string, unknown>) => void, string]> = [
      [(d) => (d.extra = 1), 'extra'],
      [(d) => ((d.rules as Array<Record<string, unknown>>)[0]!.name = 'x'), 'rules[0].name'],
      [
        (d) =>
          (((d.rules as Array<Record<string, unknown>>)[0]!.when as Record<string, unknown>).field =
            'x'),
        'rules[0].when.field',
      ],
      [
        (d) => {
          const when = (d.rules as Array<Record<string, unknown>>)[0]!.when as {
            all: Array<Record<string, unknown>>;
          };
          when.all[0]!.negate = true;
        },
        'rules[0].when.all[0].negate',
      ],
      [
        (d) => ((d.rules as Array<Record<string, unknown>>)[0]!.unless = [{ not: {}, field: 'x' }]),
        'rules[0].unless[0].field',
      ],
    ];
    for (const [mutate, path] of cases) {
      const doc = valid();
      mutate(doc);
      expect(parseDefinition(doc), path).toEqual({ ok: false, reason: 'unknown_key', path });
    }
  });

  it('refuses unknown keys in seeded random documents at the planted path', () => {
    const rng = new SeededRandom(99);
    for (let i = 0; i < 50; i += 1) {
      const doc = randomDocument(rng, TEST_CATALOG);
      const rules = doc.rules as Array<Record<string, unknown>>;
      const r = rng.int(rules.length);
      rules[r]!.bogus = i;
      expect(parseDefinition(doc)).toEqual({
        ok: false,
        reason: 'unknown_key',
        path: `rules[${r}].bogus`,
      });
    }
  });

  it('refuses structural values of the wrong JSON type as malformed', () => {
    const cases: Array<[(doc: Record<string, unknown>) => void, string]> = [
      [(d) => (d.rules = {}), 'rules'],
      [(d) => (d.priority = '10'), 'priority'],
      [(d) => delete d.direction, 'direction'],
      [(d) => ((d.rules as unknown[])[0] = 'rule'), 'rules[0]'],
      [(d) => delete (d.rules as Array<Record<string, unknown>>)[0]!.when, 'rules[0].when'],
      [
        (d) => ((d.rules as Array<Record<string, unknown>>)[0]!.actions = [{ severity: 'x' }]),
        'rules[0].actions[0].type',
      ],
      [
        (d) => ((d.rules as Array<Record<string, unknown>>)[0]!.when = { all: [], any: [] }),
        'rules[0].when',
      ],
      [
        (d) => ((d.rules as Array<Record<string, unknown>>)[0]!.enabled = 'yes'),
        'rules[0].enabled',
      ],
      [
        (d) => ((d.rules as Array<Record<string, unknown>>)[0]!.directions = ['inbound', 3]),
        'rules[0].directions[1]',
      ],
      [(d) => (d.exceptions = [{ field: 1 }]), 'exceptions[0].field'],
    ];
    for (const [mutate, path] of cases) {
      const doc = valid();
      mutate(doc);
      expect(parseDefinition(doc), path).toEqual({ ok: false, reason: 'malformed', path });
    }
  });
});

describe('path index', () => {
  it('indexes rules, nodes, actions and policy exceptions by DSL path', () => {
    const doc = {
      dslVersion: 'policy-dsl/1',
      direction: 'inbound',
      priority: 1,
      rules: [
        {
          id: 'r1',
          priority: 1,
          when: {
            all: [
              { field: 'auth.spf', op: 'equals', value: 'fail' },
              { not: { field: 'urls.count', op: 'gt', value: 0 } },
            ],
          },
          unless: [{ field: 'sender.trusted', op: 'is', value: true }],
          actions: [{ type: 'QUARANTINE' }, { type: 'ALERT', severity: 'info' }],
        },
      ],
      exceptions: [{ field: 'sender.department', op: 'in', value: [] }],
    };
    const m = model(doc);
    const { paths } = buildDefinition(m);
    const rule = m.rules[0]!;
    const root = rule.when;
    if (root.kind !== 'group') throw new Error('group expected');
    const not = root.children[1]!;
    if (not.kind !== 'not') throw new Error('not expected');
    expect(keyForPath(paths, 'rules[0]')).toBe(rule.key);
    expect(keyForPath(paths, 'rules[0].when')).toBe(root.key);
    expect(keyForPath(paths, 'rules[0].when.all[0].value')).toBe(root.children[0]!.key);
    expect(keyForPath(paths, 'rules[0].when.all[1]')).toBe(not.key);
    expect(keyForPath(paths, 'rules[0].when.all[1].not.value[3]')).toBe(not.child.key);
    expect(keyForPath(paths, 'rules[0].unless[0].field')).toBe(rule.unless![0]!.key);
    expect(keyForPath(paths, 'rules[0].actions[1].severity')).toBe(rule.actions[1]!.key);
    expect(keyForPath(paths, 'rules[0].actions')).toBe(rule.key);
    expect(keyForPath(paths, 'rules[0].id')).toBe(rule.key);
    expect(keyForPath(paths, 'exceptions[0].value')).toBe(m.exceptions![0]!.key);
    for (const policyLevel of ['', 'direction', 'priority', 'rules', 'exceptions', 'rules[7].id']) {
      expect(keyForPath(paths, policyLevel), policyLevel).toBeNull();
    }
    expect(paths.pathByKey.get(not.child.key)).toBe('rules[0].when.all[1].not');
  });
});

describe('canonical JSON and size', () => {
  it('sorts keys recursively and matches JSON.stringify of a sorted copy', () => {
    const value = { b: [{ z: 1, a: { y: null, x: 'é' } }], a: true, c: undefined };
    expect(canonicalJson(value)).toBe('{"a":true,"b":[{"a":{"x":"é","y":null},"z":1}]}');
    expect(canonicalPrettyJson(value)).toBe(
      JSON.stringify({ a: true, b: [{ a: { x: 'é', y: null }, z: 1 }] }, null, 2),
    );
    expect(canonicalJson([])).toBe('[]');
    expect(canonicalPrettyJson({ a: [], b: {} })).toBe('{\n  "a": [],\n  "b": {}\n}');
  });

  it('measures the UTF-8 size of the canonical JSON', () => {
    expect(documentBytes({ a: 'é' })).toBe('{"a":"é"}'.length + 1);
    expect(documentBytes(BRIEF_EXAMPLE)).toBe(
      new TextEncoder().encode(JSON.stringify(BRIEF_EXAMPLE)).length,
    );
  });
});

describe('new documents, rule ids and priorities', () => {
  it('starts with one rule, one empty condition and no action', () => {
    const empty = emptyDefinition('outbound');
    expect(empty.direction).toBe('outbound');
    expect(emptyDefinition().direction).toBe('any');
    const { definition } = buildDefinition(empty);
    expect(definition).toEqual({
      dslVersion: 'policy-dsl/1',
      direction: 'outbound',
      priority: 100,
      rules: [{ id: 'rule-1', priority: 0, when: { all: [{}] }, actions: [] }],
    });
    // The empty document is itself editable (round trip).
    expect(roundTrip(definition)).toStrictEqual(definition);
  });

  it('gives new rules the smallest free rule-<n> id and the highest priority + 10', () => {
    expect(nextRuleId([])).toBe('rule-1');
    expect(nextRuleId([{ id: 'rule-1' }, { id: 'rule-3' }])).toBe('rule-2');
    expect(nextRuleId([{ id: 'rule-1' }, { id: 'rule-2' }])).toBe('rule-3');
    expect(nextRulePriority([])).toBe(0);
    expect(nextRulePriority([{ priority: 40 }, { priority: 5 }])).toBe(50);
  });
});
