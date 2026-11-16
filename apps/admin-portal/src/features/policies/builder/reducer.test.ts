import { act, renderHook } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  changeLeafField,
  changeLeafOperator,
  defaultLeaf,
  fieldsFor,
  fieldsForAll,
  operatorsFor,
  whenPlacesOf,
} from './catalog';
import {
  buildDefinition,
  parseDefinition,
  type BuilderDefinition,
  type BuilderGroup,
  type BuilderNode,
} from './model';
import {
  builderReducer,
  canAddUnder,
  canWrap,
  locateNode,
  useBuilderState,
  type BuilderCommand,
} from './reducer';
import { TEST_CATALOG } from './test-support/catalog';
import { BRIEF_EXAMPLE } from './test-support/documents';

const LIMITS = TEST_CATALOG.limits;

function load(doc: unknown): BuilderDefinition {
  const parsed = parseDefinition(doc);
  if (!parsed.ok) throw new Error(parsed.reason);
  return parsed.model;
}
const doc = (state: BuilderDefinition) => buildDefinition(state).definition;
const run = (state: BuilderDefinition, ...commands: BuilderCommand[]) =>
  commands.reduce(builderReducer, state);
const rootOf = (state: BuilderDefinition, rule = 0): BuilderGroup => {
  const when = state.rules[rule]!.when;
  if (when.kind !== 'group') throw new Error('group expected');
  return when;
};
const leaf = (field: string, op: string, value?: unknown) => ({ field, op, value });

const base = () =>
  load({
    dslVersion: 'policy-dsl/1',
    direction: 'inbound',
    priority: 10,
    rules: [
      {
        id: 'r1',
        priority: 10,
        when: {
          all: [
            { field: 'auth.spf', op: 'equals', value: 'fail' },
            { field: 'urls.count', op: 'gt', value: 0 },
          ],
        },
        actions: [{ type: 'QUARANTINE' }, { type: 'ALERT', severity: 'info' }],
      },
      {
        id: 'r2',
        priority: 20,
        when: { field: 'auth.dkim', op: 'equals', value: 'fail' },
        actions: [{ type: 'TAG', label: 't' }],
      },
    ],
  });

describe('builderReducer: conditions and groups', () => {
  it('adds a condition to a group with the given key and content', () => {
    const state = base();
    const next = builderReducer(state, {
      type: 'add-condition',
      parentKey: rootOf(state).key,
      key: 'new-leaf',
      leaf: leaf('auth.dmarc', 'equals', 'fail'),
      limits: LIMITS,
    });
    expect(rootOf(next).children.map((c) => c.key)).toEqual([
      ...rootOf(state).children.map((c) => c.key),
      'new-leaf',
    ]);
    expect((doc(next).rules as Array<{ when: unknown }>)[0]!.when).toEqual({
      all: [
        leaf('auth.spf', 'equals', 'fail'),
        leaf('urls.count', 'gt', 0),
        leaf('auth.dmarc', 'equals', 'fail'),
      ],
    });
    // Untouched rules keep their identity (memoized cards do not re-render).
    expect(next.rules[1]).toBe(state.rules[1]);
  });

  it('wraps a non-group parent in an all group when adding beside it', () => {
    const state = base();
    const target = state.rules[1]!.when.key;
    const next = builderReducer(state, {
      type: 'add-condition',
      parentKey: target,
      key: 'k2',
      groupKey: 'g',
      limits: LIMITS,
    });
    expect((doc(next).rules as Array<{ when: unknown }>)[1]!.when).toEqual({
      all: [leaf('auth.dkim', 'equals', 'fail'), {}],
    });
    expect(next.rules[1]!.when.key).toBe('g');
  });

  it('adds a nested group (opposite joiner, one empty condition)', () => {
    const state = base();
    const next = builderReducer(state, {
      type: 'add-group',
      parentKey: rootOf(state).key,
      key: 'grp',
      childKey: 'grp-leaf',
      limits: LIMITS,
    });
    const added = rootOf(next).children[2] as BuilderGroup;
    expect(added).toMatchObject({ kind: 'group', key: 'grp', joiner: 'any' });
    expect(added.children).toEqual([{ kind: 'leaf', key: 'grp-leaf' }]);
  });

  it('removes nodes; removing the child of a NOT removes the NOT; the when root stays', () => {
    let state = base();
    const [first, second] = rootOf(state).children as [BuilderNode, BuilderNode];
    state = builderReducer(state, {
      type: 'toggle-not',
      key: second.key,
      notKey: 'not-1',
      limits: LIMITS,
    });
    expect(rootOf(state).children[1]).toMatchObject({ kind: 'not', key: 'not-1' });
    state = builderReducer(state, { type: 'remove-node', key: second.key });
    expect(rootOf(state).children.map((c) => c.key)).toEqual([first.key]);
    const root = rootOf(state).key;
    expect(builderReducer(state, { type: 'remove-node', key: root })).toBe(state);
    expect(builderReducer(state, { type: 'remove-node', key: 'missing' })).toBe(state);
  });

  it('moves conditions by array position within their group', () => {
    const state = base();
    const [a, b] = rootOf(state).children as [BuilderNode, BuilderNode];
    const next = builderReducer(state, { type: 'move-node', key: b.key, direction: 'up' });
    expect(rootOf(next).children.map((c) => c.key)).toEqual([b.key, a.key]);
    expect(builderReducer(next, { type: 'move-node', key: b.key, direction: 'up' })).toBe(next);
    expect(
      builderReducer(state, { type: 'move-node', key: rootOf(state).key, direction: 'down' }),
    ).toBe(state);
  });

  it('wraps in a group, toggles NOT on and off, and sets the joiner', () => {
    let state = base();
    const first = rootOf(state).children[0]!;
    state = run(
      state,
      { type: 'wrap-in-group', key: first.key, joiner: 'any', groupKey: 'w', limits: LIMITS },
      { type: 'toggle-not', key: 'w', notKey: 'n1', limits: LIMITS },
      { type: 'set-joiner', key: rootOf(state).key, joiner: 'any' },
    );
    expect((doc(state).rules as Array<{ when: unknown }>)[0]!.when).toEqual({
      any: [{ not: { any: [leaf('auth.spf', 'equals', 'fail')] } }, leaf('urls.count', 'gt', 0)],
    });
    state = builderReducer(state, { type: 'toggle-not', key: 'w' });
    expect(rootOf(state).children[0]).toMatchObject({ kind: 'group', key: 'w' });
    // NOT on a root wraps the root; toggling again unwraps it.
    const r2 = state.rules[1]!.when.key;
    const negated = builderReducer(state, {
      type: 'toggle-not',
      key: r2,
      notKey: 'rn',
      limits: LIMITS,
    });
    expect(negated.rules[1]!.when).toMatchObject({ kind: 'not', key: 'rn' });
    expect(builderReducer(negated, { type: 'toggle-not', key: r2 }).rules[1]!.when.key).toBe(r2);
  });

  it('replaces a leaf content on update-leaf (absent keys are removed)', () => {
    const state = base();
    const first = rootOf(state).children[0]!;
    const next = builderReducer(state, {
      type: 'update-leaf',
      key: first.key,
      leaf: { field: 'auth.dmarc', op: 'in', value: ['fail'] },
    });
    expect(rootOf(next).children[0]).toEqual({
      kind: 'leaf',
      key: first.key,
      field: 'auth.dmarc',
      op: 'in',
      value: ['fail'],
    });
    const cleared = builderReducer(next, { type: 'update-leaf', key: first.key, leaf: {} });
    expect(rootOf(cleared).children[0]).toEqual({ kind: 'leaf', key: first.key });
  });
});

describe('builderReducer: catalogue limits are honoured', () => {
  it('refuses a child above childrenPerGroup', () => {
    let state = base();
    const root = rootOf(state).key;
    const limits = { ...LIMITS, childrenPerGroup: 3 };
    state = builderReducer(state, { type: 'add-condition', parentKey: root, limits });
    expect(rootOf(state).children).toHaveLength(3);
    expect(builderReducer(state, { type: 'add-condition', parentKey: root, limits })).toBe(state);
    expect(canAddUnder(state, root, 'condition', limits)).toEqual({
      ok: false,
      reason: 'A group holds at most 3 conditions.',
    });
  });

  it('refuses nesting deeper than depth (root = 1)', () => {
    let state = base();
    const limits = { ...LIMITS, depth: 3 };
    state = builderReducer(state, {
      type: 'add-group',
      parentKey: rootOf(state).key,
      key: 'g2',
      childKey: 'l3',
      limits,
    });
    expect(locateNode(state, 'l3')!.depth).toBe(3);
    // A group under g2 would put its condition at depth 4.
    expect(builderReducer(state, { type: 'add-group', parentKey: 'g2', limits })).toBe(state);
    expect(builderReducer(state, { type: 'wrap-in-group', key: 'l3', limits })).toBe(state);
    expect(builderReducer(state, { type: 'toggle-not', key: 'l3', limits })).toBe(state);
    expect(canWrap(state, 'l3', limits).ok).toBe(false);
    // A plain condition at depth 3 still fits.
    expect(builderReducer(state, { type: 'add-condition', parentKey: 'g2', limits })).not.toBe(
      state,
    );
  });

  it('counts nodes of when and every unless against nodesPerRule', () => {
    let state = base();
    const limits = { ...LIMITS, nodesPerRule: 5 };
    const ruleKey = state.rules[0]!.key;
    state = builderReducer(state, {
      type: 'add-exception',
      ruleKey,
      key: 'u1',
      leaf: leaf('sender.trusted', 'is', true),
      limits,
    });
    // when: group + 2 leaves = 3, unless: 1 → 4 nodes.
    state = builderReducer(state, { type: 'add-condition', parentKey: rootOf(state).key, limits });
    expect(
      builderReducer(state, { type: 'add-condition', parentKey: rootOf(state).key, limits }),
    ).toBe(state);
    expect(builderReducer(state, { type: 'add-exception', ruleKey, limits })).toBe(state);
  });

  it('honours rulesPerPolicy, actionsPerRule, exceptionsPerRule and exceptionsPerPolicy', () => {
    const state = base();
    expect(
      builderReducer(state, { type: 'add-rule', limits: { ...LIMITS, rulesPerPolicy: 2 } }),
    ).toBe(state);
    const ruleKey = state.rules[0]!.key;
    expect(
      builderReducer(state, {
        type: 'add-action',
        ruleKey,
        actionType: 'ARCHIVE',
        limits: { ...LIMITS, actionsPerRule: 2 },
      }),
    ).toBe(state);
    const one = builderReducer(state, {
      type: 'add-exception',
      ruleKey,
      limits: { ...LIMITS, exceptionsPerRule: 1 },
    });
    expect(
      builderReducer(one, {
        type: 'add-exception',
        ruleKey,
        limits: { ...LIMITS, exceptionsPerRule: 1 },
      }),
    ).toBe(one);
    const p = builderReducer(state, {
      type: 'add-exception',
      ruleKey: null,
      limits: { ...LIMITS, exceptionsPerPolicy: 1 },
    });
    expect(
      builderReducer(p, {
        type: 'add-exception',
        ruleKey: null,
        limits: { ...LIMITS, exceptionsPerPolicy: 1 },
      }),
    ).toBe(p);
  });
});

describe('builderReducer: rules, actions, exceptions and the policy', () => {
  it('adds rules with unique ids and the next priority; ids stay unique after removals', () => {
    let state = base();
    state = run(
      state,
      { type: 'add-rule', key: 'n3', limits: LIMITS },
      { type: 'add-rule', key: 'n4', limits: LIMITS },
    );
    expect(state.rules.map((r) => [r.id, r.priority])).toEqual([
      ['r1', 10],
      ['r2', 20],
      ['rule-1', 30],
      ['rule-2', 40],
    ]);
    state = run(
      state,
      { type: 'remove-rule', ruleKey: 'n3' },
      { type: 'add-rule', key: 'n5', limits: LIMITS },
    );
    expect(state.rules.map((r) => r.id)).toEqual(['r1', 'r2', 'rule-2', 'rule-1']);
    expect(new Set(state.rules.map((r) => r.id)).size).toBe(state.rules.length);
  });

  it('moves rules by swapping priorities (the evaluation order), not array positions', () => {
    const state = base();
    const [r1, r2] = state.rules as [BuilderDefinition['rules'][0], BuilderDefinition['rules'][0]];
    const next = builderReducer(state, { type: 'move-rule', ruleKey: r2.key, direction: 'up' });
    expect(next.rules.map((r) => [r.id, r.priority])).toEqual([
      ['r1', 20],
      ['r2', 10],
    ]);
    expect(builderReducer(next, { type: 'move-rule', ruleKey: r2.key, direction: 'up' })).toBe(
      next,
    );
    expect(builderReducer(state, { type: 'move-rule', ruleKey: r1.key, direction: 'up' })).toBe(
      state,
    );
  });

  it('sets and unsets optional rule keys', () => {
    const state = base();
    const ruleKey = state.rules[0]!.key;
    const set = builderReducer(state, {
      type: 'update-rule',
      ruleKey,
      set: {
        id: 'renamed',
        description: 'Hold',
        enabled: false,
        directions: ['inbound'],
        stop: false,
        override: true,
      },
    });
    expect((doc(set).rules as unknown[])[0]).toMatchObject({
      id: 'renamed',
      description: 'Hold',
      enabled: false,
      directions: ['inbound'],
      stop: false,
      override: true,
    });
    const unset = builderReducer(set, {
      type: 'update-rule',
      ruleKey,
      unset: ['description', 'enabled', 'directions', 'stop', 'override'],
    });
    expect(Object.keys((doc(unset).rules as Array<Record<string, unknown>>)[0]!)).toEqual([
      'id',
      'priority',
      'when',
      'actions',
    ]);
  });

  it('adds, updates (set and unset parameters), moves and removes actions', () => {
    let state = base();
    const ruleKey = state.rules[0]!.key;
    state = run(
      state,
      {
        type: 'add-action',
        ruleKey,
        actionType: 'TAG',
        key: 'tag',
        params: { label: 'x' },
        limits: LIMITS,
      },
      {
        type: 'update-action',
        ruleKey,
        actionKey: 'tag',
        set: { subjectPrefix: '[X]', type: 'IGNORED' },
        unset: ['label'],
      },
      { type: 'move-action', ruleKey, actionKey: 'tag', direction: 'up' },
    );
    expect((doc(state).rules as Array<{ actions: unknown }>)[0]!.actions).toEqual([
      { type: 'QUARANTINE' },
      { type: 'TAG', subjectPrefix: '[X]' },
      { type: 'ALERT', severity: 'info' },
    ]);
    state = builderReducer(state, { type: 'remove-action', ruleKey, actionKey: 'tag' });
    expect(state.rules[0]!.actions.map((a) => a.type)).toEqual(['QUARANTINE', 'ALERT']);
  });

  it('adds and removes rule and policy-wide exceptions (an emptied list disappears)', () => {
    let state = base();
    const ruleKey = state.rules[0]!.key;
    state = run(
      state,
      {
        type: 'add-exception',
        ruleKey,
        key: 'u1',
        leaf: leaf('sender.trusted', 'is', true),
        limits: LIMITS,
      },
      { type: 'add-exception', ruleKey: null, key: 'p1', limits: LIMITS },
    );
    expect(doc(state).exceptions).toEqual([{}]);
    expect((doc(state).rules as Array<{ unless: unknown }>)[0]!.unless).toEqual([
      leaf('sender.trusted', 'is', true),
    ]);
    state = run(
      state,
      { type: 'remove-exception', ruleKey, key: 'u1' },
      { type: 'remove-node', key: 'p1' },
    );
    expect('exceptions' in doc(state)).toBe(false);
    expect('unless' in (doc(state).rules as Array<Record<string, unknown>>)[0]!).toBe(false);
  });

  it('sets the policy direction and priority, and replaces the model', () => {
    const state = base();
    const next = builderReducer(state, {
      type: 'set-policy',
      set: { direction: 'any', priority: 3 },
    });
    expect([next.direction, next.priority]).toEqual(['any', 3]);
    expect(builderReducer(next, { type: 'set-policy', set: { direction: 'any' } })).toBe(next);
    const other = load(BRIEF_EXAMPLE);
    expect(builderReducer(state, { type: 'replace', model: other })).toBe(other);
  });
});

describe('catalogue offering (fieldsFor, operatorsFor, defaultLeaf)', () => {
  it('offers fields by their catalogue contexts', () => {
    const names = (place: Parameters<typeof fieldsFor>[1]) =>
      fieldsFor(TEST_CATALOG, place).map((f) => f.name);
    expect(names('when')).toHaveLength(TEST_CATALOG.fields.length);
    expect(names('exception')).not.toContain('sender.envelope.domain');
    expect(names('exception')).not.toContain('bec.verdict');
    expect(names('exception')).toContain('sender.authenticated.domain');
    expect(names('relaxingWhen')).not.toContain('sender.header_from.address');
    expect(names('relaxingWhen')).toContain('bec.verdict');
    expect(names('holdRule')).not.toContain('bec.ai_raised');
    expect(
      fieldsForAll(TEST_CATALOG, ['when', 'relaxingWhen', 'holdRule']).map((f) => f.name),
    ).not.toContain('bec.verdict');
  });

  it('offers the field operators that have definitions; exceptions only allowedInException', () => {
    expect(operatorsFor(TEST_CATALOG, 'recipient.domain', 'when').map((o) => o.op)).toEqual([
      'equals',
      'in',
      'not_in',
      'domain_in',
      'glob',
      'regex',
    ]);
    expect(
      operatorsFor(TEST_CATALOG, 'recipient.domain', 'exception').map((o) => o.op),
    ).not.toContain('not_in');
    expect(operatorsFor(TEST_CATALOG, 'no.such.field', 'when')).toEqual([]);
  });

  it('derives the rule context from action dispositions and the override flag', () => {
    expect(whenPlacesOf(TEST_CATALOG, ['ALLOW', 'TAG'], undefined)).toEqual([
      'when',
      'relaxingWhen',
    ]);
    expect(whenPlacesOf(TEST_CATALOG, ['QUARANTINE'], true)).toEqual([
      'when',
      'relaxingWhen',
      'holdRule',
    ]);
    expect(whenPlacesOf(TEST_CATALOG, ['TAG', 'ALERT'], false)).toEqual(['when']);
  });

  it('creates default leaves (first operator, empty value of its shape, exception quantifier)', () => {
    expect(defaultLeaf(TEST_CATALOG, 'recipient.domain', 'when')).toMatchObject({
      field: 'recipient.domain',
      op: 'equals',
    });
    expect('value' in defaultLeaf(TEST_CATALOG, 'recipient.domain', 'when')).toBe(false);
    expect(defaultLeaf(TEST_CATALOG, 'dlp.categories', 'when')).toMatchObject({
      op: 'contains_any',
      value: [],
    });
    expect(defaultLeaf(TEST_CATALOG, 'recipient.department', 'exception')).toMatchObject({
      op: 'in',
      value: [],
      quantifier: 'all',
    });
    expect('quantifier' in defaultLeaf(TEST_CATALOG, 'recipient.department', 'when')).toBe(false);
  });

  it('resets operator and value on a field change; keeps the value only for the same shape', () => {
    const start = {
      kind: 'leaf' as const,
      key: 'x',
      field: 'recipient.domain',
      op: 'in',
      value: ['a.example'],
      quantifier: 'all',
    };
    expect(changeLeafField(TEST_CATALOG, start, 'auth.spf', 'when')).toEqual({
      kind: 'leaf',
      key: 'x',
      field: 'auth.spf',
      op: 'equals',
    });
    expect(changeLeafOperator(TEST_CATALOG, start, 'domain_in')).toEqual({
      ...start,
      op: 'domain_in',
    });
    expect(changeLeafOperator(TEST_CATALOG, start, 'equals')).toEqual({
      kind: 'leaf',
      key: 'x',
      field: 'recipient.domain',
      op: 'equals',
      quantifier: 'all',
    });
    expect(
      changeLeafOperator(TEST_CATALOG, { ...start, op: 'equals', value: 'a' }, 'glob'),
    ).toMatchObject({ op: 'glob', value: [] });
  });
});

describe('useBuilderState', () => {
  it('tracks dirtiness against a baseline by canonical JSON and resets it', () => {
    const initial = load(BRIEF_EXAMPLE);
    const { result } = renderHook(() => useBuilderState(initial));
    expect(result.current.isDirty).toBe(false);
    const ruleKey = result.current.state.rules[0]!.key;
    act(() => result.current.dispatch({ type: 'update-rule', ruleKey, set: { priority: 11 } }));
    expect(result.current.isDirty).toBe(true);
    act(() => result.current.dispatch({ type: 'update-rule', ruleKey, set: { priority: 10 } }));
    expect(result.current.isDirty).toBe(false);
    act(() =>
      result.current.dispatch({ type: 'update-rule', ruleKey, set: { description: 'Changed' } }),
    );
    const edited = result.current.state;
    act(() => result.current.resetBaseline(edited));
    expect(result.current.isDirty).toBe(false);
    expect(result.current.baseline).toBe(edited);
    // A re-parsed copy (new keys, same document) is not dirty either.
    const reparsed = load(buildDefinition(edited).definition);
    act(() => result.current.dispatch({ type: 'replace', model: reparsed }));
    expect(result.current.isDirty).toBe(false);
  });
});
