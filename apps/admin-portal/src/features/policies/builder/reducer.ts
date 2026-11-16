'use client';

import { useCallback, useMemo, useReducer, useState } from 'react';
import { limitOf } from './catalog';
import {
  buildDefinition,
  canonicalJson,
  emptyLeaf,
  newKey,
  newRule,
  rulesByPriority,
  type BuilderAction,
  type BuilderDefinition,
  type BuilderGroup,
  type BuilderLeaf,
  type BuilderNode,
  type BuilderRule,
  type PolicyDirection,
} from './model';

/**
 * Editor commands (design §4.7). The reducer is pure and needs no catalogue: commands that grow
 * the document carry the catalogue `limits`, and the reducer refuses (returns the state
 * unchanged) any change above them. Node, rule and action keys of new elements may be passed in
 * by the caller, which can then move the focus to the new element after the render.
 */

export type BuilderLimits = Readonly<Record<string, number>>;
export type MoveDirection = 'up' | 'down';
/** The content of a leaf (everything but `kind` and `key`). */
export type LeafContent = Omit<BuilderLeaf, 'kind' | 'key'>;
type RuleSettable = Pick<
  BuilderRule,
  'id' | 'priority' | 'description' | 'enabled' | 'directions' | 'stop' | 'override'
>;
export type RuleOptionalKey = 'description' | 'enabled' | 'directions' | 'stop' | 'override';

export type BuilderCommand =
  | {
      type: 'add-condition';
      /** A group gets a new last child; any other node is wrapped in an `all` group first. */
      parentKey: string;
      key?: string;
      groupKey?: string;
      leaf?: LeafContent;
      limits?: BuilderLimits;
    }
  | {
      type: 'add-group';
      parentKey: string;
      /** Default: the opposite of the parent group's joiner (`any` when a leaf is wrapped). */
      joiner?: 'all' | 'any';
      key?: string;
      childKey?: string;
      wrapKey?: string;
      limits?: BuilderLimits;
    }
  | { type: 'remove-node'; key: string }
  | { type: 'move-node'; key: string; direction: MoveDirection }
  | {
      type: 'wrap-in-group';
      key: string;
      joiner?: 'all' | 'any';
      groupKey?: string;
      limits?: BuilderLimits;
    }
  | { type: 'toggle-not'; key: string; notKey?: string; limits?: BuilderLimits }
  | { type: 'set-joiner'; key: string; joiner: 'all' | 'any' }
  | { type: 'update-leaf'; key: string; leaf: LeafContent }
  | {
      type: 'add-rule';
      key?: string;
      groupKey?: string;
      leafKey?: string;
      limits?: BuilderLimits;
    }
  | { type: 'remove-rule'; ruleKey: string }
  | { type: 'move-rule'; ruleKey: string; direction: MoveDirection }
  | {
      type: 'update-rule';
      ruleKey: string;
      set?: Partial<RuleSettable>;
      unset?: readonly RuleOptionalKey[];
    }
  | {
      type: 'add-action';
      ruleKey: string;
      actionType: string;
      key?: string;
      params?: Record<string, unknown>;
      limits?: BuilderLimits;
    }
  | { type: 'remove-action'; ruleKey: string; actionKey: string }
  | {
      type: 'update-action';
      ruleKey: string;
      actionKey: string;
      set?: Record<string, unknown>;
      unset?: readonly string[];
    }
  | { type: 'move-action'; ruleKey: string; actionKey: string; direction: MoveDirection }
  | {
      type: 'add-exception';
      /** `null` = a policy-wide exception. */
      ruleKey: string | null;
      key?: string;
      leaf?: LeafContent;
      limits?: BuilderLimits;
    }
  | { type: 'remove-exception'; ruleKey: string | null; key: string }
  | {
      type: 'set-policy';
      set: { direction?: PolicyDirection; priority?: number };
    }
  | { type: 'replace'; model: BuilderDefinition };

// ---------------------------------------------------------------------------------------------
// Tree helpers
// ---------------------------------------------------------------------------------------------

/** Where a tree lives: a rule's `when`, one of its `unless` entries, or a policy exception. */
export type TreeRef =
  | { kind: 'when'; ruleKey: string }
  | { kind: 'unless'; ruleKey: string; index: number }
  | { kind: 'exceptions'; index: number };

export interface LocatedNode {
  readonly node: BuilderNode;
  readonly tree: TreeRef;
  readonly root: BuilderNode;
  /** Root = 1. */
  readonly depth: number;
  readonly parent: BuilderNode | null;
  /** Position in the parent group (0 for a `not` child or a root). */
  readonly index: number;
}

function* walk(
  node: BuilderNode,
  depth: number,
  parent: BuilderNode | null,
  index: number,
): Generator<{ node: BuilderNode; depth: number; parent: BuilderNode | null; index: number }> {
  yield { node, depth, parent, index };
  if (node.kind === 'group') {
    for (let i = 0; i < node.children.length; i += 1) {
      yield* walk(node.children[i]!, depth + 1, node, i);
    }
  } else if (node.kind === 'not') {
    yield* walk(node.child, depth + 1, node, 0);
  }
}

function* trees(state: BuilderDefinition): Generator<{ root: BuilderNode; tree: TreeRef }> {
  for (const rule of state.rules) {
    yield { root: rule.when, tree: { kind: 'when', ruleKey: rule.key } };
    const unless = rule.unless ?? [];
    for (let i = 0; i < unless.length; i += 1) {
      yield { root: unless[i]!, tree: { kind: 'unless', ruleKey: rule.key, index: i } };
    }
  }
  const exceptions = state.exceptions ?? [];
  for (let i = 0; i < exceptions.length; i += 1) {
    yield { root: exceptions[i]!, tree: { kind: 'exceptions', index: i } };
  }
}

/** Finds a node anywhere in the document. */
export function locateNode(state: BuilderDefinition, key: string): LocatedNode | null {
  for (const { root, tree } of trees(state)) {
    for (const item of walk(root, 1, null, 0)) {
      if (item.node.key === key) return { ...item, tree, root };
    }
  }
  return null;
}

export function countNodes(node: BuilderNode): number {
  return [...walk(node, 1, null, 0)].length;
}

/** Depth of the deepest node of a subtree, the subtree root counting 1. */
export function subtreeDepth(node: BuilderNode): number {
  let max = 0;
  for (const item of walk(node, 1, null, 0)) max = Math.max(max, item.depth);
  return max;
}

/** Nodes counted against `nodesPerRule` (when + every unless) or `nodesPerPolicyExceptions`. */
export function nodeBudgetOf(
  state: BuilderDefinition,
  tree: TreeRef,
): { used: number; limitName: 'nodesPerRule' | 'nodesPerPolicyExceptions' } {
  if (tree.kind === 'exceptions') {
    return {
      used: (state.exceptions ?? []).reduce((sum, node) => sum + countNodes(node), 0),
      limitName: 'nodesPerPolicyExceptions',
    };
  }
  const rule = state.rules.find((r) => r.key === tree.ruleKey);
  const used = rule
    ? countNodes(rule.when) + (rule.unless ?? []).reduce((sum, node) => sum + countNodes(node), 0)
    : 0;
  return { used, limitName: 'nodesPerRule' };
}

function editNode(
  node: BuilderNode,
  key: string,
  edit: (node: BuilderNode) => BuilderNode,
): BuilderNode {
  if (node.key === key) return edit(node);
  if (node.kind === 'group') {
    let changed = false;
    const children = node.children.map((child) => {
      const next = editNode(child, key, edit);
      if (next !== child) changed = true;
      return next;
    });
    return changed ? { ...node, children } : node;
  }
  if (node.kind === 'not') {
    const child = editNode(node.child, key, edit);
    return child === node.child ? node : { ...node, child };
  }
  return node;
}

function editList(
  nodes: BuilderNode[] | undefined,
  key: string,
  edit: (node: BuilderNode) => BuilderNode,
): BuilderNode[] | undefined {
  if (nodes === undefined) return undefined;
  let changed = false;
  const out = nodes.map((node) => {
    const next = editNode(node, key, edit);
    if (next !== node) changed = true;
    return next;
  });
  return changed ? out : nodes;
}

/** Applies `edit` to the node with `key` wherever it is (structural sharing elsewhere). */
function editInState(
  state: BuilderDefinition,
  key: string,
  edit: (node: BuilderNode) => BuilderNode,
): BuilderDefinition {
  let changed = false;
  const rules = state.rules.map((rule) => {
    const when = editNode(rule.when, key, edit);
    const unless = editList(rule.unless, key, edit);
    if (when === rule.when && unless === rule.unless) return rule;
    changed = true;
    const next: BuilderRule = { ...rule, when };
    if (unless !== undefined) next.unless = unless;
    return next;
  });
  const exceptions = editList(state.exceptions, key, edit);
  if (!changed && exceptions === state.exceptions) return state;
  const next: BuilderDefinition = { ...state, rules };
  if (exceptions !== undefined) next.exceptions = exceptions;
  return next;
}

function updateRule(
  state: BuilderDefinition,
  ruleKey: string,
  edit: (rule: BuilderRule) => BuilderRule,
): BuilderDefinition {
  let changed = false;
  const rules = state.rules.map((rule) => {
    if (rule.key !== ruleKey) return rule;
    const next = edit(rule);
    if (next !== rule) changed = true;
    return next;
  });
  return changed ? { ...state, rules } : state;
}

function setList(
  state: BuilderDefinition,
  ruleKey: string | null,
  edit: (nodes: BuilderNode[] | undefined) => BuilderNode[] | undefined,
): BuilderDefinition {
  if (ruleKey === null) {
    const nodes = edit(state.exceptions);
    if (nodes === state.exceptions) return state;
    const { exceptions: _drop, ...rest } = state;
    return nodes === undefined ? rest : { ...rest, exceptions: nodes };
  }
  return updateRule(state, ruleKey, (rule) => {
    const nodes = edit(rule.unless);
    if (nodes === rule.unless) return rule;
    const { unless: _drop, ...rest } = rule;
    return nodes === undefined ? rest : { ...rest, unless: nodes };
  });
}

function swap<T>(items: readonly T[], i: number, j: number): T[] {
  const out = [...items];
  const a = out[i]!;
  out[i] = out[j]!;
  out[j] = a;
  return out;
}

const otherJoiner = (joiner: 'all' | 'any'): 'all' | 'any' => (joiner === 'all' ? 'any' : 'all');

// ---------------------------------------------------------------------------------------------
// Limit checks (shared with the UI, which disables the control and says why)
// ---------------------------------------------------------------------------------------------

export interface Capability {
  readonly ok: boolean;
  readonly reason?: string;
}

const OK: Capability = { ok: true };

/**
 * Whether `added` new nodes can go below `parentKey` (a group gains one child; another node is
 * wrapped in a new group first). `depthBelow` = levels the new content adds under the parent.
 */
export function canAddUnder(
  state: BuilderDefinition,
  parentKey: string,
  content: 'condition' | 'group',
  limits: BuilderLimits | undefined,
): Capability {
  const located = locateNode(state, parentKey);
  if (!located) return { ok: false, reason: 'The condition no longer exists.' };
  const isGroup = located.node.kind === 'group';
  const newNodes = (content === 'group' ? 2 : 1) + (isGroup ? 0 : 1);
  const childDepth = located.depth + 1;
  const deepest = isGroup
    ? childDepth + (content === 'group' ? 1 : 0)
    : Math.max(
        located.depth + subtreeDepth(located.node),
        childDepth + (content === 'group' ? 1 : 0),
      );
  if (isGroup && located.node.kind === 'group') {
    const max = limitOf(limits, 'childrenPerGroup');
    if (located.node.children.length >= max) {
      return { ok: false, reason: `A group holds at most ${max} conditions.` };
    }
  }
  const depthLimit = limitOf(limits, 'depth');
  if (deepest > depthLimit) {
    return { ok: false, reason: `Conditions nest at most ${depthLimit} levels deep.` };
  }
  return nodeBudget(state, located.tree, newNodes, limits);
}

function nodeBudget(
  state: BuilderDefinition,
  tree: TreeRef,
  added: number,
  limits: BuilderLimits | undefined,
): Capability {
  const { used, limitName } = nodeBudgetOf(state, tree);
  const max = limitOf(limits, limitName);
  if (used + added > max) {
    return {
      ok: false,
      reason:
        limitName === 'nodesPerRule'
          ? `A rule holds at most ${max} conditions and groups (exceptions included).`
          : `Policy-wide exceptions hold at most ${max} conditions and groups.`,
    };
  }
  return OK;
}

/** Whether a node can be wrapped (in a group or a NOT): one more node, one more level. */
export function canWrap(
  state: BuilderDefinition,
  key: string,
  limits: BuilderLimits | undefined,
): Capability {
  const located = locateNode(state, key);
  if (!located) return { ok: false, reason: 'The condition no longer exists.' };
  const depthLimit = limitOf(limits, 'depth');
  if (located.depth + subtreeDepth(located.node) > depthLimit) {
    return { ok: false, reason: `Conditions nest at most ${depthLimit} levels deep.` };
  }
  return nodeBudget(state, located.tree, 1, limits);
}

export function canAddRule(
  state: BuilderDefinition,
  limits: BuilderLimits | undefined,
): Capability {
  const max = limitOf(limits, 'rulesPerPolicy');
  return state.rules.length >= max
    ? { ok: false, reason: `A policy holds at most ${max} rules.` }
    : OK;
}

export function canAddAction(
  rule: Pick<BuilderRule, 'actions'>,
  limits: BuilderLimits | undefined,
): Capability {
  const max = limitOf(limits, 'actionsPerRule');
  return rule.actions.length >= max
    ? { ok: false, reason: `A rule holds at most ${max} actions.` }
    : OK;
}

export function canAddException(
  state: BuilderDefinition,
  ruleKey: string | null,
  limits: BuilderLimits | undefined,
): Capability {
  if (ruleKey === null) {
    const max = limitOf(limits, 'exceptionsPerPolicy');
    if ((state.exceptions ?? []).length >= max) {
      return { ok: false, reason: `A policy holds at most ${max} policy-wide exceptions.` };
    }
    return nodeBudget(state, { kind: 'exceptions', index: 0 }, 1, limits);
  }
  const rule = state.rules.find((r) => r.key === ruleKey);
  if (!rule) return { ok: false, reason: 'The rule no longer exists.' };
  const max = limitOf(limits, 'exceptionsPerRule');
  if ((rule.unless ?? []).length >= max) {
    return { ok: false, reason: `A rule holds at most ${max} exceptions.` };
  }
  return nodeBudget(state, { kind: 'when', ruleKey }, 1, limits);
}

// ---------------------------------------------------------------------------------------------
// The reducer
// ---------------------------------------------------------------------------------------------

function leafOf(key: string, content: LeafContent | undefined): BuilderLeaf {
  const leaf: BuilderLeaf = { kind: 'leaf', key };
  if (content?.field !== undefined) leaf.field = content.field;
  if (content?.op !== undefined) leaf.op = content.op;
  if (content?.value !== undefined) leaf.value = content.value;
  if (content?.quantifier !== undefined) leaf.quantifier = content.quantifier;
  return leaf;
}

function removeNode(state: BuilderDefinition, key: string): BuilderDefinition {
  const located = locateNode(state, key);
  if (!located) return state;
  const { parent, tree } = located;
  if (parent === null) {
    // A tree root: exceptions and policy-wide exceptions are list entries; `when` is required.
    if (tree.kind === 'when') return state;
    return removeException(state, tree.kind === 'unless' ? tree.ruleKey : null, key);
  }
  // Removing the only child of a NOT removes the NOT.
  if (parent.kind === 'not') return removeNode(state, parent.key);
  return editInState(state, parent.key, (group) =>
    group.kind === 'group'
      ? { ...group, children: group.children.filter((child) => child.key !== key) }
      : group,
  );
}

function removeException(
  state: BuilderDefinition,
  ruleKey: string | null,
  key: string,
): BuilderDefinition {
  return setList(state, ruleKey, (nodes) => {
    if (!nodes?.some((node) => node.key === key)) return nodes;
    const rest = nodes.filter((node) => node.key !== key);
    return rest.length === 0 ? undefined : rest;
  });
}

function moveNode(
  state: BuilderDefinition,
  key: string,
  direction: MoveDirection,
): BuilderDefinition {
  const located = locateNode(state, key);
  if (!located) return state;
  const delta = direction === 'up' ? -1 : 1;
  if (located.parent === null) {
    if (located.tree.kind === 'when') return state;
    const ruleKey = located.tree.kind === 'unless' ? located.tree.ruleKey : null;
    return setList(state, ruleKey, (nodes) => {
      if (!nodes) return nodes;
      const i = nodes.findIndex((node) => node.key === key);
      const j = i + delta;
      return i < 0 || j < 0 || j >= nodes.length ? nodes : swap(nodes, i, j);
    });
  }
  if (located.parent.kind !== 'group') return state;
  const group = located.parent;
  const i = located.index;
  const j = i + delta;
  if (j < 0 || j >= group.children.length) return state;
  return editInState(state, group.key, (node) =>
    node.kind === 'group' ? { ...node, children: swap(node.children, i, j) } : node,
  );
}

function addUnder(
  state: BuilderDefinition,
  parentKey: string,
  content: 'condition' | 'group',
  child: BuilderNode,
  wrapKey: string | undefined,
  limits: BuilderLimits | undefined,
): BuilderDefinition {
  if (!canAddUnder(state, parentKey, content, limits).ok) return state;
  return editInState(state, parentKey, (node) => {
    if (node.kind === 'group') return { ...node, children: [...node.children, child] };
    const wrapper: BuilderGroup = {
      kind: 'group',
      key: wrapKey ?? newKey('n'),
      joiner: 'all',
      children: [node, child],
    };
    return wrapper;
  });
}

function reduceRule(state: BuilderDefinition, command: BuilderCommand): BuilderDefinition {
  switch (command.type) {
    case 'add-rule': {
      if (!canAddRule(state, command.limits).ok) return state;
      const rule = newRule(state.rules, {
        key: command.key,
        groupKey: command.groupKey,
        leafKey: command.leafKey,
      });
      return { ...state, rules: [...state.rules, rule] };
    }
    case 'remove-rule': {
      const rules = state.rules.filter((rule) => rule.key !== command.ruleKey);
      return rules.length === state.rules.length ? state : { ...state, rules };
    }
    case 'move-rule': {
      const ordered = rulesByPriority(state.rules);
      const i = ordered.findIndex((rule) => rule.key === command.ruleKey);
      const j = i + (command.direction === 'up' ? -1 : 1);
      if (i < 0 || j < 0 || j >= ordered.length) return state;
      const a = ordered[i]!;
      const b = ordered[j]!;
      // Evaluation order is the priority, not the array order: swap the two priorities.
      return {
        ...state,
        rules: state.rules.map((rule) =>
          rule.key === a.key
            ? { ...rule, priority: b.priority }
            : rule.key === b.key
              ? { ...rule, priority: a.priority }
              : rule,
        ),
      };
    }
    case 'update-rule':
      return updateRule(state, command.ruleKey, (rule) => {
        const next: BuilderRule = { ...rule };
        for (const key of command.unset ?? []) delete next[key];
        if (command.set) {
          for (const [key, value] of Object.entries(command.set) as Array<
            [keyof RuleSettable, RuleSettable[keyof RuleSettable]]
          >) {
            if (value !== undefined) (next as unknown as Record<string, unknown>)[key] = value;
          }
        }
        return next;
      });
    default:
      return state;
  }
}

function reduceAction(state: BuilderDefinition, command: BuilderCommand): BuilderDefinition {
  switch (command.type) {
    case 'add-action':
      return updateRule(state, command.ruleKey, (rule) => {
        if (!canAddAction(rule, command.limits).ok) return rule;
        const action: BuilderAction = {
          key: command.key ?? newKey('a'),
          type: command.actionType,
          params: { ...(command.params ?? {}) },
        };
        return { ...rule, actions: [...rule.actions, action] };
      });
    case 'remove-action':
      return updateRule(state, command.ruleKey, (rule) => {
        const actions = rule.actions.filter((action) => action.key !== command.actionKey);
        return actions.length === rule.actions.length ? rule : { ...rule, actions };
      });
    case 'update-action':
      return updateRule(state, command.ruleKey, (rule) => {
        let changed = false;
        const actions = rule.actions.map((action) => {
          if (action.key !== command.actionKey) return action;
          changed = true;
          const params = { ...action.params };
          for (const name of command.unset ?? []) delete params[name];
          for (const [name, value] of Object.entries(command.set ?? {})) {
            if (name !== 'type' && value !== undefined) params[name] = value;
          }
          return { ...action, params };
        });
        return changed ? { ...rule, actions } : rule;
      });
    case 'move-action':
      return updateRule(state, command.ruleKey, (rule) => {
        const i = rule.actions.findIndex((action) => action.key === command.actionKey);
        const j = i + (command.direction === 'up' ? -1 : 1);
        if (i < 0 || j < 0 || j >= rule.actions.length) return rule;
        return { ...rule, actions: swap(rule.actions, i, j) };
      });
    default:
      return state;
  }
}

/** The builder's state transitions (pure; invalid targets and limits leave the state as is). */
export function builderReducer(
  state: BuilderDefinition,
  command: BuilderCommand,
): BuilderDefinition {
  switch (command.type) {
    case 'add-condition':
      return addUnder(
        state,
        command.parentKey,
        'condition',
        leafOf(command.key ?? newKey('n'), command.leaf),
        command.groupKey,
        command.limits,
      );
    case 'add-group': {
      const parent = locateNode(state, command.parentKey);
      if (!parent) return state;
      const joiner =
        command.joiner ?? (parent.node.kind === 'group' ? otherJoiner(parent.node.joiner) : 'any');
      const group: BuilderGroup = {
        kind: 'group',
        key: command.key ?? newKey('n'),
        joiner,
        children: [emptyLeaf(command.childKey)],
      };
      return addUnder(state, command.parentKey, 'group', group, command.wrapKey, command.limits);
    }
    case 'remove-node':
      return removeNode(state, command.key);
    case 'move-node':
      return moveNode(state, command.key, command.direction);
    case 'wrap-in-group':
      if (!canWrap(state, command.key, command.limits).ok) return state;
      return editInState(state, command.key, (node) => ({
        kind: 'group',
        key: command.groupKey ?? newKey('n'),
        joiner: command.joiner ?? 'all',
        children: [node],
      }));
    case 'toggle-not': {
      const located = locateNode(state, command.key);
      if (!located) return state;
      if (located.parent?.kind === 'not') {
        const notKey = located.parent.key;
        return editInState(state, notKey, (node) => (node.kind === 'not' ? node.child : node));
      }
      if (!canWrap(state, command.key, command.limits).ok) return state;
      return editInState(state, command.key, (node) => ({
        kind: 'not',
        key: command.notKey ?? newKey('n'),
        child: node,
      }));
    }
    case 'set-joiner':
      return editInState(state, command.key, (node) =>
        node.kind === 'group' && node.joiner !== command.joiner
          ? { ...node, joiner: command.joiner }
          : node,
      );
    case 'update-leaf':
      return editInState(state, command.key, (node) =>
        node.kind === 'leaf' ? leafOf(node.key, command.leaf) : node,
      );
    case 'add-exception': {
      if (!canAddException(state, command.ruleKey, command.limits).ok) return state;
      const leaf = leafOf(command.key ?? newKey('n'), command.leaf);
      return setList(state, command.ruleKey, (nodes) => [...(nodes ?? []), leaf]);
    }
    case 'remove-exception':
      return removeException(state, command.ruleKey, command.key);
    case 'set-policy': {
      const next = { ...state };
      if (command.set.direction !== undefined) next.direction = command.set.direction;
      if (command.set.priority !== undefined) next.priority = command.set.priority;
      return next.direction === state.direction && next.priority === state.priority ? state : next;
    }
    case 'replace':
      return command.model;
    case 'add-rule':
    case 'remove-rule':
    case 'move-rule':
    case 'update-rule':
      return reduceRule(state, command);
    case 'add-action':
    case 'remove-action':
    case 'update-action':
    case 'move-action':
      return reduceAction(state, command);
    default:
      return state;
  }
}

const canonicalOf = (model: BuilderDefinition): string =>
  canonicalJson(buildDefinition(model).definition);

/**
 * Editor state with a dirty flag against a baseline (canonical JSON comparison, so key order and
 * UI keys never count). `resetBaseline(model)` replaces the state and makes it the new baseline
 * (after a save, or "Reload theirs").
 */
export function useBuilderState(initial: BuilderDefinition): {
  state: BuilderDefinition;
  dispatch: (command: BuilderCommand) => void;
  isDirty: boolean;
  baseline: BuilderDefinition;
  resetBaseline: (model: BuilderDefinition) => void;
} {
  const [state, dispatch] = useReducer(builderReducer, initial);
  const [baseline, setBaseline] = useState(initial);
  const baselineJson = useMemo(() => canonicalOf(baseline), [baseline]);
  const currentJson = useMemo(() => canonicalOf(state), [state]);
  const resetBaseline = useCallback((model: BuilderDefinition) => {
    dispatch({ type: 'replace', model });
    setBaseline(model);
  }, []);
  return { state, dispatch, isDirty: currentJson !== baselineJson, baseline, resetBaseline };
}
