import { childPath, formatPath, type PathIndex, type PathSegment } from './paths';

/**
 * The builder model (design B3): a lossless mirror of a `policy-dsl/1` document plus stable UI
 * keys. `parseDefinition` accepts exactly the documents whose objects carry only the document
 * grammar's keys and carries every value through unvalidated (the server validates); for every
 * accepted document `buildDefinition(parseDefinition(doc).model).definition` deep-equals `doc`.
 * Optional keys keep their presence (`enabled` absent ≠ `enabled: true`, `unless` absent ≠ `[]`,
 * an action parameter absent ≠ its default); `not` is a node of its own.
 */

/** The document format this model mirrors; any other `dslVersion` is refused. */
export const MODEL_DSL_VERSION = 'policy-dsl/1';

/** A policy direction (a catalogue `policyDirections` value; carried through unvalidated). */
export type PolicyDirection = string;

export interface BuilderLeaf {
  kind: 'leaf';
  key: string;
  /** Absent while the user has not chosen a field (a new, empty condition). */
  field?: string;
  op?: string;
  value?: unknown;
  quantifier?: string;
}

export interface BuilderGroup {
  kind: 'group';
  key: string;
  joiner: 'all' | 'any';
  children: BuilderNode[];
}

export interface BuilderNot {
  kind: 'not';
  key: string;
  child: BuilderNode;
}

export type BuilderNode = BuilderLeaf | BuilderGroup | BuilderNot;

export interface BuilderAction {
  key: string;
  type: string;
  /** Every key of the action except `type`, in document order. */
  params: Record<string, unknown>;
}

export interface BuilderRule {
  key: string;
  id: string;
  priority: number;
  description?: string;
  enabled?: boolean;
  directions?: string[];
  when: BuilderNode;
  unless?: BuilderNode[];
  actions: BuilderAction[];
  stop?: boolean;
  override?: boolean;
}

export interface BuilderDefinition {
  dslVersion: string;
  direction: PolicyDirection;
  priority: number;
  rules: BuilderRule[];
  exceptions?: BuilderNode[];
}

/** The JSON document sent to the api. */
export type PolicyDslDocument = Record<string, unknown>;

export type ParseFailureReason = 'not_object' | 'unsupported_version' | 'unknown_key' | 'malformed';

export type ParseResult =
  { ok: true; model: BuilderDefinition } | { ok: false; reason: ParseFailureReason; path: string };

// ---------------------------------------------------------------------------------------------
// Keys, ids and priorities
// ---------------------------------------------------------------------------------------------

let keySeq = 0;

/** A UI key unique for the page session (`r…` rules, `n…` nodes, `a…` actions). */
export function newKey(prefix: 'r' | 'n' | 'a' | 'k' = 'k'): string {
  keySeq += 1;
  return `${prefix}${keySeq.toString(36)}`;
}

/** `rule-<n>` with the smallest free n (always matches the DSL rule id pattern). */
export function nextRuleId(rules: readonly Pick<BuilderRule, 'id'>[]): string {
  const used = new Set(rules.map((rule) => rule.id));
  let n = 1;
  while (used.has(`rule-${n}`)) n += 1;
  return `rule-${n}`;
}

/** The highest rule priority + 10 (0 for the first rule): new rules run last. */
export function nextRulePriority(rules: readonly Pick<BuilderRule, 'priority'>[]): number {
  if (rules.length === 0) return 0;
  return Math.max(...rules.map((rule) => rule.priority)) + 10;
}

/** Rules in evaluation order (priority, then document order). */
export function rulesByPriority<T extends Pick<BuilderRule, 'priority'>>(rules: readonly T[]): T[] {
  return rules
    .map((rule, index) => ({ rule, index }))
    .sort((a, b) => a.rule.priority - b.rule.priority || a.index - b.index)
    .map((item) => item.rule);
}

export const emptyLeaf = (key: string = newKey('n')): BuilderLeaf => ({ kind: 'leaf', key });

/** A rule with one empty condition in an `all` group and no action. */
export function newRule(
  rules: readonly BuilderRule[],
  keys: { key?: string; groupKey?: string; leafKey?: string } = {},
): BuilderRule {
  return {
    key: keys.key ?? newKey('r'),
    id: nextRuleId(rules),
    priority: nextRulePriority(rules),
    when: {
      kind: 'group',
      key: keys.groupKey ?? newKey('n'),
      joiner: 'all',
      children: [emptyLeaf(keys.leafKey)],
    },
    actions: [],
  };
}

/** Default policy priority of a new policy (0..10000, lower runs first). */
export const NEW_POLICY_PRIORITY = 100;
/** Default direction of a new policy: every direction (the DSL's `any`). */
export const NEW_POLICY_DIRECTION = 'any';

/** A new policy: one rule with one empty condition and no action. */
export function emptyDefinition(
  direction: PolicyDirection = NEW_POLICY_DIRECTION,
): BuilderDefinition {
  return {
    dslVersion: MODEL_DSL_VERSION,
    direction,
    priority: NEW_POLICY_PRIORITY,
    rules: [newRule([])],
  };
}

// ---------------------------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------------------------

export const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value) as unknown;
  return proto === Object.prototype || proto === null;
};

/** Deep copy of JSON data (plain objects and arrays; other values as they are). */
export function cloneJson<T>(value: T): T {
  if (Array.isArray(value)) return value.map((item: unknown) => cloneJson(item)) as T;
  if (isPlainObject(value)) {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) out[key] = cloneJson(item);
    return out as T;
  }
  return value;
}

function encode(value: unknown, indent: string | null, level: number): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') return Number.isFinite(value) ? JSON.stringify(value) : 'null';
  const pad = indent === null ? '' : `\n${indent.repeat(level + 1)}`;
  const end = indent === null ? '' : `\n${indent.repeat(level)}`;
  const sep = indent === null ? ':' : ': ';
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    return `[${value.map((item) => `${pad}${encode(item, indent, level + 1)}`).join(',')}${end}]`;
  }
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record)
      .filter((key) => record[key] !== undefined)
      .sort();
    if (keys.length === 0) return '{}';
    return `{${keys
      .map((key) => `${pad}${JSON.stringify(key)}${sep}${encode(record[key], indent, level + 1)}`)
      .join(',')}${end}}`;
  }
  return 'null';
}

/** JSON with object keys sorted (UTF-16 order, as the api's canonical JSON): dirty checks, diffs. */
export function canonicalJson(value: unknown): string {
  return encode(value, null, 0);
}

/** Canonical JSON pretty-printed with two spaces (the "Raw JSON" diff). */
export function canonicalPrettyJson(value: unknown): string {
  return encode(value, '  ', 0);
}

const utf8 = new TextEncoder();

/** UTF-8 size of the canonical JSON (what the DSL's `documentBytes` limit measures). */
export function documentBytes(definition: PolicyDslDocument): number {
  return utf8.encode(canonicalJson(definition)).length;
}

// ---------------------------------------------------------------------------------------------
// parseDefinition
// ---------------------------------------------------------------------------------------------

const DOC_KEYS = ['dslVersion', 'direction', 'priority', 'rules', 'exceptions'];
const RULE_KEYS = [
  'id',
  'priority',
  'description',
  'enabled',
  'directions',
  'when',
  'unless',
  'actions',
  'stop',
  'override',
];
const LEAF_KEYS = ['field', 'op', 'value', 'quantifier'];
const GROUP_KEYS = ['all', 'any', 'not'] as const;

class ParseFailure extends Error {
  constructor(
    readonly reason: ParseFailureReason,
    readonly path: string,
  ) {
    super(`${reason} at ${path || '(root)'}`);
    this.name = 'ParseFailure';
  }
}

function fail(reason: ParseFailureReason, at: readonly PathSegment[]): never {
  throw new ParseFailure(reason, formatPath(at));
}

const has = (obj: Record<string, unknown>, key: string): boolean =>
  Object.prototype.hasOwnProperty.call(obj, key) && obj[key] !== undefined;

function checkKeys(
  obj: Record<string, unknown>,
  allowed: readonly string[],
  at: PathSegment[],
): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) fail('unknown_key', [...at, key]);
  }
}

function plainObject(value: unknown, at: PathSegment[]): Record<string, unknown> {
  if (!isPlainObject(value)) fail('malformed', at);
  return value;
}

function stringAt(obj: Record<string, unknown>, key: string, at: PathSegment[]): string {
  const value = obj[key];
  if (typeof value !== 'string') fail('malformed', [...at, key]);
  return value;
}

function numberAt(obj: Record<string, unknown>, key: string, at: PathSegment[]): number {
  const value = obj[key];
  if (typeof value !== 'number' || !Number.isFinite(value)) fail('malformed', [...at, key]);
  return value;
}

function booleanAt(obj: Record<string, unknown>, key: string, at: PathSegment[]): boolean {
  const value = obj[key];
  if (typeof value !== 'boolean') fail('malformed', [...at, key]);
  return value;
}

function arrayAt(obj: Record<string, unknown>, key: string, at: PathSegment[]): unknown[] {
  const value = obj[key];
  if (!Array.isArray(value)) fail('malformed', [...at, key]);
  return value;
}

function parseNode(value: unknown, at: PathSegment[]): BuilderNode {
  const node = plainObject(value, at);
  const groupKeys = GROUP_KEYS.filter((key) => has(node, key));
  if (groupKeys.length > 1) fail('malformed', at);
  const groupKey = groupKeys[0];
  if (groupKey === 'not') {
    checkKeys(node, ['not'], at);
    return { kind: 'not', key: newKey('n'), child: parseNode(node.not, [...at, 'not']) };
  }
  if (groupKey === 'all' || groupKey === 'any') {
    checkKeys(node, [groupKey], at);
    const children = arrayAt(node, groupKey, at).map((child, i) =>
      parseNode(child, [...at, groupKey, i]),
    );
    return { kind: 'group', key: newKey('n'), joiner: groupKey, children };
  }
  checkKeys(node, LEAF_KEYS, at);
  const leaf: BuilderLeaf = { kind: 'leaf', key: newKey('n') };
  if (has(node, 'field')) leaf.field = stringAt(node, 'field', at);
  if (has(node, 'op')) leaf.op = stringAt(node, 'op', at);
  if (has(node, 'value')) leaf.value = cloneJson(node.value);
  if (has(node, 'quantifier')) leaf.quantifier = stringAt(node, 'quantifier', at);
  return leaf;
}

function parseNodes(obj: Record<string, unknown>, key: string, at: PathSegment[]): BuilderNode[] {
  return arrayAt(obj, key, at).map((node, i) => parseNode(node, [...at, key, i]));
}

function parseAction(value: unknown, at: PathSegment[]): BuilderAction {
  const action = plainObject(value, at);
  const type = stringAt(action, 'type', at);
  const params: Record<string, unknown> = {};
  for (const [key, param] of Object.entries(action)) {
    if (key !== 'type' && param !== undefined) params[key] = cloneJson(param);
  }
  return { key: newKey('a'), type, params };
}

function parseRule(value: unknown, at: PathSegment[]): BuilderRule {
  const rule = plainObject(value, at);
  checkKeys(rule, RULE_KEYS, at);
  if (!has(rule, 'when')) fail('malformed', [...at, 'when']);
  const out: BuilderRule = {
    key: newKey('r'),
    id: stringAt(rule, 'id', at),
    priority: numberAt(rule, 'priority', at),
    when: parseNode(rule.when, [...at, 'when']),
    actions: arrayAt(rule, 'actions', at).map((action, j) =>
      parseAction(action, [...at, 'actions', j]),
    ),
  };
  if (has(rule, 'description')) out.description = stringAt(rule, 'description', at);
  if (has(rule, 'enabled')) out.enabled = booleanAt(rule, 'enabled', at);
  if (has(rule, 'directions')) {
    out.directions = arrayAt(rule, 'directions', at).map((direction, k) => {
      if (typeof direction !== 'string') fail('malformed', [...at, 'directions', k]);
      return direction;
    });
  }
  if (has(rule, 'unless')) out.unless = parseNodes(rule, 'unless', at);
  if (has(rule, 'stop')) out.stop = booleanAt(rule, 'stop', at);
  if (has(rule, 'override')) out.override = booleanAt(rule, 'override', at);
  return out;
}

/**
 * The builder model of a document, or why it cannot be edited: `not_object`,
 * `unsupported_version` (anything but `policy-dsl/1`, including legacy `null`), `unknown_key`
 * (a key outside the document grammar, never dropped) or `malformed` (a structural value of the
 * wrong JSON type), with the JSON path of the first problem.
 */
export function parseDefinition(doc: unknown): ParseResult {
  if (!isPlainObject(doc)) return { ok: false, reason: 'not_object', path: '' };
  if (doc.dslVersion !== MODEL_DSL_VERSION) {
    return { ok: false, reason: 'unsupported_version', path: 'dslVersion' };
  }
  try {
    checkKeys(doc, DOC_KEYS, []);
    const model: BuilderDefinition = {
      dslVersion: MODEL_DSL_VERSION,
      direction: stringAt(doc, 'direction', []),
      priority: numberAt(doc, 'priority', []),
      rules: arrayAt(doc, 'rules', []).map((rule, i) => parseRule(rule, ['rules', i])),
    };
    if (has(doc, 'exceptions')) model.exceptions = parseNodes(doc, 'exceptions', []);
    return { ok: true, model };
  } catch (error) {
    if (error instanceof ParseFailure) return { ok: false, reason: error.reason, path: error.path };
    throw error;
  }
}

// ---------------------------------------------------------------------------------------------
// buildDefinition
// ---------------------------------------------------------------------------------------------

class IndexBuilder {
  readonly keyByPath = new Map<string, string>();
  readonly pathByKey = new Map<string, string>();
  add(path: string, key: string): void {
    this.keyByPath.set(path, key);
    this.pathByKey.set(key, path);
  }
}

function buildNode(node: BuilderNode, path: string, index: IndexBuilder): PolicyDslDocument {
  index.add(path, node.key);
  if (node.kind === 'group') {
    const base = childPath(path, node.joiner);
    return {
      [node.joiner]: node.children.map((child, i) => buildNode(child, childPath(base, i), index)),
    };
  }
  if (node.kind === 'not') return { not: buildNode(node.child, childPath(path, 'not'), index) };
  const leaf: PolicyDslDocument = {};
  if (node.field !== undefined) leaf.field = node.field;
  if (node.op !== undefined) leaf.op = node.op;
  if (node.value !== undefined) leaf.value = cloneJson(node.value);
  if (node.quantifier !== undefined) leaf.quantifier = node.quantifier;
  return leaf;
}

function buildRule(rule: BuilderRule, path: string, index: IndexBuilder): PolicyDslDocument {
  index.add(path, rule.key);
  const out: PolicyDslDocument = { id: rule.id, priority: rule.priority };
  if (rule.description !== undefined) out.description = rule.description;
  if (rule.enabled !== undefined) out.enabled = rule.enabled;
  if (rule.directions !== undefined) out.directions = [...rule.directions];
  out.when = buildNode(rule.when, childPath(path, 'when'), index);
  if (rule.unless !== undefined) {
    const base = childPath(path, 'unless');
    out.unless = rule.unless.map((node, k) => buildNode(node, childPath(base, k), index));
  }
  const actionsPath = childPath(path, 'actions');
  out.actions = rule.actions.map((action, j) => {
    const actionPath = childPath(actionsPath, j);
    index.add(actionPath, action.key);
    const built: PolicyDslDocument = { type: action.type };
    for (const [key, value] of Object.entries(action.params)) {
      if (key !== 'type' && value !== undefined) built[key] = cloneJson(value);
    }
    return built;
  });
  if (rule.stop !== undefined) out.stop = rule.stop;
  if (rule.override !== undefined) out.override = rule.override;
  return out;
}

/** The `policy-dsl/1` document of a model and its path index (rules, nodes, actions). */
export function buildDefinition(model: BuilderDefinition): {
  definition: PolicyDslDocument;
  paths: PathIndex;
} {
  const index = new IndexBuilder();
  const definition: PolicyDslDocument = {
    dslVersion: model.dslVersion,
    direction: model.direction,
    priority: model.priority,
    rules: model.rules.map((rule, i) => buildRule(rule, childPath('rules', i), index)),
  };
  if (model.exceptions !== undefined) {
    definition.exceptions = model.exceptions.map((node, k) =>
      buildNode(node, childPath('exceptions', k), index),
    );
  }
  return { definition, paths: { keyByPath: index.keyByPath, pathByKey: index.pathByKey } };
}
