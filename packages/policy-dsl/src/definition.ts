import { canonicalJson } from '@email-gateway/risk-scoring';
import { REASON_CODE_MAX_LENGTH, REASON_CODE_PATTERN } from '@email-gateway/security-contracts';
import { z } from 'zod';
import {
  DIRECTORY_FIELDS,
  isPolicyField,
  isPolicyOperator,
  POLICY_FIELDS,
  type PolicyFieldDefinition,
  type PolicyFieldName,
  type PolicyOperator,
} from './fields';
import {
  compileRegex,
  isValidGlob,
  normalizeAddress,
  normalizeDomain,
  parseCidr,
  parseIp,
} from './matchers';
import { isCalendarDate, isValidTimeZone, parseHhMm } from './time';
import {
  ALERT_SEVERITIES,
  isDispositionAction,
  POLICY_ACTION_TYPES,
  POLICY_DIRECTIONS,
  POLICY_DSL_VERSION,
  POLICY_HOLD_DISPOSITIONS,
  POLICY_LIMITS,
  POLICY_MESSAGE_DIRECTIONS,
  DISPOSITION_OF_ACTION,
  URL_REWRITE_FALLBACKS,
  WARN_LEVELS,
  WEEKDAYS,
  type AlertSeverity,
  type PolicyDirection,
  type PolicyDispositionAction,
  type PolicyMessageDirection,
  type UrlRewriteFallback,
  type WarnLevel,
  type Weekday,
} from './vocabulary';

/**
 * The document `policy-dsl/1` (step 5.2 P2–P6, P9) and its validator. The validator walks the
 * whole document and reports **every** violation with a stable code and a JSON path such as
 * `rules[2].when.all[0].value`, sorted by path. `policyDefinitionSchema` is the zod form of the
 * same check (its refinement is this walk), so the api, the compiler and the tests share one
 * implementation.
 */

// ---------------------------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------------------------

export type Quantifier = 'any' | 'all';

export interface TimeWindowValue {
  timeZone: string;
  days: Weekday[];
  from: string;
  to: string;
}

export interface DateRangeValue {
  timeZone: string;
  from: string;
  to: string;
}

export interface RegexValue {
  pattern: string;
  flags?: '' | 'i';
}

export interface LeafNode {
  field: PolicyFieldName;
  op: PolicyOperator;
  value?: unknown;
  quantifier?: Quantifier;
}

export type PolicyNode =
  { all: PolicyNode[] } | { any: PolicyNode[] } | { not: PolicyNode } | LeafNode;

export type PolicyAction =
  | { type: 'ALLOW' }
  | { type: 'REQUIRE_APPROVAL' }
  | { type: 'QUARANTINE' }
  | { type: 'REJECT'; notifySender?: boolean }
  | { type: 'TAG'; label: string; subjectPrefix?: string; addHeader?: boolean }
  | { type: 'WARN'; level: WarnLevel; text?: string; subjectPrefix?: string }
  | { type: 'URL_REWRITE'; ifNotRewritten?: UrlRewriteFallback }
  | { type: 'ARCHIVE' }
  | { type: 'ALERT'; severity: AlertSeverity };

export interface PolicyRule {
  id: string;
  priority: number;
  description?: string;
  enabled?: boolean;
  directions?: PolicyMessageDirection[];
  when: PolicyNode;
  unless?: PolicyNode[];
  actions: PolicyAction[];
  stop?: boolean;
  override?: boolean;
}

export interface PolicyDefinition {
  dslVersion: typeof POLICY_DSL_VERSION;
  direction: PolicyDirection;
  priority: number;
  rules: PolicyRule[];
  exceptions?: PolicyNode[];
}

/** One refusal: JSON path (`rules[2].when.all[0].value`), stable code, English message. */
export interface Violation {
  path: string;
  code: string;
  message: string;
}

export const violationSchema = z.strictObject({
  path: z.string().max(512),
  code: z.string().regex(/^[a-z][a-z0-9_]{0,63}$/),
  message: z.string().max(512),
});

/** Directory ids a definition references (P5), sorted and unique. */
export interface DirectoryReferences {
  departmentIds: string[];
  userIds: string[];
}

/** Stable violation codes (the api documents them). */
export const POLICY_VIOLATION_CODES = [
  'value_invalid',
  'value_required',
  'unknown_key',
  'unknown_field',
  'unknown_operator',
  'unknown_action',
  'operator_not_allowed',
  'quantifier_not_allowed',
  'limit_exceeded',
  'dsl_version_unsupported',
  'duplicate_rule_id',
  'duplicate_rule_priority',
  'duplicate_action',
  'multiple_dispositions',
  'override_without_disposition',
  'direction_not_in_policy',
  'exception_negation',
  'exception_quantifier',
  'identity_unauthenticated',
  'ai_field_in_exception',
  'ai_field_in_hold_rule',
  'regex_invalid',
  'glob_invalid',
  'cidr_invalid',
  'time_zone_invalid',
  'definition_hash_mismatch',
] as const;
export type PolicyViolationCode = (typeof POLICY_VIOLATION_CODES)[number];

// ---------------------------------------------------------------------------------------------
// Paths and the violation collector
// ---------------------------------------------------------------------------------------------

type Segment = string | number;

export function formatPath(segments: readonly Segment[]): string {
  let out = '';
  for (const s of segments) {
    if (typeof s === 'number') out += `[${s}]`;
    else out += out === '' ? s : `.${s}`;
  }
  return out;
}

function compareSegments(a: readonly Segment[], b: readonly Segment[]): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    const x = a[i]!;
    const y = b[i]!;
    if (x === y) continue;
    if (typeof x === 'number' && typeof y === 'number') return x - y;
    if (typeof x === 'number') return -1;
    if (typeof y === 'number') return 1;
    return x < y ? -1 : 1;
  }
  return a.length - b.length;
}

interface RawViolation {
  segments: Segment[];
  code: PolicyViolationCode;
  message: string;
}

class Collector {
  readonly items: RawViolation[] = [];
  add(segments: readonly Segment[], code: PolicyViolationCode, message: string): void {
    this.items.push({ segments: [...segments], code, message });
  }
  sorted(): Violation[] {
    const seen = new Set<string>();
    return [...this.items]
      .sort(
        (a, b) =>
          compareSegments(a.segments, b.segments) ||
          (a.code < b.code ? -1 : a.code > b.code ? 1 : 0) ||
          (a.message < b.message ? -1 : a.message > b.message ? 1 : 0),
      )
      .map((v) => ({ path: formatPath(v.segments), code: v.code, message: v.message }))
      .filter((v) => {
        const key = `${v.path}\u0000${v.code}\u0000${v.message}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
  }
}

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' &&
  v !== null &&
  !Array.isArray(v) &&
  (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);

const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v);
// eslint-disable-next-line no-control-regex -- fixed platform pattern, not tenant input
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
const PRINTABLE_ASCII = /^[\x20-\x7e]+$/;
const RULE_ID = /^[a-z0-9][a-z0-9_-]{0,47}$/;
const TAG_LABEL = /^[a-z0-9][a-z0-9._-]{0,31}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-fA-F]{64}$/;
const EXTENSION = /^[^.\s/\\]{1,32}$/;

function checkKeys(
  c: Collector,
  obj: Record<string, unknown>,
  allowed: readonly string[],
  at: readonly Segment[],
): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) c.add([...at, key], 'unknown_key', `Unknown key "${safeKey(key)}"`);
  }
}

/** Keys are echoed in messages only when they look like identifiers. */
const safeKey = (key: string): string => (/^[A-Za-z0-9_.-]{1,64}$/.test(key) ? key : '…');

export const isSubjectPrefix = (v: unknown): v is string =>
  typeof v === 'string' &&
  v.length >= 1 &&
  v.length <= 32 &&
  PRINTABLE_ASCII.test(v) &&
  !v.includes(':');

export const isHeaderText = (v: unknown): v is string =>
  typeof v === 'string' && v.length >= 1 && v.length <= 128 && PRINTABLE_ASCII.test(v);

export const isTagLabel = (v: unknown): v is string => typeof v === 'string' && TAG_LABEL.test(v);

// ---------------------------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------------------------

function scalarOk(def: PolicyFieldDefinition, name: string, v: unknown): boolean {
  switch (def.type) {
    case 'address': {
      if (typeof v !== 'string' || v.length < 3 || v.length > POLICY_LIMITS.stringValue)
        return false;
      if (CONTROL.test(v)) return false;
      return normalizeAddress(v).domain !== null;
    }
    case 'domain':
      return typeof v === 'string' && v.length <= 253 && normalizeDomain(v) !== null;
    case 'string': {
      if (typeof v !== 'string' || v.length < 1 || v.length > POLICY_LIMITS.stringValue) {
        return false;
      }
      if (CONTROL.test(v)) return false;
      if (name === 'attachment.sha256') return SHA256.test(v);
      if (name === 'attachment.extension') return EXTENSION.test(v);
      return true;
    }
    case 'enum':
      return typeof v === 'string' && (def.values ?? []).includes(v);
    case 'ip':
      return typeof v === 'string' && parseIp(v) !== null;
    case 'id':
      return typeof v === 'string' && UUID.test(v);
    default:
      return false;
  }
}

function checkList(
  c: Collector,
  v: unknown,
  at: readonly Segment[],
  max: number,
  what: string,
): v is unknown[] {
  if (!Array.isArray(v)) {
    c.add(at, 'value_invalid', `Expected a list of ${what}`);
    return false;
  }
  if (v.length < 1) {
    c.add(at, 'value_invalid', `Expected at least one ${what}`);
    return false;
  }
  if (v.length > max) {
    c.add(at, 'limit_exceeded', `At most ${max} ${what}`);
    return false;
  }
  return true;
}

function checkTimeValue(c: Collector, name: string, v: unknown, at: readonly Segment[]): void {
  if (!isPlainObject(v)) {
    c.add(at, 'value_invalid', 'Expected a time object');
    return;
  }
  const windowKeys = ['timeZone', 'days', 'from', 'to'];
  const rangeKeys = ['timeZone', 'from', 'to'];
  checkKeys(c, v, name === 'time.window' ? windowKeys : rangeKeys, at);
  if (v.timeZone === undefined) c.add([...at, 'timeZone'], 'value_required', 'Missing timeZone');
  else if (!isValidTimeZone(v.timeZone)) {
    c.add([...at, 'timeZone'], 'time_zone_invalid', 'Unknown IANA time zone');
  }
  if (name === 'time.window') {
    const days = v.days;
    if (days === undefined) c.add([...at, 'days'], 'value_required', 'Missing days');
    else if (
      !Array.isArray(days) ||
      days.length < 1 ||
      days.length > 7 ||
      new Set(days).size !== days.length ||
      !days.every((d) => typeof d === 'string' && (WEEKDAYS as readonly string[]).includes(d))
    ) {
      c.add([...at, 'days'], 'value_invalid', 'Expected 1..7 unique weekdays mon..sun');
    }
    const from = parseHhMm(v.from);
    const to = parseHhMm(v.to, true);
    if (v.from === undefined) c.add([...at, 'from'], 'value_required', 'Missing from');
    else if (from === null) c.add([...at, 'from'], 'value_invalid', 'Expected HH:MM (00:00–23:59)');
    if (v.to === undefined) c.add([...at, 'to'], 'value_required', 'Missing to');
    else if (to === null) c.add([...at, 'to'], 'value_invalid', 'Expected HH:MM (00:00–24:00)');
    if (from !== null && to !== null && from === to) {
      c.add([...at, 'to'], 'value_invalid', 'from and to must differ');
    }
    return;
  }
  for (const key of ['from', 'to'] as const) {
    if (v[key] === undefined) c.add([...at, key], 'value_required', `Missing ${key}`);
    else if (!isCalendarDate(v[key])) c.add([...at, key], 'value_invalid', 'Expected YYYY-MM-DD');
  }
  if (isCalendarDate(v.from) && isCalendarDate(v.to) && v.from > v.to) {
    c.add([...at, 'to'], 'value_invalid', 'from must not be after to');
  }
}

function checkValue(
  c: Collector,
  name: PolicyFieldName,
  def: PolicyFieldDefinition,
  op: PolicyOperator,
  leaf: Record<string, unknown>,
  at: readonly Segment[],
): void {
  const vAt = [...at, 'value'];
  const has = Object.prototype.hasOwnProperty.call(leaf, 'value');
  const v = leaf.value;
  if (op === 'exists') {
    if (has) c.add(vAt, 'value_invalid', 'exists takes no value');
    return;
  }
  if (!has || v === undefined) {
    c.add(vAt, 'value_required', `Operator ${op} needs a value`);
    return;
  }
  switch (op) {
    case 'is':
      if (typeof v !== 'boolean') c.add(vAt, 'value_invalid', 'Expected true or false');
      return;
    case 'equals':
      if (!scalarOk(def, name, v)) c.add(vAt, 'value_invalid', `Invalid ${def.type} value`);
      return;
    case 'in':
    case 'not_in':
      if (checkList(c, v, vAt, POLICY_LIMITS.listValues, 'values')) {
        v.forEach((item, k) => {
          if (!scalarOk(def, name, item)) {
            c.add([...vAt, k], 'value_invalid', `Invalid ${def.type} value`);
          }
        });
      }
      return;
    case 'domain_in':
      if (checkList(c, v, vAt, POLICY_LIMITS.listValues, 'domains')) {
        v.forEach((item, k) => {
          if (typeof item !== 'string' || normalizeDomain(item) === null) {
            c.add([...vAt, k], 'value_invalid', 'Invalid domain');
          }
        });
      }
      return;
    case 'glob':
      if (checkList(c, v, vAt, POLICY_LIMITS.globs, 'glob patterns')) {
        v.forEach((item, k) => {
          if (typeof item === 'string' && item.length > POLICY_LIMITS.globLength) {
            c.add([...vAt, k], 'limit_exceeded', `Glob longer than ${POLICY_LIMITS.globLength}`);
          } else if (!isValidGlob(item)) {
            c.add([...vAt, k], 'glob_invalid', 'Invalid glob pattern');
          }
        });
      }
      return;
    case 'regex':
      if (checkList(c, v, vAt, POLICY_LIMITS.regexes, 'regular expressions')) {
        v.forEach((item, k) => {
          const spec = regexSpecOf(item);
          if (spec === null) {
            c.add([...vAt, k], 'regex_invalid', 'Expected a pattern string or { pattern, flags }');
            return;
          }
          if (spec.pattern.length > POLICY_LIMITS.regexLength) {
            c.add([...vAt, k], 'limit_exceeded', `Regex longer than ${POLICY_LIMITS.regexLength}`);
            return;
          }
          const compiled = compileRegex(spec);
          if (!compiled.ok) {
            c.add([...vAt, k], 'regex_invalid', `Not a supported RE2 pattern (${compiled.reason})`);
          }
        });
      }
      return;
    case 'in_cidr':
      if (checkList(c, v, vAt, POLICY_LIMITS.cidrs, 'CIDRs')) {
        v.forEach((item, k) => {
          if (parseCidr(item) === null) {
            c.add([...vAt, k], 'cidr_invalid', 'Expected a canonical address/prefix CIDR');
          }
        });
      }
      return;
    case 'eq':
    case 'gt':
    case 'gte':
    case 'lt':
    case 'lte':
      if (def.type === 'int') {
        if (!isInt(v) || v < def.min! || v > def.max!) {
          c.add(vAt, 'value_invalid', `Expected an integer ${def.min}..${def.max}`);
        }
      } else if (typeof v !== 'string' || !(def.values ?? []).includes(v)) {
        c.add(vAt, 'value_invalid', 'Expected a value of the field vocabulary');
      }
      return;
    case 'between':
      if (
        !Array.isArray(v) ||
        v.length !== 2 ||
        !isInt(v[0]) ||
        !isInt(v[1]) ||
        v[0] < def.min! ||
        v[1] > def.max! ||
        v[0] > v[1]
      ) {
        c.add(vAt, 'value_invalid', `Expected [low, high] integers ${def.min}..${def.max}`);
      }
      return;
    case 'contains_any':
    case 'contains_all':
      if (checkList(c, v, vAt, POLICY_LIMITS.codes, 'codes')) {
        v.forEach((item, k) => {
          const ok =
            typeof item === 'string' &&
            (def.values
              ? def.values.includes(item)
              : item.length <= REASON_CODE_MAX_LENGTH && REASON_CODE_PATTERN.test(item));
          if (!ok) c.add([...vAt, k], 'value_invalid', 'Invalid code');
        });
      }
      return;
    case 'within':
      checkTimeValue(c, name, v, vAt);
      return;
    default:
      return;
  }
}

export function regexSpecOf(item: unknown): { pattern: string; flags: '' | 'i' } | null {
  if (typeof item === 'string') return { pattern: item, flags: '' };
  if (!isPlainObject(item)) return null;
  const keys = Object.keys(item);
  if (!keys.every((k) => k === 'pattern' || k === 'flags')) return null;
  if (typeof item.pattern !== 'string') return null;
  const flags = item.flags ?? '';
  if (flags !== '' && flags !== 'i') return null;
  return { pattern: item.pattern, flags };
}

// ---------------------------------------------------------------------------------------------
// Nodes
// ---------------------------------------------------------------------------------------------

interface NodeMode {
  /** `exception` = a rule `unless` entry or a policy-wide exception (P6). */
  kind: 'when' | 'exception';
  /** The `when` of an ALLOW or override rule (identity restriction, P6). */
  relaxing: boolean;
}

interface NodeStats {
  nodes: number;
  /** Paths of AI-derived leaves (their `field` key). */
  aiLeaves: Segment[][];
  departmentIds: Set<string>;
  userIds: Set<string>;
}

function checkNode(
  c: Collector,
  node: unknown,
  at: readonly Segment[],
  mode: NodeMode,
  depth: number,
  stats: NodeStats,
): void {
  stats.nodes += 1;
  if (depth === POLICY_LIMITS.depth + 1) {
    c.add(at, 'limit_exceeded', `Nesting deeper than ${POLICY_LIMITS.depth}`);
  }
  if (!isPlainObject(node)) {
    c.add(at, 'value_invalid', 'Expected a node: { all }, { any }, { not } or a condition');
    return;
  }
  const group = ['all', 'any', 'not'].filter((k) => Object.prototype.hasOwnProperty.call(node, k));
  if (group.length > 1) {
    c.add(at, 'value_invalid', 'A node has exactly one of all, any, not');
    return;
  }
  if (group.length === 1) {
    const key = group[0]!;
    checkKeys(c, node, [key], at);
    if (key === 'not') {
      if (mode.kind === 'exception') {
        c.add([...at, 'not'], 'exception_negation', 'Exceptions cannot use not');
      }
      checkNode(c, node.not, [...at, 'not'], mode, depth + 1, stats);
      return;
    }
    const children = node[key];
    if (!Array.isArray(children) || children.length < 1) {
      c.add(
        [...at, key],
        'value_invalid',
        `${key} needs 1..${POLICY_LIMITS.childrenPerGroup} nodes`,
      );
      return;
    }
    if (children.length > POLICY_LIMITS.childrenPerGroup) {
      c.add([...at, key], 'limit_exceeded', `At most ${POLICY_LIMITS.childrenPerGroup} children`);
    }
    children.forEach((child, i) => checkNode(c, child, [...at, key, i], mode, depth + 1, stats));
    return;
  }
  checkLeaf(c, node, at, mode, stats);
}

function checkLeaf(
  c: Collector,
  leaf: Record<string, unknown>,
  at: readonly Segment[],
  mode: NodeMode,
  stats: NodeStats,
): void {
  checkKeys(c, leaf, ['field', 'op', 'value', 'quantifier'], at);
  const name = leaf.field;
  if (name === undefined) {
    c.add([...at, 'field'], 'value_required', 'Missing field');
    return;
  }
  if (!isPolicyField(name)) {
    c.add([...at, 'field'], 'unknown_field', 'Unknown field');
    return;
  }
  const def: PolicyFieldDefinition = POLICY_FIELDS[name];
  if (def.senderIdentity === 'raw' && (mode.kind === 'exception' || mode.relaxing)) {
    c.add(
      [...at, 'field'],
      'identity_unauthenticated',
      mode.kind === 'exception'
        ? 'Exceptions see the sender only through sender.authenticated.*, sender.trusted, sender.department or sender.user'
        : 'ALLOW and override rules see the sender only through authenticated fields',
    );
  }
  if (def.aiDerived) {
    if (mode.kind === 'exception') {
      c.add([...at, 'field'], 'ai_field_in_exception', 'Exceptions cannot use AI-derived fields');
    } else stats.aiLeaves.push([...at, 'field']);
  }
  const op = leaf.op;
  if (op === undefined) {
    c.add([...at, 'op'], 'value_required', 'Missing op');
    return;
  }
  if (!isPolicyOperator(op)) {
    c.add([...at, 'op'], 'unknown_operator', 'Unknown operator');
    return;
  }
  if (!def.ops.includes(op)) {
    c.add([...at, 'op'], 'operator_not_allowed', `Operator ${op} is not allowed for ${name}`);
    return;
  }
  if (mode.kind === 'exception' && op === 'not_in') {
    c.add([...at, 'op'], 'exception_negation', 'Exceptions cannot use not_in');
  }
  const q = leaf.quantifier;
  if (q !== undefined) {
    if (!def.quantified) {
      c.add([...at, 'quantifier'], 'quantifier_not_allowed', `${name} is not a list field`);
    } else if (q !== 'any' && q !== 'all') {
      c.add([...at, 'quantifier'], 'value_invalid', 'Expected any or all');
    }
  }
  if (mode.kind === 'exception' && def.quantified && q !== 'all') {
    c.add(
      [...at, 'quantifier'],
      'exception_quantifier',
      'List conditions in exceptions need quantifier all',
    );
  }
  checkValue(c, name, def, op, leaf, at);
  const directory = (DIRECTORY_FIELDS as Readonly<Record<string, string>>)[name];
  if (directory && Array.isArray(leaf.value)) {
    for (const id of leaf.value) {
      if (typeof id === 'string' && UUID.test(id)) {
        (directory === 'department' ? stats.departmentIds : stats.userIds).add(id);
      }
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------------------------

const ACTION_KEYS: Readonly<Record<string, readonly string[]>> = {
  ALLOW: ['type'],
  REQUIRE_APPROVAL: ['type'],
  QUARANTINE: ['type'],
  ARCHIVE: ['type'],
  REJECT: ['type', 'notifySender'],
  TAG: ['type', 'label', 'subjectPrefix', 'addHeader'],
  WARN: ['type', 'level', 'text', 'subjectPrefix'],
  URL_REWRITE: ['type', 'ifNotRewritten'],
  ALERT: ['type', 'severity'],
};

function checkAction(c: Collector, a: unknown, at: readonly Segment[]): string | null {
  if (!isPlainObject(a)) {
    c.add(at, 'value_invalid', 'Expected an action object');
    return null;
  }
  const type = a.type;
  if (type === undefined) {
    c.add([...at, 'type'], 'value_required', 'Missing type');
    return null;
  }
  if (typeof type !== 'string' || !(POLICY_ACTION_TYPES as readonly string[]).includes(type)) {
    c.add([...at, 'type'], 'unknown_action', 'Unknown action type');
    return null;
  }
  checkKeys(c, a, ACTION_KEYS[type]!, at);
  const bool = (key: string) => {
    if (a[key] !== undefined && typeof a[key] !== 'boolean') {
      c.add([...at, key], 'value_invalid', 'Expected true or false');
    }
  };
  const prefix = () => {
    if (a.subjectPrefix !== undefined && !isSubjectPrefix(a.subjectPrefix)) {
      c.add(
        [...at, 'subjectPrefix'],
        'value_invalid',
        'Subject prefix: printable ASCII, 1..32 characters, no colon',
      );
    }
  };
  switch (type) {
    case 'REJECT':
      bool('notifySender');
      break;
    case 'TAG':
      if (a.label === undefined) c.add([...at, 'label'], 'value_required', 'Missing label');
      else if (!isTagLabel(a.label)) {
        c.add([...at, 'label'], 'value_invalid', 'Label: [a-z0-9][a-z0-9._-]{0,31}');
      }
      prefix();
      bool('addHeader');
      break;
    case 'WARN':
      if (a.level === undefined) c.add([...at, 'level'], 'value_required', 'Missing level');
      else if (!(WARN_LEVELS as readonly unknown[]).includes(a.level)) {
        c.add([...at, 'level'], 'value_invalid', 'Expected caution, warning or danger');
      }
      if (a.text !== undefined && !isHeaderText(a.text)) {
        c.add([...at, 'text'], 'value_invalid', 'Text: printable ASCII, 1..128 characters');
      }
      prefix();
      break;
    case 'URL_REWRITE':
      if (
        a.ifNotRewritten !== undefined &&
        !(URL_REWRITE_FALLBACKS as readonly unknown[]).includes(a.ifNotRewritten)
      ) {
        c.add([...at, 'ifNotRewritten'], 'value_invalid', 'Expected deliver or quarantine');
      }
      break;
    case 'ALERT':
      if (a.severity === undefined)
        c.add([...at, 'severity'], 'value_required', 'Missing severity');
      else if (!(ALERT_SEVERITIES as readonly unknown[]).includes(a.severity)) {
        c.add([...at, 'severity'], 'value_invalid', 'Expected info, warning or critical');
      }
      break;
    default:
      break;
  }
  return type;
}

// ---------------------------------------------------------------------------------------------
// Rules and the document
// ---------------------------------------------------------------------------------------------

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
const DOC_KEYS = ['dslVersion', 'direction', 'priority', 'rules', 'exceptions'];

interface WalkResult {
  violations: Violation[];
  references: DirectoryReferences;
  hasOverrideRules: boolean;
  ruleCount: number;
}

function priorityOk(v: unknown): v is number {
  return isInt(v) && v >= 0 && v <= POLICY_LIMITS.priorityMax;
}

function checkRule(
  c: Collector,
  rule: unknown,
  i: number,
  policyDirection: PolicyDirection | null,
  seen: { ids: Set<string>; priorities: Set<number> },
  stats: Pick<NodeStats, 'departmentIds' | 'userIds'>,
): { override: boolean } {
  const at: Segment[] = ['rules', i];
  if (!isPlainObject(rule)) {
    c.add(at, 'value_invalid', 'Expected a rule object');
    return { override: false };
  }
  checkKeys(c, rule, RULE_KEYS, at);
  if (rule.id === undefined) c.add([...at, 'id'], 'value_required', 'Missing id');
  else if (typeof rule.id !== 'string' || !RULE_ID.test(rule.id)) {
    c.add([...at, 'id'], 'value_invalid', 'Rule id: [a-z0-9][a-z0-9_-]{0,47}');
  } else if (seen.ids.has(rule.id)) {
    c.add([...at, 'id'], 'duplicate_rule_id', 'Rule ids are unique in a policy');
  } else seen.ids.add(rule.id);
  if (rule.priority === undefined) c.add([...at, 'priority'], 'value_required', 'Missing priority');
  else if (!priorityOk(rule.priority)) {
    c.add([...at, 'priority'], 'value_invalid', 'Expected an integer 0..10000');
  } else if (seen.priorities.has(rule.priority)) {
    c.add([...at, 'priority'], 'duplicate_rule_priority', 'Rule priorities are unique in a policy');
  } else seen.priorities.add(rule.priority);
  if (rule.description !== undefined) {
    const d = rule.description;
    if (typeof d !== 'string' || d.length > POLICY_LIMITS.descriptionLength || CONTROL.test(d)) {
      c.add(
        [...at, 'description'],
        'value_invalid',
        'Description: up to 256 characters, no control characters',
      );
    }
  }
  for (const key of ['enabled', 'stop', 'override'] as const) {
    if (rule[key] !== undefined && typeof rule[key] !== 'boolean') {
      c.add([...at, key], 'value_invalid', 'Expected true or false');
    }
  }
  if (rule.directions !== undefined) {
    const dirs = rule.directions;
    if (!Array.isArray(dirs) || dirs.length < 1 || new Set(dirs).size !== dirs.length) {
      c.add([...at, 'directions'], 'value_invalid', 'Expected unique inbound/outbound/internal');
    } else {
      dirs.forEach((d, k) => {
        if (!(POLICY_MESSAGE_DIRECTIONS as readonly unknown[]).includes(d)) {
          c.add(
            [...at, 'directions', k],
            'value_invalid',
            'Expected inbound, outbound or internal',
          );
        } else if (policyDirection !== null && policyDirection !== 'any' && d !== policyDirection) {
          c.add(
            [...at, 'directions', k],
            'direction_not_in_policy',
            'Rule direction outside the policy direction',
          );
        }
      });
    }
  }

  // Actions.
  let disposition: PolicyDispositionAction | null = null;
  if (rule.actions === undefined) c.add([...at, 'actions'], 'value_required', 'Missing actions');
  else if (!Array.isArray(rule.actions) || rule.actions.length < 1) {
    c.add([...at, 'actions'], 'value_invalid', 'Expected 1..8 actions');
  } else {
    if (rule.actions.length > POLICY_LIMITS.actionsPerRule) {
      c.add(
        [...at, 'actions'],
        'limit_exceeded',
        `At most ${POLICY_LIMITS.actionsPerRule} actions`,
      );
    }
    const types = new Set<string>();
    rule.actions.forEach((a, j) => {
      const type = checkAction(c, a, [...at, 'actions', j]);
      if (type === null) return;
      if (isDispositionAction(type)) {
        if (disposition !== null) {
          c.add([...at, 'actions', j], 'multiple_dispositions', 'At most one disposition per rule');
        } else disposition = type;
      } else if (types.has(type)) {
        c.add([...at, 'actions', j], 'duplicate_action', `${type} at most once per rule`);
      }
      types.add(type);
    });
  }
  const override = rule.override === true;
  if (override && disposition === null) {
    c.add(
      [...at, 'override'],
      'override_without_disposition',
      'override needs a disposition action',
    );
  }

  // Conditions.
  const ruleStats: NodeStats = {
    nodes: 0,
    aiLeaves: [],
    departmentIds: stats.departmentIds,
    userIds: stats.userIds,
  };
  const relaxing = disposition === 'ALLOW' || override;
  if (rule.when === undefined) c.add([...at, 'when'], 'value_required', 'Missing when');
  else checkNode(c, rule.when, [...at, 'when'], { kind: 'when', relaxing }, 1, ruleStats);
  if (rule.unless !== undefined) {
    if (!Array.isArray(rule.unless)) {
      c.add([...at, 'unless'], 'value_invalid', 'Expected a list of exception nodes');
    } else {
      if (rule.unless.length > POLICY_LIMITS.exceptionsPerRule) {
        c.add(
          [...at, 'unless'],
          'limit_exceeded',
          `At most ${POLICY_LIMITS.exceptionsPerRule} exceptions`,
        );
      }
      rule.unless.forEach((node, k) =>
        checkNode(c, node, [...at, 'unless', k], { kind: 'exception', relaxing }, 1, ruleStats),
      );
    }
  }
  if (ruleStats.nodes > POLICY_LIMITS.nodesPerRule) {
    c.add(at, 'limit_exceeded', `At most ${POLICY_LIMITS.nodesPerRule} nodes per rule`);
  }
  const d = disposition as PolicyDispositionAction | null;
  if (d !== null && POLICY_HOLD_DISPOSITIONS.includes(DISPOSITION_OF_ACTION[d])) {
    for (const leaf of ruleStats.aiLeaves) {
      c.add(
        leaf,
        'ai_field_in_hold_rule',
        'Rules reading AI-derived fields cannot REQUIRE_APPROVAL, QUARANTINE or REJECT',
      );
    }
  }
  return { override: override && disposition !== null };
}

function walk(doc: unknown): WalkResult {
  const c = new Collector();
  const departmentIds = new Set<string>();
  const userIds = new Set<string>();
  let hasOverrideRules = false;
  let ruleCount = 0;
  const done = (): WalkResult => ({
    violations: c.sorted(),
    references: {
      departmentIds: [...departmentIds].sort(),
      userIds: [...userIds].sort(),
    },
    hasOverrideRules,
    ruleCount,
  });
  if (!isPlainObject(doc)) {
    c.add([], 'value_invalid', 'Expected a policy-dsl/1 document object');
    return done();
  }
  try {
    const bytes = Buffer.byteLength(canonicalJson(doc), 'utf8');
    if (bytes > POLICY_LIMITS.documentBytes) {
      c.add([], 'limit_exceeded', `Document larger than ${POLICY_LIMITS.documentBytes} bytes`);
    }
  } catch {
    c.add([], 'value_invalid', 'The document is not plain JSON');
  }
  checkKeys(c, doc, DOC_KEYS, []);
  if (doc.dslVersion === undefined) c.add(['dslVersion'], 'value_required', 'Missing dslVersion');
  else if (doc.dslVersion !== POLICY_DSL_VERSION) {
    c.add(['dslVersion'], 'dsl_version_unsupported', `Expected ${POLICY_DSL_VERSION}`);
  }
  let direction: PolicyDirection | null = null;
  if (doc.direction === undefined) c.add(['direction'], 'value_required', 'Missing direction');
  else if (!(POLICY_DIRECTIONS as readonly unknown[]).includes(doc.direction)) {
    c.add(['direction'], 'value_invalid', 'Expected inbound, outbound, internal or any');
  } else direction = doc.direction as PolicyDirection;
  if (doc.priority === undefined) c.add(['priority'], 'value_required', 'Missing priority');
  else if (!priorityOk(doc.priority)) {
    c.add(['priority'], 'value_invalid', 'Expected an integer 0..10000');
  }
  if (doc.rules === undefined) c.add(['rules'], 'value_required', 'Missing rules');
  else if (!Array.isArray(doc.rules) || doc.rules.length < 1) {
    c.add(['rules'], 'value_invalid', 'Expected 1..100 rules');
  } else {
    if (doc.rules.length > POLICY_LIMITS.rulesPerPolicy) {
      c.add(['rules'], 'limit_exceeded', `At most ${POLICY_LIMITS.rulesPerPolicy} rules`);
    }
    ruleCount = doc.rules.length;
    const seen = { ids: new Set<string>(), priorities: new Set<number>() };
    doc.rules.forEach((rule, i) => {
      if (checkRule(c, rule, i, direction, seen, { departmentIds, userIds }).override) {
        hasOverrideRules = true;
      }
    });
  }
  if (doc.exceptions !== undefined) {
    if (!Array.isArray(doc.exceptions)) {
      c.add(['exceptions'], 'value_invalid', 'Expected a list of exception nodes');
    } else {
      if (doc.exceptions.length > POLICY_LIMITS.exceptionsPerPolicy) {
        c.add(
          ['exceptions'],
          'limit_exceeded',
          `At most ${POLICY_LIMITS.exceptionsPerPolicy} exceptions`,
        );
      }
      const stats: NodeStats = { nodes: 0, aiLeaves: [], departmentIds, userIds };
      doc.exceptions.forEach((node, k) =>
        checkNode(c, node, ['exceptions', k], { kind: 'exception', relaxing: false }, 1, stats),
      );
      if (stats.nodes > POLICY_LIMITS.nodesPerPolicyExceptions) {
        c.add(
          ['exceptions'],
          'limit_exceeded',
          `At most ${POLICY_LIMITS.nodesPerPolicyExceptions} exception nodes`,
        );
      }
    }
  }
  return done();
}

// ---------------------------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------------------------

/**
 * The strict `policy-dsl/1` schema: every check of `validatePolicyDefinition` as one zod
 * refinement (issues carry `params.code`). The parsed value is a deep copy of the document as
 * written (defaults are applied by the compiler, so the stored definition and its hash are
 * exactly what the tenant wrote).
 */
export const policyDefinitionSchema = z
  .unknown()
  .superRefine((doc, ctx) => {
    for (const v of walk(doc).violations) {
      ctx.addIssue({
        code: 'custom',
        message: v.message,
        path: [v.path],
        params: { code: v.code },
      });
    }
  })
  .transform((doc) => JSON.parse(JSON.stringify(doc)) as PolicyDefinition);

export type ValidationResult =
  | {
      ok: true;
      definition: PolicyDefinition;
      references: DirectoryReferences;
      hasOverrideRules: boolean;
      ruleCount: number;
    }
  | { ok: false; violations: Violation[] };

/** Validates a document and returns all violations sorted by path (P2). Never throws. */
export function validatePolicyDefinition(doc: unknown): ValidationResult {
  const result = walk(doc);
  if (result.violations.length > 0) return { ok: false, violations: result.violations };
  return {
    ok: true,
    definition: JSON.parse(JSON.stringify(doc)) as PolicyDefinition,
    references: result.references,
    hasOverrideRules: result.hasOverrideRules,
    ruleCount: result.ruleCount,
  };
}
