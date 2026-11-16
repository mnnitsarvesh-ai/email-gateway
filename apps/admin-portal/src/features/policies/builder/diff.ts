import type { BuilderCatalog } from './catalog';
import {
  canonicalJson,
  canonicalPrettyJson,
  isPlainObject,
  parseDefinition,
  rulesByPriority,
  type BuilderDefinition,
  type BuilderRule,
} from './model';
import {
  exceptionLines,
  humanizeValue,
  lineText,
  summarizeRule,
  type DirectoryNames,
  type SummaryLine,
} from './summary';

/**
 * Version diff (design B10; presentation only): policy-level changes, rules aligned by rule id
 * with property changes and line diffs of their `IF`, `UNLESS` and `THEN` summary lines, and a
 * line diff of the canonical pretty JSON. Line diffs use Myers' O((N+M)D) algorithm.
 */

export type LineDiff = Array<{ op: 'equal' | 'insert' | 'delete'; text: string }>;

export interface DefinitionDiff {
  policy: Array<{
    property: 'direction' | 'priority' | 'exceptions';
    before: string;
    after: string;
  }>;
  rules: Array<{
    ruleId: string;
    change: 'added' | 'removed' | 'changed' | 'unchanged';
    properties: Array<{ property: string; before: string; after: string }>;
    when: LineDiff;
    unless: LineDiff;
    then: LineDiff;
  }>;
  json: LineDiff;
  counts: { added: number; removed: number; changed: number };
}

// ---------------------------------------------------------------------------------------------
// Myers
// ---------------------------------------------------------------------------------------------

function myers(a: readonly string[], b: readonly string[]): LineDiff {
  const n = a.length;
  const m = b.length;
  const max = n + m;
  if (max === 0) return [];
  const offset = max + 1;
  const v = new Int32Array(2 * max + 3);
  // trace[d][k + d] = furthest x on diagonal k after d edits.
  const trace: Int32Array[] = [];
  let found = -1;
  for (let d = 0; d <= max && found < 0; d += 1) {
    for (let k = -d; k <= d; k += 2) {
      let x =
        k === -d || (k !== d && v[offset + k - 1]! < v[offset + k + 1]!)
          ? v[offset + k + 1]!
          : v[offset + k - 1]! + 1;
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) {
        x += 1;
        y += 1;
      }
      v[offset + k] = x;
      if (x >= n && y >= m) found = d;
    }
    trace.push(v.slice(offset - d, offset + d + 1));
  }
  const ops: LineDiff = [];
  let x = n;
  let y = m;
  for (let d = found; d > 0; d -= 1) {
    const previous = trace[d - 1]!;
    const at = (k: number): number => previous[k + d - 1]!;
    const k = x - y;
    const prevK = k === -d || (k !== d && at(k - 1) < at(k + 1)) ? k + 1 : k - 1;
    const prevX = at(prevK);
    const prevY = prevX - prevK;
    while (x > prevX && y > prevY) {
      ops.push({ op: 'equal', text: a[x - 1]! });
      x -= 1;
      y -= 1;
    }
    if (x === prevX) ops.push({ op: 'insert', text: b[prevY]! });
    else ops.push({ op: 'delete', text: a[prevX]! });
    x = prevX;
    y = prevY;
  }
  while (x > 0 && y > 0) {
    ops.push({ op: 'equal', text: a[x - 1]! });
    x -= 1;
    y -= 1;
  }
  return ops.reverse();
}

/** A shortest edit script from `a` to `b` (equal, delete and insert lines in order). */
export function lineDiff(a: readonly string[], b: readonly string[]): LineDiff {
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start += 1;
  let endA = a.length;
  let endB = b.length;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) {
    endA -= 1;
    endB -= 1;
  }
  const head: LineDiff = a.slice(0, start).map((text) => ({ op: 'equal', text }));
  const tail: LineDiff = a.slice(endA).map((text) => ({ op: 'equal', text }));
  return [...head, ...myers(a.slice(start, endA), b.slice(start, endB)), ...tail];
}

export const isUnchanged = (diff: LineDiff): boolean => diff.every((line) => line.op === 'equal');

// ---------------------------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------------------------

const textOf = (lines: readonly SummaryLine[]): string[] =>
  lines.map((line) => `${'  '.repeat(Math.max(0, line.depth - 1))}${lineText(line)}`);

const NOT_SET = 'Not set';

const show = (value: unknown): string =>
  typeof value === 'string' ? value : (JSON.stringify(value) ?? NOT_SET);

function propertyText(property: string, value: unknown): string {
  if (value === undefined) return NOT_SET;
  switch (property) {
    case 'enabled':
      return value === true ? 'Enabled' : value === false ? 'Disabled' : show(value);
    case 'stop':
      return value === true ? 'Stop' : value === false ? 'Continue' : show(value);
    case 'override':
      return value === true ? 'Yes' : value === false ? 'No' : show(value);
    case 'directions':
      return Array.isArray(value)
        ? value.map((d) => (typeof d === 'string' ? humanizeValue(d) : show(d))).join(', ')
        : show(value);
    default:
      return show(value);
  }
}

const RULE_PROPERTIES = [
  'priority',
  'enabled',
  'directions',
  'description',
  'stop',
  'override',
] as const;

interface Aligned {
  readonly id: string;
  readonly rule: BuilderRule;
  readonly index: number;
  readonly raw: unknown;
}

/** Rules keyed by id (a repeated id gets `#2`, `#3`… so nothing is lost). */
function alignRules(model: BuilderDefinition, raw: unknown): Map<string, Aligned> {
  const rawRules = isPlainObject(raw) && Array.isArray(raw.rules) ? raw.rules : [];
  const out = new Map<string, Aligned>();
  const seen = new Map<string, number>();
  model.rules.forEach((rule, index) => {
    const n = (seen.get(rule.id) ?? 0) + 1;
    seen.set(rule.id, n);
    out.set(n === 1 ? rule.id : `${rule.id}#${n}`, {
      id: rule.id,
      rule,
      index,
      raw: rawRules[index],
    });
  });
  return out;
}

const exceptionsText = (
  catalog: BuilderCatalog,
  model: BuilderDefinition,
  names?: DirectoryNames,
) => {
  const lines = textOf(
    exceptionLines(catalog, model, names, { listCut: Number.POSITIVE_INFINITY }),
  );
  return lines.length === 0 ? 'None' : lines.join('\n');
};

/** Differences from version `a` to version `b` (either may be any JSON; unparsable → JSON only). */
export function diffDefinitions(
  a: unknown,
  b: unknown,
  catalog: BuilderCatalog,
  names?: DirectoryNames,
): DefinitionDiff {
  const json = lineDiff(
    canonicalPrettyJson(a ?? null).split('\n'),
    canonicalPrettyJson(b ?? null).split('\n'),
  );
  const pa = parseDefinition(a);
  const pb = parseDefinition(b);
  if (!pa.ok || !pb.ok) {
    return { policy: [], rules: [], json, counts: { added: 0, removed: 0, changed: 0 } };
  }
  const ma = pa.model;
  const mb = pb.model;
  const policy: DefinitionDiff['policy'] = [];
  if (ma.direction !== mb.direction) {
    policy.push({
      property: 'direction',
      before: humanizeValue(ma.direction),
      after: humanizeValue(mb.direction),
    });
  }
  if (ma.priority !== mb.priority) {
    policy.push({ property: 'priority', before: String(ma.priority), after: String(mb.priority) });
  }
  const exA = exceptionsText(catalog, ma, names);
  const exB = exceptionsText(catalog, mb, names);
  if (
    canonicalJson(isPlainObject(a) ? a.exceptions : undefined) !==
    canonicalJson(isPlainObject(b) ? b.exceptions : undefined)
  ) {
    policy.push({ property: 'exceptions', before: exA, after: exB });
  }

  const options = { includePolicyDirection: false, listCut: Number.POSITIVE_INFINITY };
  const rulesA = alignRules(ma, a);
  const rulesB = alignRules(mb, b);
  const order = [
    ...rulesByPriority(
      [...rulesB.entries()].map(([key, item]) => ({ key, priority: item.rule.priority })),
    ).map((x) => x.key),
    ...rulesByPriority(
      [...rulesA.entries()]
        .filter(([key]) => !rulesB.has(key))
        .map(([key, item]) => ({ key, priority: item.rule.priority })),
    ).map((x) => x.key),
  ];
  const counts = { added: 0, removed: 0, changed: 0 };
  const rules: DefinitionDiff['rules'] = order.map((key) => {
    const before = rulesA.get(key);
    const after = rulesB.get(key);
    const sa = before
      ? summarizeRule(catalog, ma, before.rule, before.index, names, options)
      : null;
    const sb = after ? summarizeRule(catalog, mb, after.rule, after.index, names, options) : null;
    const when = lineDiff(sa ? textOf(sa.when) : [], sb ? textOf(sb.when) : []);
    const unless = lineDiff(sa ? textOf(sa.unless) : [], sb ? textOf(sb.unless) : []);
    const then = lineDiff(sa ? textOf(sa.then) : [], sb ? textOf(sb.then) : []);
    const properties: Array<{ property: string; before: string; after: string }> = [];
    let change: DefinitionDiff['rules'][number]['change'];
    if (!before) {
      change = 'added';
      counts.added += 1;
    } else if (!after) {
      change = 'removed';
      counts.removed += 1;
    } else {
      for (const property of RULE_PROPERTIES) {
        const x = before.rule[property];
        const y = after.rule[property];
        if (canonicalJson(x) !== canonicalJson(y) || (x === undefined) !== (y === undefined)) {
          properties.push({
            property,
            before: propertyText(property, x),
            after: propertyText(property, y),
          });
        }
      }
      change = canonicalJson(before.raw) === canonicalJson(after.raw) ? 'unchanged' : 'changed';
      if (change === 'changed') counts.changed += 1;
    }
    return { ruleId: (after ?? before)!.id, change, properties, when, unless, then };
  });
  return { policy, rules, json, counts };
}
