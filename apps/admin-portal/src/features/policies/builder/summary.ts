import { humanize } from '@/lib/format';
import {
  actionOf,
  fieldOf,
  isAllDirections,
  operatorOf,
  quantifierOf,
  type BuilderCatalog,
  type CatalogField,
  type CatalogOperator,
} from './catalog';
import {
  isPlainObject,
  parseDefinition,
  rulesByPriority,
  type BuilderAction,
  type BuilderDefinition,
  type BuilderLeaf,
  type BuilderNode,
  type BuilderRule,
} from './model';
import { childPath } from './paths';

/**
 * The readable policy summary (design B5; ADR-0063 decision 6): pure presentation of the
 * document with the catalogue's labels and phrases. It describes conditions and actions; it never
 * states what would happen to a message. Grammar: per rule a title line, `IF:` lines (the
 * direction first), `AND`/`OR` joiners per group with nested groups under `all of:`/`any of:`,
 * `NOT:` for negations, `UNLESS:` for rule exceptions, `THEN:` action lines joined with `AND`,
 * notes; then the policy-wide exceptions.
 */

export interface SummaryToken {
  kind: 'keyword' | 'field' | 'op' | 'value' | 'text';
  text: string;
}
export interface SummaryLine {
  /** Indentation level (1 = directly under `IF:`/`UNLESS:`/`THEN:`). */
  depth: number;
  tokens: SummaryToken[];
  /** DSL path of the node, action or key the line describes. */
  path: string | null;
}
export interface RuleSummary {
  ruleId: string;
  title: string;
  priority: number;
  enabled: boolean;
  when: SummaryLine[];
  unless: SummaryLine[];
  then: SummaryLine[];
  notes: string[];
}
export interface PolicySummaryDoc {
  header: SummaryLine[];
  rules: RuleSummary[];
  exceptions: SummaryLine[];
  floorNote: string;
}
/** Directory names by public id (department and user pickers), for ids in conditions. */
export interface DirectoryNames {
  departments?: ReadonlyMap<string, string>;
  users?: ReadonlyMap<string, string>;
}

/**
 * The catalogue field whose label names the policy and rule direction keys (the document keys
 * `direction`/`directions` describe the same fact as this field).
 */
const DIRECTION_FIELD = 'direction';
const LIST_CUT = 5;
const ELLIPSIS = '…';

export const NOTE_STOP = 'Then stop evaluating later rules';
export const NOTE_CONTINUE = 'Then continue with later rules';
export const NOTE_OVERRIDE =
  'May override a level-only platform recommendation (requires the organization setting)';

const kw = (text: string): SummaryToken => ({ kind: 'keyword', text });
const tx = (text: string): SummaryToken => ({ kind: 'text', text });
const SP: SummaryToken = { kind: 'text', text: ' ' };

/** `payment_card` → `Payment card`; dotted machine codes (`hb.dlp_block`) stay as written. */
export function humanizeValue(value: string): string {
  return value.includes('.') ? value : humanize(value);
}

const capitalize = (value: string): string => value.charAt(0).toUpperCase() + value.slice(1);

/** Bytes with the largest binary unit that keeps at most two exact decimals (`10 MiB`). */
export function formatBytesExact(bytes: number): string {
  const units: Array<[string, number]> = [
    ['GiB', 1024 ** 3],
    ['MiB', 1024 ** 2],
    ['KiB', 1024],
  ];
  for (const [unit, factor] of units) {
    if (Math.abs(bytes) >= factor && (bytes * 100) % factor === 0) {
      return `${String(Number((bytes / factor).toFixed(2)))} ${unit}`;
    }
  }
  return `${String(bytes)} B`;
}

const json = (value: unknown): string => {
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
};

interface Context {
  readonly catalog: BuilderCatalog;
  readonly names: DirectoryNames | undefined;
  /** Items shown per list before "and N more". */
  readonly listCut: number;
}

function directoryName(ctx: Context, id: string): string {
  return ctx.names?.departments?.get(id) ?? ctx.names?.users?.get(id) ?? id.slice(0, 8);
}

function scalarText(ctx: Context, field: CatalogField | null, value: unknown): string {
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (typeof value === 'number') {
    return field?.unit === 'bytes' && Number.isFinite(value)
      ? formatBytesExact(value)
      : String(value);
  }
  if (typeof value === 'string') {
    if (field?.type === 'id') return directoryName(ctx, value);
    if (field && (field.values !== null || field.type === 'enum' || field.type === 'codes')) {
      return humanizeValue(value);
    }
    return value;
  }
  return json(value);
}

function regexText(item: unknown): string {
  if (typeof item === 'string') return `/${item}/`;
  if (isPlainObject(item) && typeof item.pattern === 'string') {
    const flags = typeof item.flags === 'string' ? item.flags : '';
    return `/${item.pattern}/${flags}`;
  }
  return json(item);
}

function itemText(
  ctx: Context,
  field: CatalogField | null,
  itemKind: string | null,
  item: unknown,
): string {
  switch (itemKind) {
    case 'regex':
      return regexText(item);
    case 'code':
      return typeof item === 'string' ? humanizeValue(item) : json(item);
    case 'domain':
    case 'glob':
    case 'cidr':
      return typeof item === 'string' ? item : json(item);
    default:
      return scalarText(ctx, field, item);
  }
}

/** Value tokens of a list, cut after five items ("and 12 more"). */
function listTokens(items: readonly string[], cut: number = LIST_CUT): SummaryToken[] {
  if (items.length === 0) return [tx(ELLIPSIS)];
  const tokens: SummaryToken[] = [];
  items.slice(0, cut).forEach((item, i) => {
    if (i > 0) tokens.push(tx(', '));
    tokens.push({ kind: 'value', text: item });
  });
  if (items.length > cut) tokens.push(tx(` and ${items.length - cut} more`));
  return tokens;
}

function timeText(value: Record<string, unknown>, windowKind: boolean): string {
  const str = (key: string): string => (typeof value[key] === 'string' ? value[key] : ELLIPSIS);
  const zone = str('timeZone');
  if (windowKind) {
    const days = Array.isArray(value.days)
      ? value.days.map((day) => (typeof day === 'string' ? capitalize(day) : json(day))).join(', ')
      : ELLIPSIS;
    return `${days} ${str('from')}-${str('to')} (${zone})`;
  }
  return `${str('from')} to ${str('to')} (${zone})`;
}

/** The value part of a condition line (`[]` for operators without a value). */
function valueTokens(
  ctx: Context,
  field: CatalogField | null,
  operator: CatalogOperator | null,
  value: unknown,
): SummaryToken[] {
  const shape =
    operator?.valueShape ??
    (value === undefined
      ? 'none'
      : Array.isArray(value)
        ? 'list'
        : typeof value === 'boolean'
          ? 'boolean'
          : 'scalar');
  if (shape === 'none') return value === undefined ? [] : [{ kind: 'value', text: json(value) }];
  if (value === undefined) return [tx(ELLIPSIS)];
  switch (shape) {
    case 'boolean':
      return [{ kind: 'value', text: scalarText(ctx, field, value) }];
    case 'list':
      if (!Array.isArray(value)) return [{ kind: 'value', text: json(value) }];
      return listTokens(
        value.map((item) => itemText(ctx, field, operator?.itemKind ?? null, item)),
        ctx.listCut,
      );
    case 'range':
      if (!Array.isArray(value) || value.length !== 2)
        return [{ kind: 'value', text: json(value) }];
      return [
        { kind: 'value', text: scalarText(ctx, field, value[0]) },
        tx(' and '),
        { kind: 'value', text: scalarText(ctx, field, value[1]) },
      ];
    case 'time':
      if (!isPlainObject(value)) return [{ kind: 'value', text: json(value) }];
      return [
        { kind: 'value', text: timeText(value, 'days' in value || timeKindOf(field) === 'window') },
      ];
    default:
      return [{ kind: 'value', text: scalarText(ctx, field, value) }];
  }
}

/**
 * Which time value a `time` field takes. The catalogue does not state it: the last segment of
 * the field name decides (`window` → weekly window, `date_range` → date range); `null` for any
 * other time field (the value's own keys decide).
 */
export function timeKindOf(
  field: Pick<CatalogField, 'name' | 'type'> | null,
): 'window' | 'date_range' | null {
  if (!field || field.type !== 'time') return null;
  const last = field.name.slice(field.name.lastIndexOf('.') + 1);
  return last === 'window' ? 'window' : last === 'date_range' ? 'date_range' : null;
}

function leafTokens(ctx: Context, leaf: BuilderLeaf, inException: boolean): SummaryToken[] {
  if (leaf.field === undefined) return [tx('Incomplete condition')];
  const field = fieldOf(ctx.catalog, leaf.field);
  const operator = operatorOf(ctx.catalog, leaf.op);
  const tokens: SummaryToken[] = [];
  const quantified = field ? field.quantified : leaf.quantifier !== undefined;
  if (quantified && (leaf.quantifier !== undefined || inException)) {
    const id = leaf.quantifier ?? ctx.catalog.contextRules.defaultQuantifier;
    const phrase = quantifierOf(ctx.catalog, id)?.phrase ?? id;
    const noun = field ? (ctx.catalog.scopeNouns[field.scope] ?? field.scope) : 'item';
    tokens.push(tx(`${phrase} ${noun}: `));
  }
  tokens.push({ kind: 'field', text: field?.label ?? leaf.field });
  tokens.push(SP, { kind: 'op', text: operator?.phrase ?? leaf.op ?? ELLIPSIS });
  const values = valueTokens(ctx, field, operator, leaf.value);
  if (values.length > 0) tokens.push(SP, ...values);
  return tokens;
}

function nodeLines(
  ctx: Context,
  node: BuilderNode,
  depth: number,
  prefix: SummaryToken[],
  path: string,
  inException: boolean,
): SummaryLine[] {
  if (node.kind === 'not') {
    return nodeLines(
      ctx,
      node.child,
      depth,
      [...prefix, kw('NOT:'), SP],
      childPath(path, 'not'),
      inException,
    );
  }
  if (node.kind === 'group') {
    const lines: SummaryLine[] = [
      { depth, tokens: [...prefix, kw(node.joiner === 'all' ? 'all of:' : 'any of:')], path },
    ];
    const joiner = node.joiner === 'all' ? 'AND' : 'OR';
    const base = childPath(path, node.joiner);
    node.children.forEach((child, i) => {
      lines.push(
        ...nodeLines(
          ctx,
          child,
          depth + 1,
          i === 0 ? [] : [kw(joiner), SP],
          childPath(base, i),
          inException,
        ),
      );
    });
    if (node.children.length === 0) {
      lines.push({ depth: depth + 1, tokens: [tx('No conditions')], path });
    }
    return lines;
  }
  return [{ depth, tokens: [...prefix, ...leafTokens(ctx, node, inException)], path }];
}

/** Top-level items joined with one keyword (the first item without). */
function joinedLines(
  ctx: Context,
  lead: SummaryLine[],
  items: ReadonlyArray<{ node: BuilderNode; path: string }>,
  joiner: 'AND' | 'OR',
  inException: boolean,
): SummaryLine[] {
  const lines = [...lead];
  for (const item of items) {
    const prefix = lines.length === 0 ? [] : [kw(joiner), SP];
    lines.push(...nodeLines(ctx, item.node, 1, prefix, item.path, inException));
  }
  return lines;
}

function directionLine(
  ctx: Context,
  model: BuilderDefinition,
  rule: BuilderRule,
  rulePath: string,
  includePolicyDirection: boolean,
): SummaryLine | null {
  const label = fieldOf(ctx.catalog, DIRECTION_FIELD)?.label ?? 'Direction';
  if (rule.directions !== undefined) {
    return {
      depth: 1,
      tokens: [
        { kind: 'field', text: label },
        SP,
        { kind: 'op', text: rule.directions.length === 1 ? 'is' : 'is one of' },
        SP,
        ...listTokens(rule.directions.map(humanizeValue), ctx.listCut),
      ],
      path: childPath(rulePath, 'directions'),
    };
  }
  if (!includePolicyDirection || isAllDirections(ctx.catalog, model.direction)) return null;
  return {
    depth: 1,
    tokens: [
      { kind: 'field', text: label },
      SP,
      { kind: 'op', text: 'is' },
      SP,
      { kind: 'value', text: humanizeValue(model.direction) },
    ],
    path: 'direction',
  };
}

function paramText(ctx: Context, action: BuilderAction, name: string, value: unknown): string {
  const def = actionOf(ctx.catalog, action.type)?.params.find((p) => p.name === name);
  const label = (def?.label ?? name).toLowerCase();
  let shown: string;
  if (typeof value === 'boolean') shown = value ? 'yes' : 'no';
  else if (typeof value === 'string') shown = def?.type === 'enum' ? value : `"${value}"`;
  else shown = json(value);
  return `${label}: ${shown}`;
}

function actionTokens(ctx: Context, action: BuilderAction): SummaryToken[] {
  const def = actionOf(ctx.catalog, action.type);
  const tokens: SummaryToken[] = [{ kind: 'field', text: def?.label ?? action.type }];
  const order = def?.params.map((p) => p.name) ?? [];
  const names = [
    ...order.filter((name) => action.params[name] !== undefined),
    ...Object.keys(action.params).filter(
      (name) => !order.includes(name) && action.params[name] !== undefined,
    ),
  ];
  if (names.length > 0) {
    tokens.push(
      tx(` (${names.map((name) => paramText(ctx, action, name, action.params[name])).join(', ')})`),
    );
  }
  return tokens;
}

export interface SummaryOptions {
  /** Include the policy direction as the first `IF:` line (default true; the diff turns it off). */
  includePolicyDirection?: boolean;
  /** Items shown per list before "and N more" (default 5; the diff shows every item). */
  listCut?: number;
}

const contextOf = (
  catalog: BuilderCatalog,
  names: DirectoryNames | undefined,
  options: SummaryOptions,
): Context => ({ catalog, names, listCut: options.listCut ?? LIST_CUT });

/** One rule's summary (`ruleIndex` = its position in the document, for paths). */
export function summarizeRule(
  catalog: BuilderCatalog,
  model: BuilderDefinition,
  rule: BuilderRule,
  ruleIndex: number,
  names?: DirectoryNames,
  options: SummaryOptions = {},
): RuleSummary {
  const ctx = contextOf(catalog, names, options);
  const base = childPath('rules', ruleIndex);
  const whenPath = childPath(base, 'when');
  const dir = directionLine(ctx, model, rule, base, options.includePolicyDirection !== false);
  const root = rule.when;
  const flatten = root.kind === 'group' && (dir === null || root.joiner === 'all');
  const items =
    root.kind === 'group' && flatten
      ? root.children.map((node, j) => ({
          node,
          path: childPath(childPath(whenPath, root.joiner), j),
        }))
      : [{ node: root, path: whenPath }];
  const joiner = root.kind === 'group' && flatten && root.joiner === 'any' ? 'OR' : 'AND';
  const when = joinedLines(ctx, dir ? [dir] : [], items, joiner, false);
  if (when.length === 0) when.push({ depth: 1, tokens: [tx('No conditions')], path: whenPath });
  const unless = joinedLines(
    ctx,
    [],
    (rule.unless ?? []).map((node, k) => ({ node, path: childPath(childPath(base, 'unless'), k) })),
    'OR',
    true,
  );
  const then: SummaryLine[] = rule.actions.map((action, j) => ({
    depth: 1,
    tokens: [...(j === 0 ? [] : [kw('AND'), SP]), ...actionTokens(ctx, action)],
    path: childPath(childPath(base, 'actions'), j),
  }));
  if (then.length === 0) {
    then.push({ depth: 1, tokens: [tx('No action')], path: childPath(base, 'actions') });
  }
  const notes: string[] = [];
  if (rule.stop === true) notes.push(NOTE_STOP);
  if (rule.stop === false) notes.push(NOTE_CONTINUE);
  if (rule.override === true) notes.push(NOTE_OVERRIDE);
  const title = `Rule ${rule.id} (priority ${String(rule.priority)})${
    rule.description !== undefined && rule.description !== '' ? `: ${rule.description}` : ''
  }${rule.enabled === false ? ' (disabled)' : ''}`;
  return {
    ruleId: rule.id,
    title,
    priority: rule.priority,
    enabled: rule.enabled !== false,
    when,
    unless,
    then,
    notes,
  };
}

/** Policy-wide exception lines (joined with `OR`: any one of them exempts every rule). */
export function exceptionLines(
  catalog: BuilderCatalog,
  model: BuilderDefinition,
  names?: DirectoryNames,
  options: SummaryOptions = {},
): SummaryLine[] {
  return joinedLines(
    contextOf(catalog, names, options),
    [],
    (model.exceptions ?? []).map((node, k) => ({ node, path: childPath('exceptions', k) })),
    'OR',
    true,
  );
}

/**
 * The value of a condition as display text for read-only views (`10 MiB`, `Finance, Legal`);
 * every list item is shown (unlike the summary, which cuts lists after five).
 */
export function formatLeafValue(
  catalog: BuilderCatalog,
  leaf: Pick<BuilderLeaf, 'field' | 'op' | 'value'>,
  names?: DirectoryNames,
): string {
  const ctx = contextOf(catalog, names, { listCut: Number.POSITIVE_INFINITY });
  return valueTokens(ctx, fieldOf(catalog, leaf.field), operatorOf(catalog, leaf.op), leaf.value)
    .map((token) => token.text)
    .join('');
}

/** The summary of a model (rules in evaluation order). */
export function summarizeModel(
  model: BuilderDefinition,
  catalog: BuilderCatalog,
  names?: DirectoryNames,
  options: SummaryOptions = {},
): PolicySummaryDoc {
  const indexOfRule = new Map(model.rules.map((rule, i) => [rule.key, i]));
  const rules = rulesByPriority(model.rules).map((rule) =>
    summarizeRule(catalog, model, rule, indexOfRule.get(rule.key) ?? 0, names, options),
  );
  const header: SummaryLine[] =
    model.rules.length === 0
      ? [{ depth: 0, tokens: [tx('This policy has no rules.')], path: 'rules' }]
      : [];
  return {
    header,
    rules,
    exceptions: exceptionLines(catalog, model, names, options),
    floorNote: catalog.enforcement,
  };
}

/**
 * The readable summary of a `policy-dsl/1` document. A document the model does not accept
 * (unknown keys, another version) gets a header line saying why and no rules.
 */
export function summarizeDefinition(
  definition: unknown,
  catalog: BuilderCatalog,
  names?: DirectoryNames,
): PolicySummaryDoc {
  const parsed = parseDefinition(definition);
  if (!parsed.ok) {
    const why =
      parsed.reason === 'unsupported_version'
        ? 'This definition is not a policy-dsl/1 document; it is shown as JSON only.'
        : parsed.reason === 'unknown_key'
          ? `This definition has a key the builder does not know (${parsed.path}); it is shown as JSON only.`
          : parsed.reason === 'malformed'
            ? `This definition is malformed at ${parsed.path || 'the top level'}; it is shown as JSON only.`
            : 'This definition is not a JSON object.';
    return {
      header: [{ depth: 0, tokens: [tx(why)], path: parsed.path || null }],
      rules: [],
      exceptions: [],
      floorNote: catalog.enforcement,
    };
  }
  return summarizeModel(parsed.model, catalog, names);
}

export const lineText = (line: SummaryLine): string => line.tokens.map((t) => t.text).join('');

const indented = (line: SummaryLine): string => `${'  '.repeat(line.depth)}${lineText(line)}`;

/** One rule as text (title, `IF:`, `UNLESS:`, `THEN:` and notes). */
export function ruleSummaryText(rule: RuleSummary): string[] {
  const out = [rule.title, 'IF:', ...rule.when.map(indented)];
  if (rule.unless.length > 0) out.push('UNLESS:', ...rule.unless.map(indented));
  out.push('THEN:', ...rule.then.map(indented), ...rule.notes.map((note) => `  ${note}`));
  return out;
}

/** The summary as plain text (the B5 grammar; the floor note is not part of it). */
export function summaryToText(doc: PolicySummaryDoc): string {
  const blocks: string[][] = [];
  if (doc.header.length > 0) blocks.push(doc.header.map(indented));
  for (const rule of doc.rules) blocks.push(ruleSummaryText(rule));
  if (doc.exceptions.length > 0) {
    blocks.push(['Policy-wide exceptions:', ...doc.exceptions.map(indented)]);
  }
  return blocks.map((block) => block.join('\n')).join('\n\n');
}
