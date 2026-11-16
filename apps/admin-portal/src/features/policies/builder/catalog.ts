import { z } from 'zod';
import { newKey, MODEL_DSL_VERSION, type BuilderLeaf } from './model';

/**
 * The DSL catalogue as the builder reads it (step 7.3 design §4.1, §4.7, B1; ADR-0063 decision 1).
 * Every field, operator, value shape, vocabulary, unit, action, parameter, limit and placement
 * restriction the builder renders comes from `GET /api/v1/policies/catalog`; this module holds
 * no field name, operator list, vocabulary or DSL rule. The schema mirrors exactly the keys the
 * builder reads; objects are not strict, so extra keys of a newer api are ignored.
 */

export type BuilderPlace = 'when' | 'relaxingWhen' | 'holdRule' | 'exception';

/** Value shapes the builder has widgets for (§4.1 `operatorDefinitions[].valueShape`). */
export const KNOWN_VALUE_SHAPES = ['scalar', 'list', 'range', 'none', 'boolean', 'time'] as const;
export type ValueShape = (typeof KNOWN_VALUE_SHAPES)[number];

export interface CatalogFieldContexts {
  readonly when: boolean;
  readonly exception: boolean;
  readonly relaxingWhen: boolean;
  readonly holdRule: boolean;
}

export interface CatalogField {
  readonly name: string;
  readonly label: string;
  readonly group: string;
  readonly description: string;
  readonly type: string;
  readonly scope: string;
  readonly ops: readonly string[];
  readonly quantified: boolean;
  readonly senderIdentity: string | null;
  readonly aiDerived: boolean;
  readonly directions: readonly string[];
  readonly values: readonly string[] | null;
  readonly ordered: boolean;
  readonly min: number | null;
  readonly max: number | null;
  readonly unit: string | null;
  readonly suggestions: readonly string[] | null;
  readonly contexts: CatalogFieldContexts;
}

export interface CatalogOperator {
  readonly op: string;
  readonly label: string;
  readonly phrase: string;
  readonly valueShape: string;
  readonly itemKind: string | null;
  readonly maxItems: number | null;
  readonly maxItemLength: number | null;
  readonly negated: boolean;
  readonly allowedInException: boolean;
  readonly description: string;
}

export interface CatalogActionParam {
  readonly name: string;
  readonly label: string;
  readonly type: string;
  readonly required: boolean;
  readonly values: readonly string[] | null;
  readonly default: string | boolean | null;
  readonly minLength: number | null;
  readonly maxLength: number | null;
  readonly pattern: string | null;
  readonly description: string;
}

export interface CatalogAction {
  readonly type: string;
  readonly label: string;
  readonly phrase: string;
  readonly kind: string;
  readonly disposition: string | null;
  readonly params: readonly CatalogActionParam[];
  readonly description: string;
}

export interface CatalogFieldGroup {
  readonly id: string;
  readonly label: string;
}

export interface CatalogQuantifier {
  readonly id: string;
  readonly label: string;
  readonly phrase: string;
}

export interface CatalogContextRules {
  readonly defaultQuantifier: string;
  readonly exceptionQuantifier: string;
  readonly exceptionNegation: boolean;
  readonly relaxingDispositions: readonly string[];
  readonly holdDispositions: readonly string[];
}

/** Exactly the catalogue response fields the builder reads (§4.1 + existing keys). */
export interface BuilderCatalog {
  readonly versions: { readonly dsl: string };
  readonly fields: readonly CatalogField[];
  readonly operatorDefinitions: readonly CatalogOperator[];
  readonly actionDefinitions: readonly CatalogAction[];
  readonly fieldGroups: readonly CatalogFieldGroup[];
  readonly quantifiers: readonly CatalogQuantifier[];
  readonly scopeNouns: Readonly<Record<string, string>>;
  readonly contextRules: CatalogContextRules;
  readonly weekdays: readonly string[];
  readonly timeZones: readonly string[];
  readonly policyDirections: readonly string[];
  readonly messageDirections: readonly string[];
  /** The DSL limits with the deployment's organization bounds (`documentBytes`, `depth`, …). */
  readonly limits: Readonly<Record<string, number>>;
  /** The platform floor statement (shown under every summary). */
  readonly enforcement: string;
}

const text = z.string();
const strings = z.array(z.string());
const nullableInt = z.number().int().nullable();

const fieldSchema = z.object({
  name: z.string().min(1),
  label: z.string().min(1),
  group: z.string().min(1),
  description: text,
  type: z.string().min(1),
  scope: z.string().min(1),
  ops: strings,
  quantified: z.boolean(),
  senderIdentity: z.string().nullable(),
  aiDerived: z.boolean(),
  directions: strings,
  values: strings.nullable(),
  ordered: z.boolean(),
  min: z.number().nullable(),
  max: z.number().nullable(),
  unit: z.string().nullable(),
  suggestions: strings.nullable(),
  contexts: z.object({
    when: z.boolean(),
    exception: z.boolean(),
    relaxingWhen: z.boolean(),
    holdRule: z.boolean(),
  }),
});

const operatorSchema = z.object({
  op: z.string().min(1),
  label: z.string().min(1),
  phrase: z.string().min(1),
  valueShape: z.string().min(1),
  itemKind: z.string().nullable(),
  maxItems: nullableInt,
  maxItemLength: nullableInt,
  negated: z.boolean(),
  allowedInException: z.boolean(),
  description: text,
});

const paramSchema = z.object({
  name: z.string().min(1),
  label: z.string().min(1),
  type: z.string().min(1),
  required: z.boolean(),
  values: strings.nullable(),
  default: z.union([z.string(), z.boolean()]).nullable(),
  minLength: nullableInt,
  maxLength: nullableInt,
  pattern: z.string().nullable(),
  description: text,
});

const actionSchema = z.object({
  type: z.string().min(1),
  label: z.string().min(1),
  phrase: z.string().min(1),
  kind: z.string().min(1),
  disposition: z.string().nullable(),
  params: z.array(paramSchema),
  description: text,
});

const catalogSchema = z.object({
  versions: z.object({ dsl: z.string().min(1) }),
  fields: z.array(fieldSchema),
  operatorDefinitions: z.array(operatorSchema),
  actionDefinitions: z.array(actionSchema),
  fieldGroups: z.array(z.object({ id: z.string().min(1), label: z.string().min(1) })),
  quantifiers: z.array(
    z.object({ id: z.string().min(1), label: z.string().min(1), phrase: z.string().min(1) }),
  ),
  scopeNouns: z.record(z.string(), z.string()),
  contextRules: z.object({
    defaultQuantifier: z.string().min(1),
    exceptionQuantifier: z.string().min(1),
    exceptionNegation: z.boolean(),
    relaxingDispositions: strings,
    holdDispositions: strings,
  }),
  weekdays: strings,
  timeZones: strings,
  policyDirections: strings.min(1),
  messageDirections: strings.min(1),
  limits: z.record(z.string(), z.number()),
  enforcement: text,
});

// Compile-time proof that the parsed shape is a BuilderCatalog.
const _shapeCheck: z.ZodType<BuilderCatalog> = catalogSchema;
void _shapeCheck;

/** The catalogue response does not have the shape the builder needs. */
export class CatalogShapeError extends Error {
  constructor(readonly issues: readonly string[]) {
    super(`The policy catalogue cannot drive the builder: ${issues.slice(0, 5).join('; ')}`);
    this.name = 'CatalogShapeError';
  }
}

/** Checks a raw catalogue response (zod, non-strict) and returns the builder's view of it. */
export function toBuilderCatalog(raw: unknown): BuilderCatalog {
  const parsed = catalogSchema.safeParse(raw);
  if (!parsed.success) {
    throw new CatalogShapeError(
      parsed.error.issues.map(
        (issue) => `${issue.path.map(String).join('.') || '(root)'}: ${issue.message}`,
      ),
    );
  }
  if (parsed.data.versions.dsl !== MODEL_DSL_VERSION) {
    throw new CatalogShapeError([
      `versions.dsl: the builder edits ${MODEL_DSL_VERSION} documents, the catalogue describes ${parsed.data.versions.dsl}`,
    ]);
  }
  return parsed.data;
}

// ---------------------------------------------------------------------------------------------
// Lookups (indexed once per catalogue object)
// ---------------------------------------------------------------------------------------------

interface CatalogIndex {
  readonly fields: ReadonlyMap<string, CatalogField>;
  readonly operators: ReadonlyMap<string, CatalogOperator>;
  readonly actions: ReadonlyMap<string, CatalogAction>;
  readonly quantifiers: ReadonlyMap<string, CatalogQuantifier>;
}

const indexes = new WeakMap<BuilderCatalog, CatalogIndex>();

function indexOf(catalog: BuilderCatalog): CatalogIndex {
  let index = indexes.get(catalog);
  if (!index) {
    index = {
      fields: new Map(catalog.fields.map((f) => [f.name, f])),
      operators: new Map(catalog.operatorDefinitions.map((o) => [o.op, o])),
      actions: new Map(catalog.actionDefinitions.map((a) => [a.type, a])),
      quantifiers: new Map(catalog.quantifiers.map((q) => [q.id, q])),
    };
    indexes.set(catalog, index);
  }
  return index;
}

export const fieldOf = (catalog: BuilderCatalog, name: string | undefined): CatalogField | null =>
  name === undefined ? null : (indexOf(catalog).fields.get(name) ?? null);

export const operatorOf = (
  catalog: BuilderCatalog,
  op: string | undefined,
): CatalogOperator | null =>
  op === undefined ? null : (indexOf(catalog).operators.get(op) ?? null);

export const actionOf = (catalog: BuilderCatalog, type: string): CatalogAction | null =>
  indexOf(catalog).actions.get(type) ?? null;

export const quantifierOf = (catalog: BuilderCatalog, id: string): CatalogQuantifier | null =>
  indexOf(catalog).quantifiers.get(id) ?? null;

/** A catalogue limit, or `Infinity` when this catalogue does not state it. */
export function limitOf(
  limits: Readonly<Record<string, number>> | undefined,
  name: string,
): number {
  const value = limits?.[name];
  return typeof value === 'number' && Number.isFinite(value) ? value : Number.POSITIVE_INFINITY;
}

export const isKnownValueShape = (shape: string): shape is ValueShape =>
  (KNOWN_VALUE_SHAPES as readonly string[]).includes(shape);

// ---------------------------------------------------------------------------------------------
// Offering by place (catalogue `contexts` and `operatorDefinitions`, never portal rules)
// ---------------------------------------------------------------------------------------------

/** Fields whose catalogue `contexts` allow the place. */
export function fieldsFor(catalog: BuilderCatalog, place: BuilderPlace): CatalogField[] {
  return catalog.fields.filter((field) => field.contexts[place]);
}

/** Fields allowed in every one of the places (a rule's `when` can be relaxing and holding). */
export function fieldsForAll(
  catalog: BuilderCatalog,
  places: readonly BuilderPlace[],
): CatalogField[] {
  return catalog.fields.filter((field) => places.every((place) => field.contexts[place]));
}

/**
 * Operators of a field: the field's `ops` (in that order) that have a definition with a value
 * shape the builder can edit; in exceptions only those `allowedInException`.
 */
export function operatorsFor(
  catalog: BuilderCatalog,
  field: string,
  place: BuilderPlace,
): CatalogOperator[] {
  const def = fieldOf(catalog, field);
  if (!def) return [];
  const out: CatalogOperator[] = [];
  for (const op of def.ops) {
    const operator = operatorOf(catalog, op);
    if (!operator || !isKnownValueShape(operator.valueShape)) continue;
    if (place === 'exception' && !operator.allowedInException) continue;
    out.push(operator);
  }
  return out;
}

/** The empty value of a shape: `[]` for lists, nothing (no `value` key) otherwise. */
export function emptyValueOf(operator: CatalogOperator | null): unknown {
  return operator?.valueShape === 'list' ? [] : undefined;
}

/**
 * A new condition on `field`: the first operator allowed at the place and the empty value of
 * its shape; in exceptions a quantified field gets the catalogue's exception quantifier.
 */
export function defaultLeaf(
  catalog: BuilderCatalog,
  field: string,
  place: BuilderPlace,
): BuilderLeaf {
  const leaf: BuilderLeaf = { kind: 'leaf', key: newKey('n'), field };
  const first = operatorsFor(catalog, field, place)[0];
  if (first) {
    leaf.op = first.op;
    const value = emptyValueOf(first);
    if (value !== undefined) leaf.value = value;
  }
  if (place === 'exception' && fieldOf(catalog, field)?.quantified) {
    leaf.quantifier = catalog.contextRules.exceptionQuantifier;
  }
  return leaf;
}

/** Field change: operator and value reset (design §4.7); the node key is kept. */
export function changeLeafField(
  catalog: BuilderCatalog,
  leaf: BuilderLeaf,
  field: string,
  place: BuilderPlace,
): BuilderLeaf {
  return { ...defaultLeaf(catalog, field, place), key: leaf.key };
}

/** Operator change: the value is kept only when the value shape stays the same. */
export function changeLeafOperator(
  catalog: BuilderCatalog,
  leaf: BuilderLeaf,
  op: string,
): BuilderLeaf {
  const before = operatorOf(catalog, leaf.op);
  const after = operatorOf(catalog, op);
  const next: BuilderLeaf = { kind: 'leaf', key: leaf.key };
  if (leaf.field !== undefined) next.field = leaf.field;
  next.op = op;
  if (before && after && before.valueShape === after.valueShape && leaf.value !== undefined) {
    next.value = leaf.value;
  } else {
    const empty = emptyValueOf(after);
    if (empty !== undefined) next.value = empty;
  }
  if (leaf.quantifier !== undefined) next.quantifier = leaf.quantifier;
  return next;
}

// ---------------------------------------------------------------------------------------------
// Rule context from the catalogue (action dispositions × contextRules)
// ---------------------------------------------------------------------------------------------

/** Dispositions carried by a rule's actions (from `actionDefinitions[].disposition`). */
export function dispositionsOf(catalog: BuilderCatalog, actionTypes: readonly string[]): string[] {
  const out: string[] = [];
  for (const type of actionTypes) {
    const disposition = actionOf(catalog, type)?.disposition;
    if (disposition) out.push(disposition);
  }
  return out;
}

export const isDispositionAction = (catalog: BuilderCatalog, type: string): boolean =>
  actionOf(catalog, type)?.kind === 'disposition';

/**
 * The places that restrict a rule's `when`: `relaxingWhen` for a relaxing disposition (ALLOW) or
 * an override rule, `holdRule` for a holding disposition (contextRules).
 */
export function whenPlacesOf(
  catalog: BuilderCatalog,
  actionTypes: readonly string[],
  override: boolean | undefined,
): BuilderPlace[] {
  const dispositions = dispositionsOf(catalog, actionTypes);
  const places: BuilderPlace[] = ['when'];
  if (
    override === true ||
    dispositions.some((d) => catalog.contextRules.relaxingDispositions.includes(d))
  ) {
    places.push('relaxingWhen');
  }
  if (dispositions.some((d) => catalog.contextRules.holdDispositions.includes(d))) {
    places.push('holdRule');
  }
  return places;
}

/** The policy direction that stands for every message direction (`any`): not a message direction. */
export function isAllDirections(catalog: BuilderCatalog, direction: string): boolean {
  return (
    catalog.policyDirections.includes(direction) && !catalog.messageDirections.includes(direction)
  );
}

/** Field groups in catalogue order, each with its fields; unknown groups last. */
export function groupFields(
  catalog: BuilderCatalog,
  fields: readonly CatalogField[],
): Array<{ id: string; label: string; fields: CatalogField[] }> {
  const groups = catalog.fieldGroups.map((g) => ({
    id: g.id,
    label: g.label,
    fields: [] as CatalogField[],
  }));
  const byId = new Map(groups.map((g) => [g.id, g]));
  const other = { id: '__other', label: 'Other fields', fields: [] as CatalogField[] };
  for (const field of fields) (byId.get(field.group) ?? other).fields.push(field);
  return [...groups, other].filter((g) => g.fields.length > 0);
}
