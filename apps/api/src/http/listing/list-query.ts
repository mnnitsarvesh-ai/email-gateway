import { z } from 'zod';
import { DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT } from '../pagination';
import { CURSOR_MAX_LENGTH } from '../cursor/cursor-codec';

/**
 * The shared list query contract of the v1 lists (step 6.1 D3, D4): `limit`, `cursor`, `sort`,
 * an optional `from`/`to` range and allow-listed typed filters in the query-string syntax
 *
 *   field=value          equals
 *   field=a,b,c          in (at most `maxValues`, default 1 = no list)
 *   field.gte= / .lte= / .gt= / .lt=   typed ranges (int, datetime filters with `range: true`)
 *   field=true|false     booleans
 *
 * The schema is strict: an unknown parameter or operator is `400 validation_failed`
 * (`"(root)": Unrecognized key …`), a repeated parameter or a wrong type is a `400` naming the
 * parameter, values are never echoed.
 *
 * SQL safety: a filter's name and type come from code; repositories map each filter to a column
 * through a code-side constant (never from input) and pass every value as a bound parameter
 * (Prisma `where` objects or `Prisma.sql` tagged templates). Never a raw SQL fragment,
 * `$queryRawUnsafe` or string concatenation of input.
 */

/** Default most values of `field=a,b,c` when a filter allows lists (D4). */
export const DEFAULT_MAX_LIST_VALUES = 10;

export type RangeOperator = 'gte' | 'lte' | 'gt' | 'lt';
export const RANGE_OPERATORS: readonly RangeOperator[] = ['gte', 'lte', 'gt', 'lt'];

export type FilterSpec =
  | { type: 'enum'; values: readonly [string, ...string[]]; maxValues?: number }
  /** Exact string (case-sensitive), at most `maxLength` characters. */
  | { type: 'string'; maxLength: number; maxValues?: number }
  /** Exact address-like string, trimmed and lower-cased (`envelope_from`, recipients). */
  | { type: 'email'; maxLength?: number }
  /** A public id (UUID). */
  | { type: 'publicId'; maxValues?: number }
  /** An integer within bounds; `range: true` adds `.gte/.lte/.gt/.lt` (and keeps equality). */
  | { type: 'int'; min: number; max: number; range?: boolean; maxValues?: number }
  /** An ISO 8601 instant with offset; ranges only. */
  | { type: 'datetime'; range: true }
  | { type: 'bool' };

/** One parsed filter: equality values (one or more) and/or range bounds. */
export interface ParsedFilter<T> {
  values?: T[];
  gte?: T;
  lte?: T;
  gt?: T;
  lt?: T;
}

type ValueOf<S extends FilterSpec> = S extends { type: 'enum'; values: readonly (infer V)[] }
  ? V
  : S extends { type: 'int' }
    ? number
    : S extends { type: 'datetime' }
      ? Date
      : S extends { type: 'bool' }
        ? boolean
        : string;

export interface ListQueryDefinition<
  F extends Record<string, FilterSpec>,
  S extends readonly [string, ...string[]],
> {
  filters: F;
  /** Allowed `sort` values (`-receivedAt`, `receivedAt`): only leading keys of the keyset index. */
  sorts: S;
  defaultSort: S[number];
  /** Adds `from`/`to` (ISO instants); bounds are checked by `resolveRange`. */
  range?: boolean;
}

export interface ParsedListQuery<F extends Record<string, FilterSpec>, Sort extends string> {
  limit: number;
  cursor?: string;
  sort: Sort;
  from?: Date;
  to?: Date;
  filters: { [K in keyof F]?: ParsedFilter<ValueOf<F[K]>> };
}

const FILTER_NAME = /^[a-z][A-Za-z0-9]{0,39}$/;
const RESERVED = new Set(['limit', 'cursor', 'sort', 'from', 'to']);

const isoInstant = z.iso.datetime({ offset: true });

function maxValuesOf(spec: FilterSpec): number {
  if (spec.type === 'datetime' || spec.type === 'bool' || spec.type === 'email') return 1;
  return spec.maxValues ?? 1;
}

/** A schema that reads one raw query string. */
type RawValueSchema = z.ZodType<unknown, string>;

/** zod schema of one raw value (a single string from the query) of a filter. */
function valueSchema(spec: FilterSpec): RawValueSchema {
  return rawValueSchema(spec) as RawValueSchema;
}

function rawValueSchema(spec: FilterSpec): z.ZodType {
  switch (spec.type) {
    case 'enum':
      return z.enum(spec.values as unknown as [string, ...string[]]);
    case 'string':
      return z.string().min(1).max(spec.maxLength);
    case 'email':
      return z
        .string()
        .trim()
        .min(3)
        .max(spec.maxLength ?? 320)
        .regex(/^[^\s@]+@[^\s@]+$/, 'must be an address')
        .transform((v) => v.toLowerCase());
    case 'publicId':
      return z.uuid();
    case 'int':
      return z
        .string()
        .regex(/^-?\d{1,15}$/, 'must be an integer')
        .transform(Number)
        .pipe(z.number().int().min(spec.min).max(spec.max));
    case 'datetime':
      return isoInstant.transform((v) => new Date(v));
    case 'bool':
      return z.enum(['true', 'false']).transform((v) => v === 'true');
  }
}

/** `field=v` or `field=a,b` (comma list up to the filter's maxValues). */
function equalitySchema(spec: FilterSpec): z.ZodType {
  const max = maxValuesOf(spec);
  const value = valueSchema(spec);
  if (max === 1)
    return z
      .string()
      .pipe(value)
      .transform((v) => [v]);
  return z
    .string()
    .transform((raw) => raw.split(','))
    .pipe(
      z
        .array(value)
        .min(1)
        .max(max, `may list at most ${max} values`)
        .refine((values) => new Set(values.map(String)).size === values.length, {
          message: 'must not repeat a value',
        }),
    );
}

function hasRange(spec: FilterSpec): boolean {
  return (spec.type === 'int' && spec.range === true) || spec.type === 'datetime';
}

function hasEquality(spec: FilterSpec): boolean {
  return spec.type !== 'datetime';
}

/**
 * Builds the strict query schema of a list. The output is `{ limit, cursor?, sort, from?, to?,
 * filters }`, with every filter as `{ values?, gte?, lte?, gt?, lt? }` of its type.
 */
export function defineListQuery<
  const F extends Record<string, FilterSpec>,
  const S extends readonly [string, ...string[]],
>(
  definition: ListQueryDefinition<F, S>,
): z.ZodType<ParsedListQuery<F, S[number]>, Record<string, unknown>> {
  const shape: Record<string, z.ZodType> = {
    limit: z
      .string()
      .regex(/^\d{1,3}$/, 'must be an integer')
      .transform(Number)
      .pipe(z.number().int().min(1).max(MAX_PAGE_LIMIT))
      .optional(),
    cursor: z.string().min(1).max(CURSOR_MAX_LENGTH).optional(),
    sort: z.enum(definition.sorts as unknown as [string, ...string[]]).optional(),
  };
  if (!definition.sorts.includes(definition.defaultSort)) {
    throw new Error('defineListQuery: defaultSort must be one of sorts');
  }
  if (definition.range) {
    shape.from = isoInstant.transform((v) => new Date(v)).optional();
    shape.to = isoInstant.transform((v) => new Date(v)).optional();
  }
  const keyToFilter = new Map<string, { name: string; op: 'eq' | RangeOperator }>();
  for (const [name, spec] of Object.entries(definition.filters)) {
    if (!FILTER_NAME.test(name) || RESERVED.has(name)) {
      throw new Error(`defineListQuery: invalid filter name ${name}`);
    }
    if (spec.type === 'int' && spec.min > spec.max) {
      throw new Error(`defineListQuery: ${name} has min > max`);
    }
    if (hasEquality(spec)) {
      shape[name] = equalitySchema(spec).optional();
      keyToFilter.set(name, { name, op: 'eq' });
    }
    if (hasRange(spec)) {
      for (const op of RANGE_OPERATORS) {
        shape[`${name}.${op}`] = z.string().pipe(valueSchema(spec)).optional();
        keyToFilter.set(`${name}.${op}`, { name, op });
      }
    }
  }
  return z.strictObject(shape).transform((raw) => {
    const filters: Record<string, ParsedFilter<unknown>> = {};
    for (const [key, value] of Object.entries(raw)) {
      const target = keyToFilter.get(key);
      if (!target || value === undefined) continue;
      const parsed = (filters[target.name] ??= {});
      if (target.op === 'eq') parsed.values = value as unknown[];
      else parsed[target.op] = value;
    }
    return {
      limit: (raw.limit as number | undefined) ?? DEFAULT_PAGE_LIMIT,
      ...(raw.cursor !== undefined && { cursor: raw.cursor as string }),
      sort: (raw.sort as S[number] | undefined) ?? definition.defaultSort,
      ...(raw.from !== undefined && { from: raw.from as Date }),
      ...(raw.to !== undefined && { to: raw.to as Date }),
      filters,
    } as ParsedListQuery<F, S[number]>;
  });
}

/**
 * The filters of a parsed query in a JSON-safe canonical form (dates as ISO strings) for
 * `filterHash`; filters without a value are dropped.
 */
export function canonicalFilters(
  filters: Record<string, ParsedFilter<unknown> | undefined>,
): Record<string, Record<string, unknown>> {
  const out: Record<string, Record<string, unknown>> = {};
  for (const [name, filter] of Object.entries(filters)) {
    if (!filter) continue;
    const entry: Record<string, unknown> = {};
    for (const [op, value] of Object.entries(filter)) {
      if (value === undefined) continue;
      const norm = (v: unknown) => (v instanceof Date ? v.toISOString() : v);
      // Equality lists are sets: their order never changes the result.
      entry[op] = Array.isArray(value)
        ? value.map(norm).sort((a, b) => String(a).localeCompare(String(b)))
        : norm(value);
    }
    if (Object.keys(entry).length > 0) out[name] = entry;
  }
  return out;
}
