import type { OperationTool } from '../registry/types';
import { toErrorEnvelope } from './minimize';
import { isCredentialKey, sanitizeText, scrubValue } from './sanitize';
import { PUBLIC_ID, detectRowId, detectShape, isPlainObject } from './shape';
import {
  CARD_VERSION,
  type AssistantCard,
  type CardColumn,
  type CardLink,
  type CardValue,
  type RefMap,
} from './types';

/**
 * Result cards for the user (`assistant-card/1`, design D8): built from the real API response with
 * generic shape detection (`{ data: [...] }` → table, object → key-value, time buckets → series)
 * and the manifest's display hints; portal links from the tool's route template. Credential keys
 * are dropped and strings sanitized; the card is capped at 64 KiB (rows trimmed).
 */

export const CARD_MAX_BYTES = 64 * 1024;
const DEFAULT_COLUMNS = 6;
const MAX_FIELDS = 60;
const MAX_SERIES = 8;
const CELL_MAX_CHARS = 300;
const TIME_KEYS = ['start', 'bucketStart', 'day', 'date', 'at', 'bucket', 'timestamp', 'from'];

export type CardTool = Pick<
  OperationTool,
  'name' | 'summary' | 'display' | 'portalRoute' | 'pathParams'
>;

export interface CardInput {
  executionId: string;
  tool: CardTool;
  httpStatus: number;
  body: unknown;
  /** The validated call arguments (fill `{param}` of the portal route). */
  args?: Record<string, unknown>;
  /** Refs of the envelope (same row order). */
  refs?: RefMap;
  /** Execution sequence of the refs (`r<refSeq>.<row>`). */
  refSeq?: number;
}

const byteLength = (value: unknown): number => Buffer.byteLength(JSON.stringify(value), 'utf8');

/** `receivedAt` → `Received at`. */
export function labelOf(key: string): string {
  const words = key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[_.-]+/g, ' ')
    .trim()
    .toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** A scalar cell value: scalars as is, scalar arrays joined, objects as their scalar leaves. */
export function cellValue(value: unknown): CardValue {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return sanitizeText(value, CELL_MAX_CHARS);
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean') return value;
  const leaves: string[] = [];
  const collect = (item: unknown, depth: number): void => {
    if (leaves.length >= 12 || depth > 3) return;
    if (item === null || item === undefined) return;
    if (typeof item === 'string' || typeof item === 'number' || typeof item === 'boolean') {
      leaves.push(String(item));
      return;
    }
    if (Array.isArray(item)) {
      for (const entry of item) collect(entry, depth + 1);
      return;
    }
    if (isPlainObject(item))
      for (const [key, entry] of Object.entries(item))
        if (!isCredentialKey(key)) collect(entry, depth + 1);
  };
  collect(value, 0);
  return leaves.length === 0
    ? null
    : sanitizeText(leaves.join(Array.isArray(value) ? ', ' : ' · '), CELL_MAX_CHARS);
}

function isScalar(value: unknown): boolean {
  return value === null || ['string', 'number', 'boolean'].includes(typeof value);
}

function defaultColumns(rows: readonly Record<string, unknown>[]): string[] {
  const first = rows.find(isPlainObject);
  if (!first) return [];
  return Object.keys(first)
    .filter((key) => !isCredentialKey(key) && key !== 'id' && !/Id$/.test(key))
    .filter((key) => isScalar(first[key]))
    .slice(0, DEFAULT_COLUMNS);
}

/**
 * Fills `{param}` of a portal route: from the argument of the same name, else (a one-parameter
 * route of a one-path-parameter tool, e.g. `/users/{userId}` for `/users/{id}`) from that path
 * argument; a single remaining parameter takes the row id. `usedRow` tells whether it did.
 */
export function fillRoute(
  template: string,
  args: Record<string, unknown> | undefined,
  pathParams: readonly string[] = [],
  rowId?: string | null,
): { href: string; usedRow: boolean } | null {
  const params = [...template.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]!);
  let href = template;
  const unfilled: string[] = [];
  for (const param of params) {
    let value = args?.[param];
    if (value === undefined && params.length === 1 && pathParams.length === 1)
      value = args?.[pathParams[0]!];
    if (typeof value === 'string' && PUBLIC_ID.test(value))
      href = href.replace(`{${param}}`, encodeURIComponent(value));
    else if (typeof value === 'number' && Number.isSafeInteger(value))
      href = href.replace(`{${param}}`, String(value));
    else unfilled.push(param);
  }
  if (unfilled.length === 0) return { href, usedRow: false };
  if (unfilled.length === 1 && rowId && PUBLIC_ID.test(rowId))
    return { href: href.replace(`{${unfilled[0]}}`, encodeURIComponent(rowId)), usedRow: true };
  return null;
}

/** The static page of a route template: everything before the first parameter. */
export function routePage(template: string): string | null {
  const index = template.indexOf('{');
  const page = (index < 0 ? template : template.slice(0, index)).replace(/\/+$/, '');
  return page.startsWith('/') && page.length > 1 ? page : null;
}

function seriesOf(
  record: Record<string, unknown>,
): { key: string; series: NonNullable<AssistantCard['series']> } | null {
  for (const [key, value] of Object.entries(record)) {
    if (!Array.isArray(value) || value.length === 0 || !value.every(isPlainObject)) continue;
    const items = value;
    const timeKey = TIME_KEYS.find((name) => items.every((item) => typeof item[name] === 'string'));
    if (!timeKey) continue;
    const numeric = Object.keys(items[0]!)
      .filter((name) => name !== timeKey && typeof items[0]![name] === 'number')
      .slice(0, MAX_SERIES);
    if (numeric.length === 0) continue;
    return {
      key,
      series: {
        x: items.map((item) => sanitizeText(String(item[timeKey]), 64)),
        series: numeric.map((name) => ({
          name,
          values: items.map((item) =>
            typeof item[name] === 'number' && Number.isFinite(item[name]) ? item[name] : null,
          ),
        })),
      },
    };
  }
  return null;
}

/** Flattens a record into key-value fields (two levels; arrays summarized). */
function fieldsOf(
  record: Record<string, unknown>,
  skip: ReadonlySet<string> = new Set(),
  columns?: readonly string[],
): NonNullable<AssistantCard['fields']> {
  const fields: NonNullable<AssistantCard['fields']> = [];
  const push = (key: string, value: unknown): void => {
    if (fields.length >= MAX_FIELDS) return;
    fields.push({ key, label: labelOf(key), value: cellValue(value) });
  };
  const keys = columns && columns.length > 0 ? columns : Object.keys(record);
  for (const key of keys) {
    if (skip.has(key) || isCredentialKey(key)) continue;
    const value = record[key];
    if (isPlainObject(value)) {
      for (const [sub, inner] of Object.entries(value)) {
        if (isCredentialKey(sub)) continue;
        if (isPlainObject(inner) || (Array.isArray(inner) && inner.some(isPlainObject)))
          push(`${key}.${sub}`, Array.isArray(inner) ? `${inner.length} items` : cellValue(inner));
        else push(`${key}.${sub}`, inner);
      }
    } else if (Array.isArray(value) && value.some(isPlainObject)) {
      push(key, `${value.length} items`);
    } else {
      push(key, value);
    }
  }
  return fields;
}

export function toCard(input: CardInput): AssistantCard {
  const { tool, httpStatus, body, args } = input;
  const title = sanitizeText(tool.display.title ?? tool.summary, 120);
  const route = tool.portalRoute;
  const base = {
    version: CARD_VERSION,
    executionId: input.executionId,
    tool: tool.name,
    title,
  } as const;

  if (httpStatus >= 400) {
    const error = toErrorEnvelope(tool.name, httpStatus, body);
    const page = route ? (fillRoute(route, args, tool.pathParams)?.href ?? routePage(route)) : null;
    return {
      ...base,
      status: 'error',
      kind: 'error',
      error: { httpStatus, code: error.code, message: error.message },
      portalLinks: page ? [{ label: title, href: page }] : [],
      refs: [],
    };
  }

  const shape = detectShape(body);
  const seq = input.refSeq;
  const refOf = (index: number): string | null => {
    if (seq === undefined) return null;
    const ref = `r${seq}.${index + 1}`;
    return !input.refs || input.refs[ref] ? ref : null;
  };

  if (shape.kind === 'list') {
    const rawRows = shape.rows.filter(isPlainObject);
    const keys = tool.display.columns?.length ? tool.display.columns : defaultColumns(rawRows);
    const columns: CardColumn[] = keys.map((key) => ({ key, label: labelOf(key) }));
    const rows: Array<Record<string, CardValue>> = [];
    const rowLinks: Array<CardLink | null> = [];
    const rowRefs: Array<string | null> = [];
    rawRows.forEach((row, index) => {
      const cells: Record<string, CardValue> = {};
      for (const key of keys) cells[key] = isCredentialKey(key) ? null : cellValue(row[key]);
      const ref = refOf(index);
      if (ref) cells.ref = ref;
      rows.push(cells);
      rowRefs.push(ref);
      const linkValue = tool.display.linkField ? row[tool.display.linkField] : undefined;
      const rowId = typeof linkValue === 'string' ? linkValue : detectRowId(row, tool.display);
      const filled = route && rowId ? fillRoute(route, args, tool.pathParams, rowId) : null;
      if (filled?.usedRow) {
        const first = keys.length > 0 ? cellValue(row[keys[0]!]) : null;
        const label = sanitizeText(
          typeof first === 'string' && first ? first : (rowId ?? title),
          80,
        );
        rowLinks.push({ label, href: filled.href, ...(ref ? { ref } : {}) });
      } else rowLinks.push(null);
    });
    const page = route ? (fillRoute(route, args, tool.pathParams)?.href ?? routePage(route)) : null;
    const pageLinks: CardLink[] = page ? [{ label: title, href: page }] : [];
    const total = isPlainObject(body) ? body.total : undefined;
    // 64 KiB cap: keep the longest row prefix that fits (row + its link + its ref per row).
    const empty: AssistantCard = {
      ...base,
      status: 'ok',
      kind: 'table',
      columns,
      rows: [],
      nextCursor: shape.hasMore,
      portalLinks: pageLinks,
      refs: [],
      ...(typeof total === 'number' && Number.isSafeInteger(total) ? { total } : {}),
      truncated: false,
    };
    let budget = CARD_MAX_BYTES - byteLength(empty);
    let keep = 0;
    while (keep < rows.length) {
      const cost =
        byteLength(rows[keep]) +
        (rowLinks[keep] ? byteLength(rowLinks[keep]) + 1 : 0) +
        (rowRefs[keep] ? byteLength(rowRefs[keep]) + 1 : 0) +
        1;
      if (cost > budget) break;
      budget -= cost;
      keep += 1;
    }
    const card: AssistantCard = {
      ...empty,
      rows: rows.slice(0, keep),
      portalLinks: [
        ...pageLinks,
        ...rowLinks
          .slice(0, keep)
          .filter((link): link is CardLink => link !== null && link.href !== page),
      ],
      refs: rowRefs.slice(0, keep).filter((ref): ref is string => ref !== null),
    };
    if (keep < rows.length) card.truncated = true;
    else delete card.truncated;
    while (byteLength(card) > CARD_MAX_BYTES && card.rows!.length > 0) {
      card.rows!.pop();
      card.truncated = true;
    }
    return card;
  }

  if (shape.kind === 'record') {
    const record = scrubValue(shape.record) as Record<string, unknown>;
    const recordId = detectRowId(shape.record, tool.display);
    const page = route
      ? (fillRoute(route, args, tool.pathParams, recordId)?.href ?? routePage(route))
      : null;
    const portalLinks: CardLink[] = page ? [{ label: title, href: page }] : [];
    const ref = refOf(0);
    const refs = ref && input.refs?.[ref] ? [ref] : [];
    const found = seriesOf(record);
    const card: AssistantCard = found
      ? {
          ...base,
          status: 'ok',
          kind: 'series',
          series: found.series,
          fields: fieldsOf(record, new Set([found.key])),
          portalLinks,
          refs,
        }
      : {
          ...base,
          status: 'ok',
          kind: 'kv',
          fields: fieldsOf(record, new Set(), tool.display.columns),
          portalLinks,
          refs,
        };
    while (byteLength(card) > CARD_MAX_BYTES && card.fields && card.fields.length > 0) {
      card.fields.pop();
      card.truncated = true;
    }
    if (card.series && byteLength(card) > CARD_MAX_BYTES) {
      delete card.series;
      card.kind = 'kv';
      card.truncated = true;
    }
    return card;
  }

  const page = route ? (fillRoute(route, args, tool.pathParams)?.href ?? routePage(route)) : null;
  return {
    ...base,
    status: 'ok',
    kind: 'message',
    message: shape.value === null ? 'Done.' : sanitizeText(String(cellValue(shape.value) ?? '')),
    portalLinks: page ? [{ label: title, href: page }] : [],
    refs: [],
  };
}
