import type { OperationTool } from '../registry/types';
import { isCredentialKey, sanitizeText } from './sanitize';
import { detectRowId, detectShape, isPlainObject } from './shape';
import {
  ENVELOPE_NOTE,
  type RefMap,
  type ToolResultEnvelope,
  type ToolResultError,
  type ToolResultOk,
} from './types';

/**
 * The minimizer (design D8): an API response → the `assistant-tool-result/1` envelope the model
 * sees, plus the refs map the server keeps. Rows capped at `maxRows`, the serialized envelope at
 * `maxBytes` (rows trimmed first, then fields), strings sanitized and capped at 300 characters,
 * credential-pattern keys dropped at any depth, mail-derived strings wrapped as
 * `{ untrusted_text }`. The next-page cursor never reaches the model (`hasMore` only).
 */

export interface EnvelopeOptions {
  /** ASSISTANT_TOOL_RESULT_MAX_ROWS. */
  maxRows: number;
  /** ASSISTANT_TOOL_RESULT_MAX_BYTES. */
  maxBytes: number;
  /** Conversation-wide execution sequence: refs are `r<refSeq>` and `r<refSeq>.<row>`. */
  refSeq: number;
  /** Response paths to wrap as untrusted text (default: the tool's manifest list). */
  untrustedFields?: readonly string[];
}

export type EnvelopeTool = Pick<OperationTool, 'name' | 'display' | 'untrustedFields'>;

export interface MinimizedResult {
  envelope: ToolResultEnvelope;
  refs: RefMap;
}

/** Items kept from nested arrays (top-level rows use `maxRows`). */
export const NESTED_ARRAY_MAX_ITEMS = 20;
const MAX_DEPTH = 8;

/** `''` (a free-form response root) covers every path. */
function isUntrusted(path: string, untrusted: readonly string[]): boolean {
  return untrusted.some(
    (entry) =>
      entry === '' ||
      path === entry ||
      path.startsWith(`${entry}.`) ||
      path.startsWith(`${entry}[]`),
  );
}

const join = (base: string, key: string): string => (base ? `${base}.${key}` : key);

/** Projects one value: sanitize, drop credential keys, wrap untrusted strings, cap arrays. */
export function projectValue(
  value: unknown,
  path: string,
  untrusted: readonly string[],
  depth = 0,
): unknown {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') {
    const text = sanitizeText(value);
    return isUntrusted(path, untrusted) ? { untrusted_text: text } : text;
  }
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean') return value;
  if (depth >= MAX_DEPTH) return null;
  if (Array.isArray(value)) {
    const items = value
      .slice(0, NESTED_ARRAY_MAX_ITEMS)
      .map((item) => projectValue(item, `${path}[]`, untrusted, depth + 1));
    if (value.length > NESTED_ARRAY_MAX_ITEMS)
      items.push({ omitted_items: value.length - NESTED_ARRAY_MAX_ITEMS });
    return items;
  }
  if (isPlainObject(value)) {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      if (isCredentialKey(key) || item === undefined) continue;
      out[sanitizeText(key, 64)] = projectValue(item, join(path, key), untrusted, depth + 1);
    }
    return out;
  }
  return null;
}

const byteLength = (value: unknown): number => Buffer.byteLength(JSON.stringify(value), 'utf8');

/** The coded error body of the api (`{ statusCode, error, code, message, requestId }`). */
export function toErrorEnvelope(tool: string, httpStatus: number, body: unknown): ToolResultError {
  const record = isPlainObject(body) ? body : {};
  const code =
    typeof record.code === 'string' && /^[a-z0-9_.:-]{1,64}$/i.test(record.code)
      ? record.code
      : httpStatus >= 500
        ? 'upstream_error'
        : 'request_failed';
  const raw = record.message;
  const message = Array.isArray(raw)
    ? raw.filter((item): item is string => typeof item === 'string').join('; ')
    : typeof raw === 'string'
      ? raw
      : '';
  return {
    kind: 'tool_result/1',
    tool,
    status: 'error',
    httpStatus,
    code,
    message: sanitizeText(message),
  };
}

/** Removes the largest field (never `ref`) of a record; false when nothing is left to remove. */
function dropLargestField(record: Record<string, unknown>): boolean {
  let largest: string | null = null;
  let size = -1;
  for (const [key, value] of Object.entries(record)) {
    if (key === 'ref') continue;
    const bytes = byteLength(value ?? null);
    if (bytes > size) {
      size = bytes;
      largest = key;
    }
  }
  if (largest === null) return false;
  delete record[largest];
  return true;
}

export function toToolResultEnvelope(
  tool: EnvelopeTool,
  httpStatus: number,
  body: unknown,
  options: EnvelopeOptions,
): MinimizedResult {
  if (httpStatus >= 400)
    return { envelope: toErrorEnvelope(tool.name, httpStatus, body), refs: {} };
  const untrusted = options.untrustedFields ?? tool.untrustedFields;
  const resourceType = tool.display.resourceType ?? tool.name;
  const executionRef = `r${options.refSeq}`;
  const shape = detectShape(body);
  const refs: RefMap = {};
  const envelope: ToolResultOk = {
    kind: 'tool_result/1',
    tool: tool.name,
    status: 'ok',
    httpStatus,
    ref: executionRef,
    returned: 0,
    hasMore: false,
    truncated: false,
    note: ENVELOPE_NOTE,
    data: null,
  };

  if (shape.kind === 'list') {
    const base = shape.listKey ? `${shape.listKey}[]` : '[]';
    const rows: Array<Record<string, unknown>> = [];
    const limit = Math.max(0, options.maxRows);
    shape.rows.slice(0, limit).forEach((row, index) => {
      const ref = `${executionRef}.${index + 1}`;
      const projected = projectValue(row, base, untrusted);
      const record = isPlainObject(projected) ? projected : { value: projected };
      const publicId = detectRowId(row, tool.display);
      if (publicId) refs[ref] = { resourceType, publicId };
      rows.push({ ref, ...record });
    });
    envelope.data = rows;
    envelope.returned = rows.length;
    envelope.hasMore = shape.hasMore;
    envelope.truncated = shape.rows.length > rows.length;
    const meta = projectValue(shape.rest, '', untrusted);
    if (isPlainObject(meta) && Object.keys(meta).length > 0) envelope.meta = meta;
    // Byte cap: trim rows from the end, then fields of the last row, then the meta block.
    while (byteLength(envelope) > options.maxBytes && rows.length > 1) {
      const removed = rows.pop()!;
      delete refs[String(removed.ref)];
      envelope.truncated = true;
    }
    while (byteLength(envelope) > options.maxBytes && rows[0] && dropLargestField(rows[0]))
      envelope.truncated = true;
    if (byteLength(envelope) > options.maxBytes && envelope.meta) {
      delete envelope.meta;
      envelope.truncated = true;
    }
    if (byteLength(envelope) > options.maxBytes && rows.length > 0) {
      for (const row of rows.splice(0)) delete refs[String(row.ref)];
      envelope.truncated = true;
    }
    envelope.returned = rows.length;
    return { envelope, refs };
  }

  if (shape.kind === 'record') {
    const projected = projectValue(shape.record, '', untrusted) as Record<string, unknown>;
    const publicId = detectRowId(shape.record, tool.display);
    const record: Record<string, unknown> = publicId
      ? { ref: `${executionRef}.1`, ...projected }
      : projected;
    if (publicId) refs[`${executionRef}.1`] = { resourceType, publicId };
    envelope.data = record;
    envelope.returned = 1;
    while (byteLength(envelope) > options.maxBytes && dropLargestField(record))
      envelope.truncated = true;
    return { envelope, refs };
  }

  // 204 / scalar body
  const value = projectValue(shape.value, '', untrusted);
  envelope.data = value === null ? null : { value };
  envelope.returned = value === null ? 0 : 1;
  if (byteLength(envelope) > options.maxBytes) {
    envelope.data = null;
    envelope.truncated = true;
  }
  return { envelope, refs };
}
