import type { HttpMethod, OperationMeta, RouteMatcher } from './operation-types';
import { operations, routeMatchers, type OperationId } from './operations.gen';

export type { OperationId } from './operations.gen';
export type { OperationMeta, PermissionRequirement } from './operation-types';

export function getOperation(operationId: OperationId): OperationMeta {
  return operations[operationId];
}

export function isOperationId(value: string): value is OperationId {
  return Object.prototype.hasOwnProperty.call(operations, value);
}

export interface OperationMatch {
  readonly operationId: OperationId;
  readonly params: Readonly<Record<string, string>>;
}

/** Characters/sequences refused anywhere in a raw proxied path (P5). */
const FORBIDDEN_RAW = /(%2f|%5c|%00|%2e%2e|\\|\0)/i;

/**
 * Splits a raw (still percent-encoded) path below `/api/v1/` into decoded segments; `null` for
 * traversal and smuggling attempts: `..`, `.`, empty segments (`//`), encoded slashes or
 * backslashes, NUL, or malformed percent-encoding.
 */
export function splitRawPath(rawPath: string): string[] | null {
  if (rawPath.length === 0 || FORBIDDEN_RAW.test(rawPath)) return null;
  const parts = rawPath.split('/');
  const out: string[] = [];
  for (const part of parts) {
    if (part.length === 0 || part === '.' || part === '..') return null;
    let decoded: string;
    try {
      decoded = decodeURIComponent(part);
    } catch {
      return null;
    }
    if (decoded === '.' || decoded === '..' || decoded.includes('/') || decoded.length === 0) {
      return null;
    }
    out.push(decoded);
  }
  return out;
}

function matches(
  matcher: RouteMatcher<OperationId>,
  method: string,
  segments: readonly string[],
): Record<string, string> | null {
  if (matcher.method !== method || matcher.segments.length !== segments.length) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < segments.length; i += 1) {
    const expected = matcher.segments[i];
    const actual = segments[i] ?? '';
    if (typeof expected === 'string') {
      if (expected !== actual) return null;
    } else if (expected) {
      params[expected.param] = actual;
    }
  }
  return params;
}

/** Resolves decoded segments against the generated allow-list (static segments win). */
export function matchOperation(method: string, segments: readonly string[]): OperationMatch | null {
  const upper = method.toUpperCase() as HttpMethod;
  let best: { match: OperationMatch; statics: number } | null = null;
  for (const matcher of routeMatchers) {
    const params = matches(matcher, upper, segments);
    if (!params) continue;
    const statics = matcher.segments.filter((s) => typeof s === 'string').length;
    if (!best || statics > best.statics) {
      best = { match: { operationId: matcher.operationId, params }, statics };
    }
  }
  return best?.match ?? null;
}

/** Fills `{param}` placeholders of a template path with encoded values. */
export function buildPath(template: string, params: Readonly<Record<string, string>>): string {
  return template.replace(/\{([^}]+)\}/g, (_, name: string) => {
    const value = params[name];
    if (value === undefined) throw new Error(`Missing path parameter ${name}`);
    return encodeURIComponent(value);
  });
}

/** Operations with a collection response (lists). */
export function isListOperation(operationId: OperationId): boolean {
  return operations[operationId].listKey !== null;
}
