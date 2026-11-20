/**
 * The OData `$filter` subset the Graph simulator implements (design note D12): `ge`, `le`, `eq`,
 * `in`, joined by `and`, plus `proxyAddresses/any(x:x eq '…')`. Anything else is a 400, like
 * Graph answers an unsupported query.
 */

export type ODataValue = string | number | boolean | null | ODataValue[];

export interface ODataClause {
  field: string;
  op: 'ge' | 'le' | 'eq' | 'in' | 'any_eq';
  value: ODataValue;
}

export class ODataError extends Error {
  constructor() {
    super('unsupported_filter');
  }
}

function splitAnd(filter: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quoted = false;
  let current = '';
  for (let i = 0; i < filter.length; i += 1) {
    const ch = filter[i] as string;
    if (ch === "'") {
      // '' is an escaped quote inside a literal
      if (quoted && filter[i + 1] === "'") {
        current += "''";
        i += 1;
        continue;
      }
      quoted = !quoted;
    }
    if (!quoted && ch === '(') depth += 1;
    if (!quoted && ch === ')') depth -= 1;
    if (!quoted && depth === 0 && filter.slice(i, i + 5).toLowerCase() === ' and ') {
      parts.push(current.trim());
      current = '';
      i += 4;
      continue;
    }
    current += ch;
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}

function parseLiteral(raw: string): ODataValue {
  const text = raw.trim();
  if (text.startsWith("'") && text.endsWith("'") && text.length >= 2) {
    return text.slice(1, -1).replace(/''/g, "'");
  }
  if (text === 'true' || text === 'false') return text === 'true';
  if (text === 'null') return null;
  if (/^-?\d+(\.\d+)?$/.test(text)) return Number(text);
  if (/^\d{4}-\d{2}-\d{2}T[0-9:.]+Z$/.test(text)) return text;
  throw new ODataError();
}

export function parseFilter(filter: string | null): ODataClause[] {
  if (filter === null || filter.trim() === '') return [];
  return splitAnd(filter).map((part) => {
    const any = /^([A-Za-z]+)\/any\(\s*([a-z]+)\s*:\s*\2\s+eq\s+(.+)\)$/.exec(part);
    if (any)
      return { field: any[1] as string, op: 'any_eq', value: parseLiteral(any[3] as string) };
    const inMatch = /^([A-Za-z/]+)\s+in\s+\((.*)\)$/.exec(part);
    if (inMatch) {
      const items = (inMatch[2] as string)
        .split(/,(?=(?:[^']*'[^']*')*[^']*$)/)
        .map((item) => parseLiteral(item));
      return { field: inMatch[1] as string, op: 'in', value: items };
    }
    const cmp = /^([A-Za-z/]+)\s+(ge|le|eq)\s+(.+)$/.exec(part);
    if (!cmp) throw new ODataError();
    return {
      field: cmp[1] as string,
      op: cmp[2] as 'ge' | 'le' | 'eq',
      value: parseLiteral(cmp[3] as string),
    };
  });
}

function read(record: unknown, field: string): unknown {
  let value: unknown = record;
  for (const segment of field.split('/')) {
    if (value === null || typeof value !== 'object') return undefined;
    value = (value as Record<string, unknown>)[segment];
  }
  return value;
}

function compare(a: unknown, b: ODataValue): number | null {
  if (typeof a === 'string' && typeof b === 'string') {
    const da = Date.parse(a);
    const db = Date.parse(b);
    if (!Number.isNaN(da) && !Number.isNaN(db) && /T/.test(a) && /T/.test(b)) return da - db;
    return a.toLowerCase() < b.toLowerCase() ? -1 : a.toLowerCase() > b.toLowerCase() ? 1 : 0;
  }
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  if (typeof a === 'boolean' && typeof b === 'boolean') return a === b ? 0 : 1;
  if (a === null && b === null) return 0;
  return null;
}

export function matches(record: unknown, clauses: readonly ODataClause[]): boolean {
  return clauses.every((clause) => {
    const value = read(record, clause.field);
    switch (clause.op) {
      case 'ge': {
        const c = compare(value, clause.value);
        return c !== null && c >= 0;
      }
      case 'le': {
        const c = compare(value, clause.value);
        return c !== null && c <= 0;
      }
      case 'eq':
        return compare(value, clause.value) === 0;
      case 'in':
        return (
          Array.isArray(clause.value) && clause.value.some((item) => compare(value, item) === 0)
        );
      case 'any_eq':
        return Array.isArray(value) && value.some((item) => compare(item, clause.value) === 0);
    }
  });
}
