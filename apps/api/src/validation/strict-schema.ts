import type { z } from 'zod';

/**
 * Strict-schema detector (step 6.1 D1): every object node of a request body or query schema must
 * be a `z.strictObject` (unknown fields → `400 validation_failed`), never a stripping `z.object`
 * or a passthrough `z.looseObject`.
 *
 * Walks a zod v4 schema through objects (their properties and catchall), arrays, tuples,
 * records, optional / nullable / default / prefault / catch / readonly / nonoptional wrappers,
 * unions, intersections, lazy schemas and pipes (only the INPUT side: what the client sends; a
 * transform's output is server-side). Returns the paths of the object nodes that are not strict
 * (`(root)`, `filters`, `items[]`, `rules[].when`, …); an empty list means the schema is strict.
 */
export function isStrictRequestSchema(schema: z.ZodType): string[] {
  const offenders: string[] = [];
  walk(schema, '', offenders, new Set());
  return offenders;
}

interface Def {
  type: string;
  [key: string]: unknown;
}

const defOf = (schema: unknown): Def | undefined =>
  (schema as { _zod?: { def?: Def } } | undefined)?._zod?.def;

const label = (path: string): string => path || '(root)';

function walk(schema: unknown, path: string, offenders: string[], seen: Set<unknown>): void {
  const def = defOf(schema);
  if (!def || seen.has(schema)) return;
  seen.add(schema);
  switch (def.type) {
    case 'object': {
      const catchall = defOf(def.catchall);
      if (catchall?.type !== 'never') offenders.push(label(path));
      const shape = def.shape as Record<string, unknown>;
      for (const [key, value] of Object.entries(shape)) {
        walk(value, path ? `${path}.${key}` : key, offenders, seen);
      }
      if (catchall && catchall.type !== 'never') walk(def.catchall, `${path}[*]`, offenders, seen);
      return;
    }
    case 'array':
      walk(def.element, `${path}[]`, offenders, seen);
      return;
    case 'set':
      walk(def.valueType, `${path}[]`, offenders, seen);
      return;
    case 'tuple':
      (def.items as unknown[]).forEach((item, i) => walk(item, `${path}[${i}]`, offenders, seen));
      if (def.rest) walk(def.rest, `${path}[]`, offenders, seen);
      return;
    case 'record':
    case 'map':
      walk(def.valueType, `${path}[*]`, offenders, seen);
      return;
    case 'optional':
    case 'nullable':
    case 'default':
    case 'prefault':
    case 'catch':
    case 'readonly':
    case 'nonoptional':
    case 'promise':
      walk(def.innerType, path, offenders, seen);
      return;
    case 'union':
      for (const option of def.options as unknown[]) walk(option, path, offenders, seen);
      return;
    case 'intersection':
      walk(def.left, path, offenders, seen);
      walk(def.right, path, offenders, seen);
      return;
    case 'lazy':
      walk((def.getter as () => unknown)(), path, offenders, seen);
      return;
    case 'pipe':
      // What the client sends is validated by the input side; the output side is server data.
      walk(def.in, path, offenders, seen);
      return;
    default:
      return;
  }
}
