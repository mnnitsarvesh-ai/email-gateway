/**
 * DSL JSON paths (`rules[2].when.all[0].value`, the format of the validator's violations and the
 * evaluator's trace) and the path index of a built definition (design B3): every rule, node and
 * action of the document by path, so server violations and trace paths land on the edited node.
 */

export type PathSegment = string | number;

/** `{ keyByPath, pathByKey }` of one `buildDefinition` result. */
export interface PathIndex {
  readonly keyByPath: ReadonlyMap<string, string>;
  readonly pathByKey: ReadonlyMap<string, string>;
}

export const EMPTY_PATH_INDEX: PathIndex = { keyByPath: new Map(), pathByKey: new Map() };

/** `['rules', 2, 'when', 'all', 0]` → `rules[2].when.all[0]` (the validator's format). */
export function formatPath(segments: readonly PathSegment[]): string {
  let out = '';
  for (const segment of segments) {
    if (typeof segment === 'number') out += `[${segment}]`;
    else out += out === '' ? segment : `.${segment}`;
  }
  return out;
}

export const childPath = (path: string, segment: PathSegment): string =>
  typeof segment === 'number'
    ? `${path}[${segment}]`
    : path === ''
      ? segment
      : `${path}.${segment}`;

/** The path and its prefixes, longest first (cut before every `.` and `[`). */
export function pathPrefixes(path: string): string[] {
  const out = [path];
  for (let i = path.length - 1; i > 0; i -= 1) {
    const ch = path[i];
    if (ch === '.' || ch === '[') out.push(path.slice(0, i));
  }
  return out;
}

/** The key of the deepest indexed prefix of a DSL path (`null` = a policy-level path). */
export function keyForPath(paths: PathIndex, dslPath: string): string | null {
  for (const prefix of pathPrefixes(dslPath)) {
    const key = paths.keyByPath.get(prefix);
    if (key !== undefined) return key;
  }
  return null;
}

export function pathForKey(paths: PathIndex, key: string): string | null {
  return paths.pathByKey.get(key) ?? null;
}

/**
 * A readable location of a DSL path: `rules[0].when.all[1].value` → "Rule 1 › conditions ›
 * item 2 › value". Positions are 1-based; unknown segments are kept as written.
 */
export function describePath(path: string): string {
  if (path === '') return 'Policy';
  const parts: string[] = [];
  const re = /([^.[\]]+)|\[(\d+)\]/g;
  const tokens: PathSegment[] = [];
  for (const match of path.matchAll(re)) {
    if (match[1] !== undefined) tokens.push(match[1]);
    else if (match[2] !== undefined) tokens.push(Number(match[2]));
  }
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (token === undefined) break;
    if (typeof token === 'number') {
      parts.push(`item ${token + 1}`);
      continue;
    }
    const next = tokens[i + 1];
    const position = typeof next === 'number' ? next + 1 : null;
    if (position !== null) i += 1;
    switch (token) {
      case 'rules':
        parts.push(position === null ? 'Rules' : `Rule ${position}`);
        break;
      case 'when':
        parts.push('conditions');
        break;
      case 'unless':
        parts.push(position === null ? 'exceptions' : `exception ${position}`);
        break;
      case 'exceptions':
        parts.push(
          position === null ? 'policy-wide exceptions' : `policy-wide exception ${position}`,
        );
        break;
      case 'actions':
        parts.push(position === null ? 'actions' : `action ${position}`);
        break;
      case 'all':
      case 'any':
        parts.push(position === null ? `${token} group` : `item ${position}`);
        break;
      case 'not':
        parts.push('NOT');
        break;
      default:
        parts.push(position === null ? token : `${token} ${position}`);
    }
  }
  return parts.join(' › ');
}
