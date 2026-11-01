// @ts-check
import path from 'node:path';

/** Deep control-plane entry points of @esg/db and @esg/config (hard rule 2). */
export const CONTROL_PLANE_REGEX_SOURCE = '^@esg/(db|config)/.*control-plane';
const CONTROL_PLANE_REGEX = new RegExp(CONTROL_PLANE_REGEX_SOURCE);

const WORKSPACE_PATTERNS = [
  /^services\/[^/]+/,
  /^packages\/[^/]+/,
  /^tooling\/[^/]+/,
  /^db(?=\/|$)/,
  /^test\/e2e(?=\/|$)/,
];

/**
 * Repo-relative (posix) directory of the workspace that owns `filename`, if any.
 * @param {string} root
 * @param {string} filename
 * @returns {string | undefined}
 */
export function workspaceOf(root, filename) {
  const rel = path.relative(root, filename).split(path.sep).join('/');
  if (rel.startsWith('..')) return undefined;
  for (const re of WORKSPACE_PATTERNS) {
    const m = re.exec(rel);
    if (m) return m[0];
  }
  return undefined;
}

/** @param {string} spec */
function isRelative(spec) {
  return spec === '.' || spec === '..' || spec.startsWith('./') || spec.startsWith('../');
}

/**
 * Literal string value of a specifier expression, or undefined when not literal.
 * @param {any} node
 * @returns {string | undefined}
 */
function literal(node) {
  if (!node) return undefined;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0 && node.quasis.length === 1) {
    return node.quasis[0].value.cooked ?? undefined;
  }
  return undefined;
}

/**
 * True when the call is `require(...)`, `require.resolve(...)` or `createRequire(...)(...)`.
 * @param {any} callee
 */
function isRequireCallee(callee) {
  if (callee.type === 'Identifier') return callee.name === 'require';
  if (callee.type === 'MemberExpression') {
    return callee.object.type === 'Identifier' && callee.object.name === 'require' && !callee.computed;
  }
  if (callee.type === 'CallExpression') {
    const inner = callee.callee;
    if (inner.type === 'Identifier') return inner.name === 'createRequire';
    if (inner.type === 'MemberExpression') return !inner.computed && inner.property.name === 'createRequire';
  }
  return false;
}

/**
 * Local rule enforcing hard rules 8 and 2 for forms `no-restricted-imports` cannot see:
 *  - any relative specifier (static, dynamic import(), require, createRequire()()) that resolves
 *    outside the importing file's own workspace root;
 *  - dynamic import()/require of service package names and of control-plane subpaths.
 * Static name-based restrictions stay with core `no-restricted-imports`.
 * @type {import('eslint').Rule.RuleModule}
 */
export const importBoundaries = {
  meta: {
    type: 'problem',
    schema: [{ type: 'object' }],
    docs: { description: 'Enforce workspace boundaries for relative, dynamic and require() imports.' },
  },
  create(context) {
    const opts = /** @type {{ root: string, services: { dir: string, name?: string }[], controlPlaneAllow: string[] }} */ (
      context.options[0]
    );
    const ws = workspaceOf(opts.root, context.filename);
    if (!ws) return {};
    const own = opts.services.find((s) => `services/${s.dir}` === ws)?.name;
    const controlPlaneAllowed = opts.controlPlaneAllow.some((a) => ws === a || ws.startsWith(`${a}/`));

    /**
     * @param {any} node
     * @param {string | undefined} spec
     * @param {boolean} dynamic
     */
    function check(node, spec, dynamic) {
      if (spec === undefined) return;
      if (isRelative(spec)) {
        const target = path.resolve(path.dirname(context.filename), spec);
        const rel = path.relative(path.join(opts.root, ws ?? ''), target);
        if (rel.startsWith('..') || path.isAbsolute(rel)) {
          context.report({
            node,
            message: `[boundary] Relative import "${spec}" leaves workspace ${ws ?? ''}. Import the package by name (@esg/<name>) instead (hard rule 8).`,
          });
        }
        return;
      }
      if (!dynamic) return;
      for (const s of opts.services) {
        if (!s.name || s.name === own) continue;
        if (spec === s.name || spec.startsWith(`${s.name}/`)) {
          context.report({
            node,
            message: `[boundary] Services must not be imported by other workspaces (hard rule 8): ${spec}. Move shared code to a package under packages/.`,
          });
        }
      }
      if (!controlPlaneAllowed && CONTROL_PLANE_REGEX.test(spec)) {
        context.report({
          node,
          message: `[control-plane] ${spec} is reserved for ${opts.controlPlaneAllow.join(', ')} (hard rule 2).`,
        });
      }
    }

    return {
      ImportDeclaration: (/** @type {any} */ n) => check(n, literal(n.source), false),
      ExportNamedDeclaration: (/** @type {any} */ n) => {
        if (n.source) check(n, literal(n.source), false);
      },
      ExportAllDeclaration: (/** @type {any} */ n) => check(n, literal(n.source), false),
      ImportExpression: (/** @type {any} */ n) => check(n, literal(n.source), true),
      TSImportType: (/** @type {any} */ n) => check(n, literal(n.argument?.literal ?? n.argument), true),
      TSExternalModuleReference: (/** @type {any} */ n) => check(n, literal(n.expression), true),
      CallExpression: (/** @type {any} */ n) => {
        if (isRequireCallee(n.callee) && n.arguments.length > 0) check(n, literal(n.arguments[0]), true);
      },
    };
  },
};
