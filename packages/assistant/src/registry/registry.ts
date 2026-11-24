import Ajv, { type ErrorObject, type ValidateFunction } from 'ajv';
import addFormats from 'ajv-formats';
import {
  NOT_APPLICABLE_OPERATIONS,
  OPERATION_TOOLS,
  REGISTRY_VERSION,
} from './operations.generated';
import { NATIVE_TOOLS, isNativeTool } from './native';
import type { NotApplicableOperation, OperationTool, PermissionRequirement } from './types';

/**
 * Runtime helpers over the generated registry (design D3–D5): lookup, the permission pre-filter
 * view of the catalogue, the catalogue index of the system prompt, `describe_tool` output and the
 * cached Ajv validators of tool arguments. Step AI-R (design 31 D1): the native tools are part of
 * every helper through `ALL_TOOLS`.
 */

export { NATIVE_TOOLS, NOT_APPLICABLE_OPERATIONS, OPERATION_TOOLS, REGISTRY_VERSION, isNativeTool };

/** The generated operation tools followed by the native tools (step AI-R D1). */
export const ALL_TOOLS: readonly OperationTool[] = [...OPERATION_TOOLS, ...NATIVE_TOOLS];

const BY_NAME: ReadonlyMap<string, OperationTool> = new Map(
  ALL_TOOLS.map((tool) => [tool.name, tool]),
);
const BY_OPERATION: ReadonlyMap<string, OperationTool | NotApplicableOperation> = new Map<
  string,
  OperationTool | NotApplicableOperation
>([
  ...ALL_TOOLS.map((tool) => [tool.operationId, tool] as const),
  ...NOT_APPLICABLE_OPERATIONS.map((op) => [op.operationId, op] as const),
]);

export function findTool(name: string): OperationTool | undefined {
  return BY_NAME.get(name);
}

export function findOperation(
  operationId: string,
): OperationTool | NotApplicableOperation | undefined {
  return BY_OPERATION.get(operationId);
}

/**
 * The same predicate as `PermissionsGuard` (`all` / `any` / `authenticated`). The api keeps the
 * authoritative copy (`apps/api/src/auth-contracts/authorization.ts`); this one serves the
 * package's pure helpers and tests.
 */
export function satisfiesRequirement(
  requirement: PermissionRequirement,
  held: ReadonlySet<string>,
): boolean {
  if (requirement.mode === 'authenticated') return true;
  if (requirement.mode === 'all') return requirement.permissions.every((p) => held.has(p));
  return requirement.permissions.some((p) => held.has(p));
}

/**
 * The tools this principal may use: enabled, permission requirement satisfied, and platform-only
 * tools only for platform users (D5 step 3). Registry order (module, path, method).
 */
export function enabledTools(
  principalPermissions: Iterable<string>,
  isPlatformUser: boolean,
  tools: readonly OperationTool[] = ALL_TOOLS,
): OperationTool[] {
  const held = new Set(principalPermissions);
  return tools.filter(
    (tool) =>
      tool.enabled &&
      (!tool.platformOnly || isPlatformUser) &&
      satisfiesRequirement(tool.requirement, held),
  );
}

const ENUM_INLINE_MAX = 8;

function paramSignature(name: string, schema: unknown, required: boolean): string {
  const optional = required ? '' : '?';
  const values = enumValues(schema);
  if (values && values.length <= ENUM_INLINE_MAX) return `${name}${optional}: ${values.join('|')}`;
  return `${name}${optional}`;
}

function enumValues(schema: unknown): string[] | null {
  if (!schema || typeof schema !== 'object') return null;
  const value = (schema as { enum?: unknown }).enum;
  if (!Array.isArray(value)) return null;
  return value.filter((v) => v !== null).map((v) => String(v));
}

/**
 * One signature line (D4): `name(param?: a|b, cursor?, limit?) - Summary`. A native tool lists
 * its input properties in schema order (it has no path or query parameters).
 */
export function toolSignature(tool: OperationTool): string {
  const properties = (tool.inputSchema.properties ?? {}) as Record<string, unknown>;
  const required = new Set((tool.inputSchema.required as string[] | undefined) ?? []);
  const paging = ['cursor', 'limit'];
  const names = isNativeTool(tool)
    ? Object.keys(properties)
    : [
        ...tool.pathParams,
        ...tool.queryParams.filter((name) => !paging.includes(name)),
        ...(tool.hasBody ? ['body'] : []),
        ...tool.queryParams.filter((name) => paging.includes(name)),
      ];
  const params = names.map((name) => paramSignature(name, properties[name], required.has(name)));
  return `${tool.name}(${params.join(', ')}) - ${tool.summary}`;
}

/**
 * The catalogue index of the system prompt (D4): the given tools grouped by module in a fixed
 * (alphabetical) order, one signature line each. Deterministic for prompt caching.
 */
export function renderCatalogueIndex(tools: readonly OperationTool[]): string {
  const modules = new Map<string, OperationTool[]>();
  for (const tool of tools) {
    const list = modules.get(tool.module) ?? [];
    list.push(tool);
    modules.set(tool.module, list);
  }
  const lines: string[] = [];
  for (const module of [...modules.keys()].sort((a, b) => a.localeCompare(b, 'en'))) {
    lines.push(`## ${module}`);
    const list = [...modules.get(module)!].sort((a, b) => a.name.localeCompare(b.name, 'en'));
    for (const tool of list) lines.push(toolSignature(tool));
    lines.push('');
  }
  return lines.join('\n').trimEnd();
}

export interface ToolDescription {
  name: string;
  module: string;
  summary: string;
  description: string;
  access: OperationTool['access'];
  risk: OperationTool['risk'];
  confirm: OperationTool['confirm'];
  available: boolean;
  /** Why it is not available (when not). */
  unavailableReason: 'disabled' | 'permission' | null;
  inputSchema: Record<string, unknown>;
  portalRoute: string | null;
  limitations: string | null;
}

/** `describe_tool` output (D4). `available` is computed by the caller's pre-filter. */
export function describeTool(
  tool: OperationTool,
  availability: { available: boolean; reason?: 'disabled' | 'permission' } = {
    available: tool.enabled,
    reason: tool.enabled ? undefined : 'disabled',
  },
): ToolDescription {
  return {
    name: tool.name,
    module: tool.module,
    summary: tool.summary,
    description: tool.description,
    access: tool.access,
    risk: tool.risk,
    confirm: tool.confirm,
    available: availability.available,
    unavailableReason: availability.available ? null : (availability.reason ?? 'disabled'),
    inputSchema: tool.inputSchema,
    portalRoute: tool.portalRoute,
    limitations: tool.limitations,
  };
}

// ---------------------------------------------------------------------------------------------
// Argument validation (D5 step 6)
// ---------------------------------------------------------------------------------------------

export interface ArgumentIssue {
  /** JSON pointer of the offending argument (never its value). */
  path: string;
  keyword: string;
  /** Ajv's message (built from the schema, not from the value). */
  message: string;
}

export type ArgumentValidation = { ok: true } | { ok: false; issues: ArgumentIssue[] };
export type ArgumentValidator = (value: unknown) => ArgumentValidation;

let ajv: Ajv | null = null;
const validators = new WeakMap<OperationTool, ValidateFunction>();

function ajvInstance(): Ajv {
  if (ajv) return ajv;
  ajv = new Ajv({ strict: true, allErrors: true, allowUnionTypes: true, validateFormats: true });
  addFormats(ajv, ['uuid', 'date-time', 'date', 'email']);
  return ajv;
}

const MAX_ISSUES = 10;

function toIssue(error: ErrorObject): ArgumentIssue {
  const missing =
    error.keyword === 'required' && typeof error.params.missingProperty === 'string'
      ? `/${error.params.missingProperty}`
      : '';
  const extra =
    error.keyword === 'additionalProperties' && typeof error.params.additionalProperty === 'string'
      ? `/${String(error.params.additionalProperty).slice(0, 64)}`
      : '';
  return {
    path: `${error.instancePath}${missing}${extra}` || '/',
    keyword: error.keyword,
    message: error.message ?? error.keyword,
  };
}

/** Ajv 8 strict validator of a tool's arguments, compiled once per tool record and cached. */
export function compileValidator(tool: OperationTool): ArgumentValidator {
  let validate = validators.get(tool);
  if (!validate) {
    validate = ajvInstance().compile(tool.inputSchema);
    validators.set(tool, validate);
  }
  const fn = validate;
  return (value: unknown) => {
    if (fn(value)) return { ok: true };
    return { ok: false, issues: (fn.errors ?? []).slice(0, MAX_ISSUES).map(toIssue) };
  };
}
