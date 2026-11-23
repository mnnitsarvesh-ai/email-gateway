import { createHash } from 'node:crypto';
import {
  ASSISTANT_PROGRAM_PHASE,
  CONFIRMATION_SUPPORT_PHASE,
  CONFIRM_OF_RISK,
  CONTROLLER_HINTS,
  FEATURE_PAGES,
  NON_PAGE_FEATURES,
  OPERATION_OVERRIDES,
  READ_TOOLS_TESTED_BY,
  classifyOperation,
  type OperationFacts,
} from './manifest';
import {
  PROGRAM_PHASES,
  type HttpMethod,
  type MatrixStatus,
  type NotApplicableOperation,
  type OperationTool,
  type PermissionRequirement,
  type ProgramPhase,
} from './types';

/**
 * Pure registry builder (design D3): OpenAPI document + portal operation usage + manifest →
 * tool records and not-applicable records. `scripts/generate-registry.ts` does the file IO and
 * formatting; tests call this directly.
 */

export const API_PREFIX = '/api/v1';
export const DESCRIPTION_MAX_CHARS = 300;
const METHODS = ['get', 'put', 'post', 'delete', 'patch'] as const;
const SCHEMA_MAX_DEPTH = 40;

export interface OpenApiOperation {
  operationId?: string;
  summary?: string;
  description?: string;
  tags?: string[];
  parameters?: Array<{
    name: string;
    in: string;
    required?: boolean;
    description?: string;
    schema?: unknown;
    $ref?: string;
  }>;
  requestBody?: { required?: boolean; content?: Record<string, { schema?: unknown }> };
  'x-eg-permissions'?: { mode: 'all' | 'any'; permissions: string[] };
  'x-eg-returns-secret'?: boolean;
  'x-eg-idempotency'?: 'required' | 'legacy';
  'x-eg-rate-class'?: 'sensitive' | 'expensive';
  'x-eg-cursor'?: 'v0' | 'v1';
  responses?: Record<string, { content?: Record<string, { schema?: unknown }> }>;
  [key: string]: unknown;
}

export interface OpenApiDocument {
  paths: Record<string, Partial<Record<(typeof METHODS)[number], OpenApiOperation>>>;
  components?: { schemas?: Record<string, unknown>; parameters?: Record<string, unknown> };
}

/** operationId → portal feature folders that reference it. */
export type PortalUsage = ReadonlyMap<string, readonly string[]>;

export interface RegistryBuild {
  version: string;
  tools: OperationTool[];
  notApplicable: NotApplicableOperation[];
}

export function phaseIndex(phase: ProgramPhase): number {
  return PROGRAM_PHASES.indexOf(phase);
}

/** `PolicyManagement` → `policy_management`, `scansOf` → `scans_of`. */
export function snakeCase(value: string): string {
  return value
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .toLowerCase()
    .replace(/^_+|_+$/g, '');
}

/** `PolicyManagementController_list_v1` → `policy_management_list` (D3). */
export function toolNameOf(operationId: string): string {
  const [controller = '', method = ''] = operationId.split('_');
  return `${snakeCase(controller.replace(/Controller$/, ''))}_${snakeCase(method)}`.slice(0, 64);
}

export function trimText(value: string, max = DESCRIPTION_MAX_CHARS): string {
  const text = value.replace(/\s+/g, ' ').trim();
  return text.length <= max ? text : `${text.slice(0, max - 1).trimEnd()}…`;
}

export function requirementOf(op: OpenApiOperation): PermissionRequirement {
  const value = op['x-eg-permissions'];
  if (!value) return { mode: 'authenticated' };
  return { mode: value.mode, permissions: [...value.permissions] };
}

export function isPlatformOnly(requirement: PermissionRequirement): boolean {
  if (requirement.mode === 'authenticated') return false;
  const platform = (p: string) => p.startsWith('platform:');
  return requirement.mode === 'all'
    ? requirement.permissions.some(platform)
    : requirement.permissions.length > 0 && requirement.permissions.every(platform);
}

/**
 * OpenAPI 3.0 schema → strict-mode JSON Schema: `$ref`s inlined, `nullable` turned into a `null`
 * type/enum member, `example` dropped, descriptions trimmed to 300 characters.
 */
export function normalizeSchema(
  schema: unknown,
  components: Record<string, unknown> = {},
  depth = 0,
): Record<string, unknown> {
  if (depth > SCHEMA_MAX_DEPTH) throw new Error('schema too deep (recursive $ref?)');
  if (schema === null || typeof schema !== 'object' || Array.isArray(schema)) return {};
  const source = schema as Record<string, unknown>;
  if (typeof source.$ref === 'string') {
    const match = /^#\/components\/schemas\/(.+)$/.exec(source.$ref);
    const target = match ? components[match[1]!] : undefined;
    if (!target) throw new Error(`unresolved $ref ${source.$ref}`);
    return normalizeSchema(target, components, depth + 1);
  }
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(source)) {
    if (key === 'example' || key === 'examples' || key === 'nullable' || key === 'deprecated')
      continue;
    if (key === 'description' && typeof value === 'string') {
      out.description = trimText(value);
    } else if ((key === 'properties' || key === 'patternProperties') && isObject(value)) {
      out[key] = Object.fromEntries(
        Object.entries(value).map(([name, sub]) => [
          name,
          normalizeSchema(sub, components, depth + 1),
        ]),
      );
    } else if ((key === 'items' || key === 'not') && isObject(value)) {
      out[key] = normalizeSchema(value, components, depth + 1);
    } else if (key === 'additionalProperties' && isObject(value)) {
      out[key] = normalizeSchema(value, components, depth + 1);
    } else if ((key === 'anyOf' || key === 'oneOf' || key === 'allOf') && Array.isArray(value)) {
      out[key] = value.map((sub) => normalizeSchema(sub, components, depth + 1));
    } else {
      out[key] = structuredClone(value);
    }
  }
  if (source.nullable === true) {
    if (typeof out.type === 'string') {
      out.type = [out.type, 'null'];
      const values: unknown[] | null = Array.isArray(out.enum) ? (out.enum as unknown[]) : null;
      if (values && !values.includes(null)) out.enum = [...values, null];
    } else if (out.type === undefined) {
      const { description, ...rest } = out;
      return {
        ...(description !== undefined ? { description } : {}),
        anyOf: [rest, { type: 'null' }],
      };
    }
  }
  return out;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** True when `path` is `entry` or lies under it (the minimizer's rule, `minimize.ts`). */
function coveredBy(path: string, entry: string): boolean {
  return path === entry || path.startsWith(`${entry}.`) || path.startsWith(`${entry}[]`);
}

/** The JSON schema of the operation's success response (200, else 201), if any. */
export function successResponseSchema(op: OpenApiOperation): unknown {
  for (const code of ['200', '201']) {
    const schema = op.responses?.[code]?.content?.['application/json']?.schema;
    if (schema !== undefined) return schema;
  }
  return undefined;
}

/**
 * Response paths of free-form values (step AI-1 review, D8): objects without declared
 * properties, objects open to additional properties (maps, `Record<string, unknown>`) and
 * untyped values. Their keys and strings are not described by the contract (evidence, detail,
 * metadata, criteria, params), so they are untrusted by default; `''` is the response root.
 */
export function freeFormResponsePaths(
  op: OpenApiOperation,
  components: Record<string, unknown>,
): string[] {
  const schema = successResponseSchema(op);
  if (schema === undefined) return [];
  const out = new Set<string>();
  const walk = (node: Record<string, unknown>, path: string, depth: number): void => {
    if (depth > SCHEMA_MAX_DEPTH) return;
    const composed = [
      ...((node.anyOf as unknown[] | undefined) ?? []),
      ...((node.oneOf as unknown[] | undefined) ?? []),
      ...((node.allOf as unknown[] | undefined) ?? []),
    ].filter(isObject);
    const types = Array.isArray(node.type)
      ? (node.type as unknown[])
      : node.type !== undefined
        ? [node.type]
        : [];
    for (const variant of composed) walk(variant, path, depth + 1);
    if (composed.length > 0 && types.length === 0 && node.properties === undefined) return;
    if (types.includes('array') || node.items !== undefined) {
      if (isObject(node.items)) walk(node.items, `${path}[]`, depth + 1);
      return;
    }
    const additional = node.additionalProperties;
    const objectLike =
      types.includes('object') || node.properties !== undefined || additional !== undefined;
    const untyped =
      types.length === 0 &&
      node.properties === undefined &&
      node.enum === undefined &&
      node.const === undefined;
    if (!objectLike && !untyped) return;
    const properties = node.properties as Record<string, unknown> | undefined;
    if (
      !properties ||
      Object.keys(properties).length === 0 ||
      (additional !== undefined && additional !== false)
    ) {
      out.add(path);
      return;
    }
    for (const [key, sub] of Object.entries(properties))
      if (isObject(sub)) walk(sub, path ? `${path}.${key}` : key, depth + 1);
  };
  walk(normalizeSchema(schema, components), '', 0);
  return [...out];
}

/**
 * The tool's untrusted response paths: the manifest's (mail-derived and attacker-controlled
 * strings) followed by every free-form path the manifest does not already cover.
 */
export function untrustedFieldsOf(
  listed: readonly string[],
  freeForm: readonly string[],
): string[] {
  const fields = [...listed];
  for (const path of freeForm)
    if (!fields.some((entry) => coveredBy(path, entry))) fields.push(path);
  return fields;
}

interface InputSchemaParts {
  inputSchema: Record<string, unknown>;
  pathParams: string[];
  queryParams: string[];
  hasBody: boolean;
}

/** Path + query parameters (+ `body`) as one strict JSON Schema object (D3). */
export function buildInputSchema(
  op: OpenApiOperation,
  components: Record<string, unknown>,
  bound: ReadonlySet<string>,
): InputSchemaParts {
  const properties: Record<string, unknown> = {};
  const required: string[] = [];
  const pathParams: string[] = [];
  const queryParams: string[] = [];
  for (const param of op.parameters ?? []) {
    if (param.$ref) throw new Error(`${op.operationId}: parameter $ref is not supported`);
    if (param.in !== 'path' && param.in !== 'query') continue; // headers are never model-controlled
    const schema = normalizeSchema(param.schema ?? {}, components);
    if (param.description && schema.description === undefined)
      schema.description = trimText(param.description);
    properties[param.name] = schema;
    if (param.in === 'path') pathParams.push(param.name);
    else queryParams.push(param.name);
    if ((param.in === 'path' || param.required) && !bound.has(param.name))
      required.push(param.name);
  }
  const bodySchema = op.requestBody?.content?.['application/json']?.schema;
  const hasBody = bodySchema !== undefined;
  if (hasBody) {
    if ('body' in properties) throw new Error(`${op.operationId}: a parameter is named body`);
    properties.body = normalizeSchema(bodySchema, components);
    if (op.requestBody?.required) required.push('body');
  }
  const inputSchema: Record<string, unknown> = {
    type: 'object',
    properties,
    additionalProperties: false,
  };
  if (required.length > 0) inputSchema.required = required;
  return { inputSchema, pathParams, queryParams, hasBody };
}

function portalPagesOf(operationId: string, usage: PortalUsage): string[] {
  const features = [...(usage.get(operationId) ?? [])]
    .filter((feature) => !NON_PAGE_FEATURES.has(feature))
    .sort();
  const pages: string[] = [];
  for (const feature of features) {
    const label = FEATURE_PAGES[feature] ?? `/${feature}`;
    if (!pages.includes(label)) pages.push(label);
  }
  return pages;
}

function comparePaths(a: { module: string; pathTemplate: string; method: string }, b: typeof a) {
  return (
    a.module.localeCompare(b.module, 'en') ||
    a.pathTemplate.localeCompare(b.pathTemplate, 'en') ||
    a.method.localeCompare(b.method, 'en')
  );
}

export function buildRegistry(document: OpenApiDocument, usage: PortalUsage): RegistryBuild {
  const components = document.components?.schemas ?? {};
  const tools: OperationTool[] = [];
  const notApplicable: NotApplicableOperation[] = [];
  const seenIds = new Set<string>();
  const currentPhase = phaseIndex(ASSISTANT_PROGRAM_PHASE);
  const confirmationsBuilt = currentPhase >= phaseIndex(CONFIRMATION_SUPPORT_PHASE);

  for (const [fullPath, item] of Object.entries(document.paths)) {
    for (const lower of METHODS) {
      const op = item[lower];
      if (!op) continue;
      const method = lower.toUpperCase() as HttpMethod;
      const operationId = op.operationId;
      if (!operationId) throw new Error(`${method} ${fullPath} has no operationId`);
      if (seenIds.has(operationId)) throw new Error(`duplicate operationId ${operationId}`);
      seenIds.add(operationId);
      const path = fullPath.startsWith(API_PREFIX) ? fullPath.slice(API_PREFIX.length) : fullPath;
      const tags = op.tags ?? [];
      const module = tags.join(',') || 'untagged';
      const facts: OperationFacts = {
        operationId,
        method,
        path,
        tags,
        returnsSecret: op['x-eg-returns-secret'] === true,
      };
      const override = OPERATION_OVERRIDES[operationId] ?? {};
      const classification = classifyOperation(facts);
      const controller = operationId.split('_')[0] ?? '';
      const hints = CONTROLLER_HINTS[controller];
      const portalPages = portalPagesOf(operationId, usage);
      const portalRoute =
        override.portalRoute ??
        hints?.portalRoute ??
        portalPages.find((page) => page.startsWith('/'))?.split(',')[0] ??
        null;
      const requirement = requirementOf(op);
      const summary = trimText(override.title ?? op.summary ?? operationId);

      if (classification.kind === 'not_applicable' || override.status === 'not_applicable') {
        notApplicable.push({
          operationId,
          method,
          pathTemplate: fullPath,
          module,
          summary,
          requirement,
          access: classification.access,
          risk: classification.kind === 'not_applicable' ? classification.risk : null,
          reason:
            override.reason ??
            (classification.kind === 'not_applicable' ? classification.reason : 'not applicable'),
          portalRoute,
          portalPages,
        });
        continue;
      }

      if (override.access !== undefined && (override.access as string) !== 'write')
        throw new Error(
          `${operationId}: an access override may only make a read a write, never the reverse`,
        );
      const access = override.access ?? classification.access;
      if (access === 'write' && classification.access === 'read' && override.risk === undefined)
        throw new Error(`${operationId}: a read reclassified as a write needs a risk override`);
      const risk = override.risk ?? classification.risk;
      const phase = override.phase ?? classification.phase;
      const bind = { ...(override.bind ?? {}) };
      const parts = buildInputSchema(op, components, new Set(Object.keys(bind)));
      const enabled =
        phaseIndex(phase) <= currentPhase &&
        (access === 'read' || (confirmationsBuilt && Boolean(override.testedBy)));
      const testedBy =
        override.testedBy ?? (enabled && access === 'read' ? READ_TOOLS_TESTED_BY : null);
      const status: Exclude<MatrixStatus, 'NOT_APPLICABLE'> = !enabled
        ? 'MISSING'
        : override.limitations
          ? 'PARTIALLY_IMPLEMENTED'
          : 'IMPLEMENTED';
      tools.push({
        name: toolNameOf(operationId),
        operationId,
        method,
        pathTemplate: fullPath,
        module,
        summary,
        description: trimText(
          override.description ?? (op.description ? op.description : (op.summary ?? '')),
        ),
        ...parts,
        requirement,
        platformOnly: isPlatformOnly(requirement),
        idempotency: op['x-eg-idempotency'] ?? null,
        rateClass: op['x-eg-rate-class'] ?? null,
        cursor: op['x-eg-cursor'] ?? null,
        access,
        risk,
        confirm: CONFIRM_OF_RISK[risk],
        phase,
        enabled,
        status,
        portalRoute,
        portalPages,
        display: {
          ...override.display,
          resourceType:
            override.display?.resourceType ??
            hints?.resourceType ??
            snakeCase(controller.replace(/Controller$/, '')),
        },
        untrustedFields: untrustedFieldsOf(
          override.untrustedFields ?? [],
          freeFormResponsePaths(op, components),
        ),
        bind,
        limitations: override.limitations ?? null,
        testedBy,
      });
    }
  }
  tools.sort(comparePaths);
  notApplicable.sort(comparePaths);
  const version = createHash('sha256')
    .update(JSON.stringify({ tools, notApplicable }))
    .digest('hex')
    .slice(0, 16);
  return { version, tools, notApplicable };
}
