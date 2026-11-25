import { escalationField, escalationPath } from '../confirmations/escalation';
import { guardArgumentPaths, guardMessageKey } from '../confirmations/guards';
import { hasImpactTemplate } from '../confirmations/impact';
import {
  CONFIRMATION_SPECS,
  IMPACT_PREVIEW_TOOLS,
  type ConfirmationSpec,
} from '../confirmations/specs';
import { isCredentialKey } from '../results/sanitize';
import { phaseIndex } from './build';
import {
  ASSISTANT_PROGRAM_PHASE,
  CONFIRMATION_SUPPORT_PHASE,
  CREDENTIAL_FIELD_EXCEPTIONS,
  CREDENTIAL_KEY_EXCEPTIONS,
  OPERATION_OVERRIDES,
} from './manifest';
import { NATIVE_OPERATION_ID, NATIVE_PATH_PREFIX } from './native';
import type { OperationTool, ProgramPhase } from './types';

/**
 * Registry consistency rules of step AI-2 (design 29 §4.3), checked by the generator (it refuses
 * to write outputs that break them) and by the registry tests:
 *
 * - no tool of a phase after the program phase is enabled; no write is enabled before the
 *   confirmation manager exists (`CONFIRMATION_SUPPORT_PHASE`);
 * - an enabled write has a `testedBy` suite, a confirmation spec, an impact template and a
 *   confirmable risk (`low` / `medium` / `high`; `critical` operations are never tools);
 * - every spec belongs to an enabled write (exactly one spec per operation);
 * - every precondition tool (and each `toolByAction` tool) is an enabled read whose path
 *   parameters are exactly the mapped ones, and every mapped argument path exists in the write's
 *   input schema;
 * - every injected CAS field exists in the write's input schema (body or query) with the spec's
 *   minimum; `validateDefinition` names an existing body field.
 *
 * Step AI-3 (design 30 D3–D6, §4.3) adds:
 *
 * - every guard and escalation argument path exists in the write's input schema; a
 *   `deny_permission_change` guard with a `beforeField` needs a single precondition; all
 *   guards of a spec share one message key (`guardMessageOf`, D12);
 * - `select` only on single preconditions, with a non-empty `array` and an `arg` that exists in
 *   the write's input schema (the CAS `rowVersionField` is then item-relative);
 * - no enabled write's input schema has a property (at any depth of `properties`, `items`,
 *   `anyOf`/`oneOf`/`allOf`, `additionalProperties`) whose key matches the credential-key pattern
 *   (`isCredentialKey`, I14), except the named `CREDENTIAL_KEY_EXCEPTIONS`;
 * - the generator refuses an access override other than `'write'` (`build.ts`).
 *
 * Step AI-R (design 31 D1) adds the native tools (pass `[...operationTools, ...NATIVE_TOOLS]`):
 *
 * - tool names and operation ids are unique across both sets;
 * - a native tool has `native: true`, an operation id matching `^AssistantNative_[A-Za-z]+$`
 *   that is absent from OpenAPI (`openApiOperationIds`), a path template starting with
 *   `native:`, no path or query parameters, a strict input schema and a `testedBy` suite; no
 *   input key of a native tool matches the credential-key pattern;
 * - a generated tool never has `native` set or a `native:` path;
 * - every enabled native write has a confirmation spec with `native` set (and an impact
 *   template, as every enabled write); a spec of an OpenAPI write never sets `native`.
 *
 * Step AI-4 (design 32 D3, D5, D9, §4.4) adds:
 *
 * - `not_self_field` and `require_read_value` guards (they read the precondition target) need a
 *   single precondition;
 * - a single precondition maps exactly the read's path parameters plus, optionally, some of its
 *   query parameters (`threat_hashes_list { sha256 }`, an exact filter used with `select`);
 * - `redactParams` only on read tools (a write's stored request stays exact for its digest), and
 *   every listed path exists in the tool's input schema.
 *
 * Step AI-5 (design 33 D3, D5, D7, §4.3) adds:
 *
 * - a read-relative escalation (`below`, `becomes`, `differs`) needs a single precondition whose
 *   `stateFields` include its `field` (the confirm-time state digest then proves the compared
 *   value unchanged); its `path` exists in the write's input schema (as for every escalation);
 * - `impactToken` only with a single precondition, only an `IMPACT_PREVIEW_TOOLS` tool that is an
 *   enabled read, with params mapping exactly its path parameters to existing arguments, a
 *   `change.from` that exists, and a write whose input schema has `body.impactToken` and
 *   `body.confirm`; a server-filled `body.impactToken` satisfies the credential-key input rule
 *   (no `CREDENTIAL_KEY_EXCEPTIONS` entry), no other credential-pattern input does;
 * - no state, row-version or display field has a path segment matching the credential-key
 *   pattern, except the named `CREDENTIAL_FIELD_EXCEPTIONS` (the preview's `impactToken` never is);
 * - an `omitInputs` input (`OPERATION_OVERRIDES`) is absent from the tool's input schema and its
 *   query parameters (the generator removes it and refuses required or missing inputs).
 */

export interface ConsistencyOptions {
  specs?: readonly ConfirmationSpec[];
  programPhase?: ProgramPhase;
  /** The operation ids of `docs/api/openapi.json` (native ids must not be among them). */
  openApiOperationIds?: ReadonlySet<string>;
}

type Schema = Record<string, unknown>;

const isRecord = (value: unknown): value is Schema =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

/** The JSON schema of an argument path (`policyId`, `body.messageId`) in a tool's input schema. */
export function argumentSchema(tool: OperationTool, path: string): Schema | null {
  let node: unknown = tool.inputSchema;
  for (const segment of path.split('.')) {
    const properties = isRecord(node) ? node.properties : undefined;
    if (!isRecord(properties) || !isRecord(properties[segment])) return null;
    node = properties[segment];
  }
  return isRecord(node) ? node : null;
}

/** Paths (`body.settings.key`, `body.items[].token`) of credential-pattern keys in a schema. */
export function credentialKeyPaths(schema: unknown, prefix = '', depth = 0): string[] {
  if (!isRecord(schema) || depth > 40) return [];
  const out: string[] = [];
  const join = (key: string) => (prefix ? `${prefix}.${key}` : key);
  const properties = schema.properties;
  if (isRecord(properties))
    for (const [key, sub] of Object.entries(properties)) {
      if (isCredentialKey(key)) out.push(join(key));
      out.push(...credentialKeyPaths(sub, join(key), depth + 1));
    }
  if (isRecord(schema.items))
    out.push(...credentialKeyPaths(schema.items, `${prefix}[]`, depth + 1));
  for (const key of ['anyOf', 'oneOf', 'allOf'] as const) {
    const variants = schema[key];
    if (Array.isArray(variants))
      for (const variant of variants) out.push(...credentialKeyPaths(variant, prefix, depth + 1));
  }
  if (isRecord(schema.additionalProperties))
    out.push(...credentialKeyPaths(schema.additionalProperties, join('*'), depth + 1));
  return [...new Set(out)];
}

export function registryConsistencyIssues(
  tools: readonly OperationTool[],
  options: ConsistencyOptions = {},
): string[] {
  const specs = options.specs ?? CONFIRMATION_SPECS;
  const program = phaseIndex(options.programPhase ?? ASSISTANT_PROGRAM_PHASE);
  const confirmationsBuilt = program >= phaseIndex(CONFIRMATION_SUPPORT_PHASE);
  const issues: string[] = [];
  const byName = new Map(tools.map((tool) => [tool.name, tool]));
  const byOperation = new Map(tools.map((tool) => [tool.operationId, tool]));
  const specByOperation = new Map<string, ConfirmationSpec>();
  for (const spec of specs) {
    if (specByOperation.has(spec.operationId))
      issues.push(`${spec.operationId}: more than one confirmation spec`);
    specByOperation.set(spec.operationId, spec);
  }

  const names = new Set<string>();
  const operationIds = new Set<string>();
  for (const tool of tools) {
    if (names.has(tool.name)) issues.push(`${tool.name}: duplicate tool name`);
    if (operationIds.has(tool.operationId))
      issues.push(`${tool.operationId}: duplicate operation id`);
    names.add(tool.name);
    operationIds.add(tool.operationId);
    const nativePath = tool.pathTemplate.startsWith(NATIVE_PATH_PREFIX);
    if (tool.native === true) {
      if (!NATIVE_OPERATION_ID.test(tool.operationId))
        issues.push(`${tool.name}: native operation id must match ${NATIVE_OPERATION_ID.source}`);
      if (options.openApiOperationIds?.has(tool.operationId))
        issues.push(`${tool.name}: native operation id ${tool.operationId} exists in OpenAPI`);
      if (!nativePath)
        issues.push(`${tool.name}: native path template must start with ${NATIVE_PATH_PREFIX}`);
      if (tool.pathParams.length > 0 || tool.queryParams.length > 0 || tool.hasBody)
        issues.push(`${tool.name}: a native tool has no path, query or body parameters`);
      if (tool.inputSchema.additionalProperties !== false)
        issues.push(`${tool.name}: native input schema must set additionalProperties: false`);
      if (!tool.testedBy) issues.push(`${tool.name}: native tool without testedBy`);
      for (const path of credentialKeyPaths(tool.inputSchema))
        issues.push(`${tool.name}: input property ${path} matches the credential-key pattern`);
      if (tool.enabled && tool.access === 'write' && !specByOperation.get(tool.operationId)?.native)
        issues.push(`${tool.name}: enabled native write without a native confirmation spec`);
    } else if (
      nativePath ||
      tool.native !== undefined ||
      NATIVE_OPERATION_ID.test(tool.operationId)
    )
      issues.push(`${tool.name}: only native tools may use native ids or native: paths`);
    if (!tool.native && tool.access === 'write' && specByOperation.get(tool.operationId)?.native)
      issues.push(`${tool.name}: a native confirmation spec on an OpenAPI write`);
    if ((tool.risk as string) === 'critical')
      issues.push(`${tool.name}: a critical operation must be not_applicable (portal only)`);
    // Step AI-4 D9: redacted inputs only on side-effect-free reads, only existing paths.
    const redacted = tool.redactParams;
    if (redacted.length > 0 && tool.access !== 'read')
      issues.push(`${tool.name}: redactParams is only allowed on read tools`);
    for (const path of redacted)
      if (!argumentSchema(tool, path))
        issues.push(`${tool.name}: redactParams names the missing argument ${path}`);
    // Step AI-5 D7: omitted inputs are never offered to the model.
    if (!tool.native)
      for (const path of OPERATION_OVERRIDES[tool.operationId]?.omitInputs ?? [])
        if (argumentSchema(tool, path) || tool.queryParams.includes(path))
          issues.push(`${tool.name}: the omitted input ${path} is still in the input schema`);
    if (!tool.enabled) continue;
    if (phaseIndex(tool.phase) > program)
      issues.push(
        `${tool.name}: enabled although its phase ${tool.phase} is after the program phase`,
      );
    if (tool.access !== 'write') continue;
    if (!confirmationsBuilt)
      issues.push(`${tool.name}: a write is enabled before the confirmation manager exists`);
    if (!tool.testedBy) issues.push(`${tool.name}: enabled write without testedBy`);
    if (!specByOperation.has(tool.operationId))
      issues.push(`${tool.name}: enabled write without a confirmation spec`);
    if (!hasImpactTemplate(tool.operationId))
      issues.push(`${tool.name}: enabled write without an impact template`);
    if (!['low', 'medium', 'high'].includes(tool.risk))
      issues.push(`${tool.name}: enabled write with the non-confirmable risk ${tool.risk}`);
    if (tool.native) continue; // credential keys of native inputs are checked above
    const allowed = CREDENTIAL_KEY_EXCEPTIONS[tool.operationId] ?? {};
    // Step AI-5 D5: the server fills `body.impactToken` from a fresh preview (never the model).
    const serverFilled = specByOperation.get(tool.operationId)?.impactToken
      ? ['body.impactToken']
      : [];
    for (const path of credentialKeyPaths(tool.inputSchema))
      if (!Object.prototype.hasOwnProperty.call(allowed, path) && !serverFilled.includes(path))
        issues.push(`${tool.name}: input property ${path} matches the credential-key pattern`);
  }

  const enabledRead = (name: string, owner: string): OperationTool | null => {
    const read = byName.get(name);
    if (!read) issues.push(`${owner}: precondition tool ${name} does not exist`);
    else if (!read.enabled || read.access !== 'read')
      issues.push(`${owner}: precondition tool ${name} is not an enabled read`);
    else return read;
    return null;
  };

  for (const spec of specs) {
    const write = byOperation.get(spec.operationId);
    const owner = write?.name ?? spec.operationId;
    if (!write || !write.enabled || write.access !== 'write') {
      issues.push(`${spec.operationId}: confirmation spec without an enabled write tool`);
      continue;
    }
    const pre = spec.precondition;
    if (pre && pre.kind !== 'single' && 'select' in pre)
      issues.push(`${owner}: select is only allowed on a single precondition`);
    if (pre?.kind === 'single' && pre.select) {
      if (pre.select.array.length === 0 || pre.select.field.length === 0)
        issues.push(`${owner}: select needs a non-empty array and field`);
      if (!argumentSchema(write, pre.select.arg))
        issues.push(`${owner}: select reads the missing argument ${pre.select.arg}`);
    }
    for (const guard of spec.guards ?? []) {
      for (const path of guardArgumentPaths(guard))
        if (!argumentSchema(write, path))
          issues.push(`${owner}: ${guard.kind} guard reads the missing argument ${path}`);
      if (guard.kind === 'deny_permission_change' && guard.beforeField && pre?.kind !== 'single')
        issues.push(
          `${owner}: deny_permission_change with beforeField needs a single precondition`,
        );
      if (
        (guard.kind === 'not_self_field' || guard.kind === 'require_read_value') &&
        pre?.kind !== 'single'
      )
        issues.push(`${owner}: ${guard.kind} needs a single precondition`);
    }
    // Step AI-3 D12: a stored `denied_guard` execution shows the message derived from its spec
    // (`guardMessageOf`), which is only exact when all guards of the spec share one message.
    if (new Set((spec.guards ?? []).map(guardMessageKey)).size > 1)
      issues.push(`${owner}: all guards of a spec must share one message`);
    for (const escalation of spec.escalate ?? []) {
      const path = escalationPath(escalation.when);
      if (!argumentSchema(write, path))
        issues.push(`${owner}: escalation reads the missing argument ${path}`);
      // Step AI-5 D3: a read-relative condition compares with a state field of the single read.
      const field = escalationField(escalation.when);
      if (field !== null && (pre?.kind !== 'single' || !pre.stateFields.includes(field)))
        issues.push(
          `${owner}: read-relative escalation field ${field} must be a state field of a single precondition`,
        );
    }
    // Step AI-5 §4.3: no state or display field holds a credential-pattern key.
    if (pre) {
      const fieldExceptions = CREDENTIAL_FIELD_EXCEPTIONS[spec.operationId] ?? {};
      const fields = [
        ...pre.stateFields,
        ...(pre.rowVersionField ? [pre.rowVersionField] : []),
        ...(pre.kind === 'single' ? (pre.displayFields ?? []) : []),
      ];
      for (const field of new Set(fields))
        if (
          field.split('.').some((segment) => isCredentialKey(segment.replace(/\[\]$/, ''))) &&
          !Object.prototype.hasOwnProperty.call(fieldExceptions, field)
        )
          issues.push(
            `${owner}: state or display field ${field} matches the credential-key pattern`,
          );
    }
    // Step AI-5 D5: a server-filled impact token from an allow-listed preview.
    if (spec.impactToken) {
      const injection = spec.impactToken;
      if (pre?.kind !== 'single') issues.push(`${owner}: impactToken needs a single precondition`);
      if (!(IMPACT_PREVIEW_TOOLS as readonly string[]).includes(injection.previewTool))
        issues.push(`${owner}: impactToken preview ${injection.previewTool} is not allow-listed`);
      const preview = enabledRead(injection.previewTool, owner);
      if (preview) {
        const mapped = Object.keys(injection.params).sort();
        if (JSON.stringify(mapped) !== JSON.stringify([...preview.pathParams].sort()))
          issues.push(
            `${owner}: impactToken params [${mapped.join(', ')}] must map exactly the path parameters [${preview.pathParams.join(', ')}] of ${preview.name}`,
          );
        if (!preview.hasBody || !argumentSchema(preview, 'body.change'))
          issues.push(`${owner}: impactToken preview ${preview.name} takes no body.change`);
      }
      for (const [param, path] of Object.entries(injection.params))
        if (!argumentSchema(write, path))
          issues.push(`${owner}: impactToken param ${param} maps the missing argument ${path}`);
      if ('from' in injection.change && !argumentSchema(write, injection.change.from))
        issues.push(
          `${owner}: impactToken change reads the missing argument ${injection.change.from}`,
        );
      for (const path of ['body.impactToken', 'body.confirm'])
        if (!argumentSchema(write, path))
          issues.push(`${owner}: impactToken needs ${path} in the write's input schema`);
    }
    if (pre?.kind === 'single') {
      const read = enabledRead(pre.tool, owner);
      if (read) {
        // Every path parameter, plus optionally query parameters (step AI-4: exact filters).
        const mapped = Object.keys(pre.params)
          .filter((param) => !read.queryParams.includes(param) || read.pathParams.includes(param))
          .sort();
        if (JSON.stringify(mapped) !== JSON.stringify([...read.pathParams].sort()))
          issues.push(
            `${owner}: precondition params [${mapped.join(', ')}] must map exactly the path parameters [${read.pathParams.join(', ')}] of ${read.name}`,
          );
      }
      for (const [param, path] of Object.entries(pre.params))
        if (!argumentSchema(write, path))
          issues.push(`${owner}: precondition param ${param} maps the missing argument ${path}`);
      if (pre.stateFields.length === 0) issues.push(`${owner}: precondition without state fields`);
    } else if (pre?.kind === 'each') {
      const actionSchema = argumentSchema(write, pre.actionFrom);
      if (!argumentSchema(write, pre.idsFrom))
        issues.push(`${owner}: each precondition reads the missing argument ${pre.idsFrom}`);
      if (!actionSchema)
        issues.push(`${owner}: each precondition reads the missing argument ${pre.actionFrom}`);
      const actions = Array.isArray(actionSchema?.enum) ? (actionSchema.enum as unknown[]) : [];
      const reads: Array<[string, string, string]> = [['(default)', pre.tool, pre.param]];
      for (const [action, name] of Object.entries(pre.toolByAction ?? {})) {
        if (!actions.includes(action))
          issues.push(`${owner}: toolByAction names the unknown action ${action}`);
        reads.push([action, name, pre.paramByAction?.[action] ?? pre.param]);
      }
      for (const [action, name, param] of reads) {
        const read = enabledRead(name, owner);
        if (read && (read.pathParams.length !== 1 || read.pathParams[0] !== param))
          issues.push(
            `${owner}: ${action} read ${name} must take exactly the path parameter ${param}`,
          );
      }
      if (pre.stateFields.length === 0) issues.push(`${owner}: precondition without state fields`);
    }
    if (spec.inject) {
      const path = spec.inject.in === 'body' ? `body.${spec.inject.field}` : spec.inject.field;
      const schema = argumentSchema(write, path);
      if (!schema) issues.push(`${owner}: injected field ${path} is not in the input schema`);
      else if (schema.minimum !== spec.inject.min)
        issues.push(
          `${owner}: injected field ${path} has minimum ${String(schema.minimum)}, spec says ${spec.inject.min}`,
        );
      if (spec.inject.in === 'query' && !write.queryParams.includes(spec.inject.field))
        issues.push(`${owner}: injected query field ${spec.inject.field} is not a query parameter`);
      if (!pre || (pre.kind === 'single' && !pre.rowVersionField))
        issues.push(`${owner}: CAS injection needs a precondition with a rowVersionField`);
    }
    if (spec.validateDefinition && !argumentSchema(write, spec.validateDefinition))
      issues.push(
        `${owner}: validateDefinition names the missing argument ${spec.validateDefinition}`,
      );
  }
  return issues;
}
