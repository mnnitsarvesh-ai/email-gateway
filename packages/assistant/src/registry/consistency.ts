import { hasImpactTemplate } from '../confirmations/impact';
import { CONFIRMATION_SPECS, type ConfirmationSpec } from '../confirmations/specs';
import { phaseIndex } from './build';
import { ASSISTANT_PROGRAM_PHASE, CONFIRMATION_SUPPORT_PHASE } from './manifest';
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
 */

export interface ConsistencyOptions {
  specs?: readonly ConfirmationSpec[];
  programPhase?: ProgramPhase;
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

  for (const tool of tools) {
    if ((tool.risk as string) === 'critical')
      issues.push(`${tool.name}: a critical operation must be not_applicable (portal only)`);
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
    if (pre?.kind === 'single') {
      const read = enabledRead(pre.tool, owner);
      if (read) {
        const mapped = Object.keys(pre.params).sort();
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
