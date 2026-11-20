import {
  findTool,
  NOT_APPLICABLE_OPERATIONS,
  type NotApplicableOperation,
  OPERATION_TOOLS,
  type OperationTool,
  toolNameOf,
} from '@email-gateway/assistant';
import { satisfiesRequirement } from '../../../auth-contracts/authorization';
import type { Principal, UserPrincipal } from '../../../auth-contracts/principal';

/**
 * The caller's view of the tool registry (step AI-1 D3–D5): the permission pre-filter is the
 * api's own `satisfiesRequirement` (the predicate of `PermissionsGuard`), so a tool is offered
 * exactly when the guard would let the loopback call through on permissions; `platform:*`-only
 * tools are absent for customer users. The guard still runs on every loopback call.
 */

/** A customer user's own organization or a platform operator (with or without an override). */
export const isPlatformUser = (principal: Principal): boolean =>
  principal.kind === 'user' && principal.organizationKind === 'platform';

/** Flags of the pre-filter: every assistant caller is an MFA-enrolled user (routes are user-only). */
const PREFILTER_FLAGS = { userOnly: true, requireMfa: false, allowDuringMfaEnrollment: false };

export type ToolAvailability =
  { available: true } | { available: false; reason: 'disabled' | 'permission' };

export function toolAvailability(principal: Principal, tool: OperationTool): ToolAvailability {
  if (!tool.enabled) return { available: false, reason: 'disabled' };
  if (tool.platformOnly && !isPlatformUser(principal)) {
    return { available: false, reason: 'permission' };
  }
  return satisfiesRequirement(principal, tool.requirement, PREFILTER_FLAGS).ok
    ? { available: true }
    : { available: false, reason: 'permission' };
}

/** The enabled tools this principal may call, in registry order. */
export function availableTools(
  principal: Principal,
  tools: readonly OperationTool[] = OPERATION_TOOLS,
): OperationTool[] {
  return tools.filter((tool) => toolAvailability(principal, tool).available);
}

const NOT_APPLICABLE_BY_NAME: ReadonlyMap<string, NotApplicableOperation> = new Map(
  NOT_APPLICABLE_OPERATIONS.map((op) => [toolNameOf(op.operationId), op]),
);

export type ToolLookup =
  | { kind: 'tool'; tool: OperationTool }
  | { kind: 'not_applicable'; operation: NotApplicableOperation }
  | { kind: 'unknown' };

/** Registry lookup by tool name (D5 step 2). */
export function lookupTool(name: string): ToolLookup {
  const tool = findTool(name);
  if (tool) return { kind: 'tool', tool };
  const operation = NOT_APPLICABLE_BY_NAME.get(name);
  return operation ? { kind: 'not_applicable', operation } : { kind: 'unknown' };
}

/** Public id of the scope's organization (the override target under a platform override). */
export function scopeOrganizationPublicId(principal: UserPrincipal): string {
  return principal.override?.targetOrganizationPublicId ?? principal.organizationPublicId;
}
