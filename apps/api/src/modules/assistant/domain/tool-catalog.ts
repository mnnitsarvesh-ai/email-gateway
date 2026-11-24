import {
  ALL_TOOLS,
  findTool,
  isNativeTool,
  sanitizeText,
  NOT_APPLICABLE_OPERATIONS,
  type NotApplicableOperation,
  type OperationTool,
  REPORT_GENERATE,
  REPORT_SEND_EMAIL,
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
export const PREFILTER_FLAGS = {
  userOnly: true,
  requireMfa: false,
  allowDuringMfaEnrollment: false,
};

/**
 * The platform switches of the native tools (step AI-R D1): `report_generate` is hidden when
 * ASSISTANT_REPORTS_ENABLED=false, `report_send_email` when ASSISTANT_REPORT_EMAIL_ENABLED=false
 * (`denied_disabled`, absent from the catalogue index and `GET /assistant/tools`).
 */
export interface NativeSwitches {
  reports: boolean;
  reportEmail: boolean;
}

/** Both native tools switched on (the configuration defaults). */
export const NATIVE_SWITCHES_ON: NativeSwitches = Object.freeze({
  reports: true,
  reportEmail: true,
});

export function nativeSwitchesOf(config: {
  ASSISTANT_REPORTS_ENABLED: boolean;
  ASSISTANT_REPORT_EMAIL_ENABLED: boolean;
}): NativeSwitches {
  return {
    reports: config.ASSISTANT_REPORTS_ENABLED,
    reportEmail: config.ASSISTANT_REPORT_EMAIL_ENABLED,
  };
}

/** False for a native tool whose platform switch is off; true for every other tool. */
export function nativeSwitchedOn(tool: OperationTool, switches: NativeSwitches): boolean {
  if (!isNativeTool(tool)) return true;
  if (tool.name === REPORT_GENERATE.name) return switches.reports;
  if (tool.name === REPORT_SEND_EMAIL.name) return switches.reportEmail;
  return false;
}

export type ToolAvailability =
  { available: true } | { available: false; reason: 'disabled' | 'permission' };

export function toolAvailability(
  principal: Principal,
  tool: OperationTool,
  switches: NativeSwitches = NATIVE_SWITCHES_ON,
): ToolAvailability {
  if (!tool.enabled || !nativeSwitchedOn(tool, switches)) {
    return { available: false, reason: 'disabled' };
  }
  if (tool.platformOnly && !isPlatformUser(principal)) {
    return { available: false, reason: 'permission' };
  }
  return satisfiesRequirement(principal, tool.requirement, PREFILTER_FLAGS).ok
    ? { available: true }
    : { available: false, reason: 'permission' };
}

/**
 * The enabled tools this principal may call, in registry order (step AI-R: the generated
 * operation tools followed by the native tools whose switch is on).
 */
export function availableTools(
  principal: Principal,
  switches: NativeSwitches = NATIVE_SWITCHES_ON,
  tools: readonly OperationTool[] = ALL_TOOLS,
): OperationTool[] {
  return tools.filter((tool) => toolAvailability(principal, tool, switches).available);
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

/**
 * The display title of a tool call (the stream's `tool.started` title and the execution view's
 * `title`): the tool's display title or summary, the summary of a not-applicable operation, else
 * the (sanitised) name.
 */
export function toolTitleOf(name: string): string {
  const lookup = lookupTool(name);
  return sanitizeText(
    lookup.kind === 'tool'
      ? (lookup.tool.display.title ?? lookup.tool.summary)
      : lookup.kind === 'not_applicable'
        ? lookup.operation.summary
        : name,
    120,
  );
}

/** Public id of the scope's organization (the override target under a platform override). */
export function scopeOrganizationPublicId(principal: UserPrincipal): string {
  return principal.override?.targetOrganizationPublicId ?? principal.organizationPublicId;
}
