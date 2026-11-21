import { sanitizeText } from '../results/sanitize';
import { stateDigest, valueAtPath } from './digest';

/**
 * Confirmation specs (step AI-2 D4): for every enabled write, how the executor reads the target's
 * current state before proposing (the precondition read, through an enabled read tool and the
 * user's own token), which fields of that read bind the confirmation (state digest), which CAS
 * field it injects from the read, and whether a policy definition is validated first. The
 * registry check (`registryConsistencyIssues`) requires exactly one spec per enabled write.
 *
 * Argument paths address the write tool's input object: path and query parameters at the top
 * level (`policyId`), the JSON body under `body` (`body.messageId`).
 */

/** A read of one target. `params` maps the read tool's path parameters to argument paths. */
export interface SinglePrecondition {
  kind: 'single';
  tool: string;
  params: Readonly<Record<string, string>>;
  /** Fields of the read whose change between proposal and confirm refuses the confirm. */
  stateFields: readonly string[];
  /** Field holding the CAS counter (injected when the spec has `inject`). */
  rowVersionField?: string;
  /** Further fields the impact template shows (sanitized, ≤ 300 characters). */
  displayFields?: readonly string[];
}

/** One read per id of a list argument (quarantine bulk: the first `max` ids). */
/** Most precondition reads of one confirmation (the first items of an `each` precondition). */
export const PRECONDITION_MAX_READS = 25;

export interface EachPrecondition {
  kind: 'each';
  /** Read tool per `body.action` value (else `tool`). */
  toolByAction?: Readonly<Record<string, string>>;
  /** The path parameter of a `toolByAction` tool (else `param`). */
  paramByAction?: Readonly<Record<string, string>>;
  tool: string;
  /** The path parameter of `tool` that takes the id. */
  param: string;
  idsFrom: 'body.ids';
  actionFrom: 'body.action';
  max: typeof PRECONDITION_MAX_READS;
  /** Per item; a missing field is null (entries have `state`, approvals `status`). */
  stateFields: readonly string[];
  rowVersionField?: string;
}

export type ConfirmationPrecondition = SinglePrecondition | EachPrecondition;

/** CAS field set from the precondition read's row version (server-authoritative, D1 step 5). */
export interface CasInjection {
  in: 'body' | 'query';
  field: 'expectedRowVersion' | 'expectedVersion';
  /** The schema minimum; also the placeholder used before the read (D1). */
  min: 0 | 1;
}

export interface ConfirmationSpec {
  operationId: string;
  precondition: ConfirmationPrecondition | null;
  inject?: CasInjection;
  validateDefinition?: 'body.definition';
}

const POLICY_GET = 'policy_management_get';
const POLICY_GET_VERSION = 'policy_management_get_version';
const ENTRY_DETAIL = 'quarantine_entries_detail';
const SELF_DETAIL = 'quarantine_self_detail';
const MESSAGE_DETAIL = 'messages_detail';
const APPROVAL_GET = 'quarantine_approvals_get';

const POLICY_DISPLAY = [
  'name',
  'description',
  'status',
  'direction',
  'priority',
  'activeVersionNo',
  'latestVersionNo',
] as const;
const VERSION_DISPLAY = ['versionNo', 'status', 'active', 'ruleCount', 'changeNote'] as const;
const ENTRY_DISPLAY = [
  'subject',
  'sender.envelope',
  'sender.headerFrom',
  'recipient',
  'reason',
  'direction',
  'riskLevel',
  'kind',
  'approvalRequestId',
] as const;
const MESSAGE_DISPLAY = [
  'subject',
  'envelopeFrom',
  'headerFrom',
  'direction',
  'finalVerdict',
  'finalAction',
  'recipientCount',
] as const;
const APPROVAL_DISPLAY = ['kind', 'entryId', 'expiresAt', 'requestedBy.type'] as const;

const policy = (stateFields: readonly string[]): SinglePrecondition => ({
  kind: 'single',
  tool: POLICY_GET,
  params: { policyId: 'policyId' },
  stateFields,
  rowVersionField: 'rowVersion',
  displayFields: POLICY_DISPLAY,
});
const policyVersion = (): SinglePrecondition => ({
  kind: 'single',
  tool: POLICY_GET_VERSION,
  params: { policyId: 'policyId', versionNo: 'versionNo' },
  stateFields: ['rowVersion', 'status'],
  rowVersionField: 'rowVersion',
  displayFields: VERSION_DISPLAY,
});
const entry = (tool: string): SinglePrecondition => ({
  kind: 'single',
  tool,
  params: { entryId: 'entryId' },
  stateFields: ['rowVersion', 'state'],
  rowVersionField: 'rowVersion',
  displayFields: ENTRY_DISPLAY,
});
const message = (argPath: string): SinglePrecondition => ({
  kind: 'single',
  tool: MESSAGE_DETAIL,
  params: { messageId: argPath },
  stateFields: ['status', 'version', 'lifecycleRound'],
  rowVersionField: 'version',
  displayFields: MESSAGE_DISPLAY,
});
const approval = (): SinglePrecondition => ({
  kind: 'single',
  tool: APPROVAL_GET,
  params: { approvalId: 'approvalId' },
  stateFields: ['status'],
  displayFields: APPROVAL_DISPLAY,
});
const BODY_ROW_VERSION: CasInjection = { in: 'body', field: 'expectedRowVersion', min: 1 };
const QUERY_ROW_VERSION: CasInjection = { in: 'query', field: 'expectedRowVersion', min: 1 };

/** The 31 writes of step AI-2 (design D4; field names checked against docs/api/openapi.json). */
export const CONFIRMATION_SPECS: readonly ConfirmationSpec[] = [
  // --- policies (11) ---
  {
    operationId: 'PolicyManagementController_create_v1',
    precondition: null,
    validateDefinition: 'body.definition',
  },
  {
    operationId: 'PolicyManagementController_update_v1',
    precondition: policy(['rowVersion', 'name', 'description', 'status']),
    inject: BODY_ROW_VERSION,
  },
  {
    operationId: 'PolicyManagementController_enable_v1',
    precondition: policy(['rowVersion', 'status', 'activeVersionNo']),
    inject: BODY_ROW_VERSION,
  },
  {
    operationId: 'PolicyManagementController_disable_v1',
    precondition: policy(['rowVersion', 'status', 'activeVersionNo']),
    inject: BODY_ROW_VERSION,
  },
  {
    operationId: 'PolicyManagementController_remove_v1',
    precondition: policy(['rowVersion', 'status']),
    inject: QUERY_ROW_VERSION,
  },
  {
    operationId: 'PolicyManagementController_createDraft_v1',
    precondition: policy(['rowVersion', 'status', 'latestVersionNo']),
    validateDefinition: 'body.definition',
  },
  {
    operationId: 'PolicyManagementController_updateDraft_v1',
    precondition: policyVersion(),
    inject: BODY_ROW_VERSION,
    validateDefinition: 'body.definition',
  },
  {
    operationId: 'PolicyManagementController_deleteDraft_v1',
    precondition: policyVersion(),
    inject: QUERY_ROW_VERSION,
  },
  {
    operationId: 'PolicyManagementController_publish_v1',
    precondition: policyVersion(),
    inject: BODY_ROW_VERSION,
  },
  {
    operationId: 'PolicyManagementController_activate_v1',
    precondition: policy(['rowVersion', 'status', 'activeVersionNo']),
    inject: BODY_ROW_VERSION,
  },
  {
    operationId: 'PolicySettingsController_put_v1',
    precondition: {
      kind: 'single',
      tool: 'policy_settings_get',
      params: {},
      stateFields: ['rowVersion', 'settingsSha256'],
      rowVersionField: 'rowVersion',
      displayFields: [
        'effective.allowRecommendationOverrides',
        'effective.recipientSplit',
        'effective.notices.senderNonDelivery',
        'effective.alerts.enabled',
        'effective.tagging.platformTagHeader',
        'effective.tagging.platformTagOutbound',
      ],
    },
    inject: { in: 'body', field: 'expectedRowVersion', min: 0 },
  },
  // --- quarantine (13) ---
  {
    operationId: 'QuarantineEntriesController_release_v1',
    precondition: entry(ENTRY_DETAIL),
    inject: BODY_ROW_VERSION,
  },
  {
    operationId: 'QuarantineEntriesController_reject_v1',
    precondition: entry(ENTRY_DETAIL),
    inject: BODY_ROW_VERSION,
  },
  {
    operationId: 'QuarantineEntriesController_delete_v1',
    precondition: entry(ENTRY_DETAIL),
    inject: BODY_ROW_VERSION,
  },
  {
    operationId: 'QuarantineEntriesController_requestRelease_v1',
    precondition: entry(ENTRY_DETAIL),
  },
  {
    operationId: 'QuarantineSelfController_release_v1',
    precondition: entry(SELF_DETAIL),
    inject: BODY_ROW_VERSION,
  },
  {
    operationId: 'QuarantineSelfController_requestRelease_v1',
    precondition: entry(SELF_DETAIL),
  },
  {
    operationId: 'QuarantineSelfController_putPreferences_v1',
    precondition: {
      kind: 'single',
      tool: 'quarantine_self_preferences',
      params: {},
      stateFields: ['digestOptOut'],
      displayFields: ['allowOptOut'],
    },
  },
  {
    operationId: 'QuarantineToolsController_putSettings_v1',
    precondition: {
      kind: 'single',
      tool: 'quarantine_tools_get_settings',
      params: {},
      stateFields: ['rowVersion'],
      rowVersionField: 'rowVersion',
    },
    inject: { in: 'body', field: 'expectedRowVersion', min: 0 },
  },
  {
    operationId: 'QuarantineEntriesController_manual_v1',
    precondition: message('body.messageId'),
  },
  { operationId: 'QuarantineApprovalsController_approve_v1', precondition: approval() },
  { operationId: 'QuarantineApprovalsController_deny_v1', precondition: approval() },
  { operationId: 'QuarantineApprovalsController_cancel_v1', precondition: approval() },
  {
    operationId: 'QuarantineToolsController_bulk_v1',
    precondition: {
      kind: 'each',
      tool: ENTRY_DETAIL,
      param: 'entryId',
      toolByAction: { approve: APPROVAL_GET, deny: APPROVAL_GET },
      paramByAction: { approve: 'approvalId', deny: 'approvalId' },
      idsFrom: 'body.ids',
      actionFrom: 'body.action',
      max: PRECONDITION_MAX_READS,
      stateFields: ['state', 'status', 'rowVersion'],
      rowVersionField: 'rowVersion',
    },
  },
  // --- messages (2) ---
  {
    operationId: 'MessageLifecycleController_release_v1',
    precondition: message('messageId'),
    inject: { in: 'body', field: 'expectedVersion', min: 0 },
  },
  {
    operationId: 'MessageLifecycleController_rescan_v1',
    precondition: message('messageId'),
    inject: { in: 'body', field: 'expectedVersion', min: 0 },
  },
  // --- recipient suppressions (2) ---
  { operationId: 'RecipientSuppressionsController_create_v1', precondition: null },
  {
    operationId: 'RecipientSuppressionsController_delete_v1',
    precondition: {
      kind: 'single',
      tool: 'recipient_suppressions_get',
      params: { suppressionId: 'suppressionId' },
      stateFields: ['active', 'expiresAt', 'reason'],
      displayFields: ['address', 'source'],
    },
  },
  // --- saved views (3) ---
  { operationId: 'SavedViewsController_create_v1', precondition: null },
  {
    operationId: 'SavedViewsController_update_v1',
    precondition: {
      kind: 'single',
      tool: 'saved_views_get',
      params: { viewId: 'viewId' },
      stateFields: ['rowVersion', 'name'],
      rowVersionField: 'rowVersion',
      displayFields: ['kind'],
    },
    inject: BODY_ROW_VERSION,
  },
  {
    operationId: 'SavedViewsController_remove_v1',
    precondition: {
      kind: 'single',
      tool: 'saved_views_get',
      params: { viewId: 'viewId' },
      stateFields: ['rowVersion'],
      rowVersionField: 'rowVersion',
      displayFields: ['name', 'kind'],
    },
  },
];

const BY_OPERATION: ReadonlyMap<string, ConfirmationSpec> = new Map(
  CONFIRMATION_SPECS.map((spec) => [spec.operationId, spec]),
);

/** The spec of a write operation, or undefined (the executor then refuses: `denied_disabled`). */
export function confirmationSpecOf(operationId: string): ConfirmationSpec | undefined {
  return BY_OPERATION.get(operationId);
}

// ---------------------------------------------------------------------------------------------
// Argument helpers (pure; the api's executor uses them around its loopback calls)
// ---------------------------------------------------------------------------------------------

/** The argument at a dotted path (`policyId`, `body.messageId`). */
export function readArgPath(args: Readonly<Record<string, unknown>>, path: string): unknown {
  return valueAtPath(args, path);
}

/** The read tool's arguments of a single precondition (path parameters only). */
export function preconditionArgs(
  precondition: SinglePrecondition,
  args: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [param, path] of Object.entries(precondition.params))
    out[param] = readArgPath(args, path);
  return out;
}

export interface EachRead {
  id: string;
  tool: string;
  args: Record<string, string>;
}

/** The reads of an `each` precondition: the first `max` ids, the read tool per action. */
export function eachReads(
  precondition: EachPrecondition,
  args: Readonly<Record<string, unknown>>,
): { action: string | null; total: number; reads: EachRead[] } {
  const rawAction = readArgPath(args, precondition.actionFrom);
  const action = typeof rawAction === 'string' ? rawAction : null;
  const rawIds = readArgPath(args, precondition.idsFrom);
  const ids = Array.isArray(rawIds)
    ? rawIds.filter((id): id is string => typeof id === 'string')
    : [];
  const tool = (action && precondition.toolByAction?.[action]) || precondition.tool;
  const param = (action && precondition.paramByAction?.[action]) || precondition.param;
  return {
    action,
    total: ids.length,
    reads: ids.slice(0, precondition.max).map((id) => ({ id, tool, args: { [param]: id } })),
  };
}

function cloneArgs(args: Readonly<Record<string, unknown>>): Record<string, unknown> {
  return structuredClone(args);
}

function setCas(
  args: Readonly<Record<string, unknown>>,
  inject: CasInjection,
  value: number,
  onlyWhenMissing: boolean,
): Record<string, unknown> {
  const out = cloneArgs(args);
  if (inject.in === 'query') {
    if (!onlyWhenMissing || out[inject.field] === undefined) out[inject.field] = value;
    return out;
  }
  const current = out.body;
  const body: Record<string, unknown> =
    current !== null && typeof current === 'object' && !Array.isArray(current)
      ? (current as Record<string, unknown>)
      : {};
  if (!onlyWhenMissing || body[inject.field] === undefined) body[inject.field] = value;
  out.body = body;
  return out;
}

/**
 * Arguments for the first schema check (D1): the CAS field pre-filled with the placeholder (the
 * schema minimum) when the model omitted it, so a required `expectedRowVersion` never blocks the
 * proposal. A spec without injection returns the arguments unchanged (a copy).
 */
export function withCasPlaceholder(
  args: Readonly<Record<string, unknown>>,
  spec: ConfirmationSpec,
): Record<string, unknown> {
  return spec.inject ? setCas(args, spec.inject, spec.inject.min, true) : cloneArgs(args);
}

/** Arguments with the CAS field set to the precondition read's row version (overrides the model). */
export function withInjectedCas(
  args: Readonly<Record<string, unknown>>,
  spec: ConfirmationSpec,
  rowVersion: number,
): Record<string, unknown> {
  if (!spec.inject) return cloneArgs(args);
  if (!Number.isSafeInteger(rowVersion) || rowVersion < 0)
    throw new TypeError('withInjectedCas: the row version must be a non-negative integer');
  return setCas(args, spec.inject, rowVersion, false);
}

// ---------------------------------------------------------------------------------------------
// Snapshots of the precondition read
// ---------------------------------------------------------------------------------------------

export type SnapshotValue = string | number | boolean | null;
/** Picked fields of the precondition read by dotted path (strings sanitized, ≤ 300 chars). */
export type ConfirmationSnapshot = Record<string, SnapshotValue>;

export const SNAPSHOT_STRING_MAX_CHARS = 300;

function snapshotValue(value: unknown): SnapshotValue {
  if (value === undefined || value === null) return null;
  if (typeof value === 'string') return sanitizeText(value, SNAPSHOT_STRING_MAX_CHARS);
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean') return value;
  try {
    return sanitizeText(JSON.stringify(value), SNAPSHOT_STRING_MAX_CHARS);
  } catch {
    return null;
  }
}

/** The fields of a single precondition read kept with the confirmation (state + row version + display). */
export function buildSnapshot(
  body: unknown,
  precondition: SinglePrecondition,
): ConfirmationSnapshot {
  const paths = new Set<string>([
    ...precondition.stateFields,
    ...(precondition.rowVersionField ? [precondition.rowVersionField] : []),
    ...(precondition.displayFields ?? []),
  ]);
  const out: ConfirmationSnapshot = {};
  for (const path of paths) out[path] = snapshotValue(valueAtPath(body, path));
  return out;
}

/** The read's row version (the CAS counter), or null when the field is absent or not an integer. */
export function rowVersionOf(
  body: unknown,
  precondition: Pick<SinglePrecondition, 'rowVersionField'>,
): number | null {
  if (!precondition.rowVersionField) return null;
  const value = valueAtPath(body, precondition.rowVersionField);
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

/** One item of an `each` precondition (bulk preview). */
export interface EachSnapshotItem {
  id: string;
  /** The first present of the state fields that is a string (`state` of entries, `status` of approvals). */
  status: string | null;
  rowVersion: number | null;
  stateDigest: string;
}

export function buildEachItem(
  id: string,
  body: unknown,
  precondition: EachPrecondition,
): EachSnapshotItem {
  let status: string | null = null;
  for (const path of precondition.stateFields) {
    const value = valueAtPath(body, path);
    if (typeof value === 'string' && path !== precondition.rowVersionField) {
      status = sanitizeText(value, 64);
      break;
    }
  }
  return {
    id,
    status,
    rowVersion: rowVersionOf(body, precondition),
    stateDigest: stateDigest(body, precondition.stateFields),
  };
}
