import { sanitizeText, scrubValue } from '../results/sanitize';
import { stateDigest, valueAtPath } from './digest';
import type { RiskEscalation } from './escalation';
import type { ProposalGuard } from './guards';

/**
 * Confirmation specs (step AI-2 D4): for every enabled write, how the executor reads the target's
 * current state before proposing (the precondition read, through an enabled read tool and the
 * user's own token), which fields of that read bind the confirmation (state digest), which CAS
 * field it injects from the read, and whether a policy definition is validated first. The
 * registry check (`registryConsistencyIssues`) requires exactly one spec per enabled write.
 *
 * Argument paths address the write tool's input object: path and query parameters at the top
 * level (`policyId`), the JSON body under `body` (`body.messageId`).
 *
 * Step AI-3 (design 30 D3–D6) adds proposal guards (`guards`, `guards.ts`), conditional risk
 * escalation (`escalate`, `escalation.ts`) and selected-item preconditions (`select`).
 */

/**
 * The target is one item of a list read (step AI-3 D5): the item of the array at `array` (a
 * dotted path in the read body) whose `field` equals the write argument `arg` (string compare).
 */
export interface PreconditionSelect {
  array: string;
  field: string;
  arg: string;
  /**
   * `true`: a missing item fails the proposal like a `404` read of the target (`kind: 'response'`,
   * status 404, code `not_found`, "The target was not found"). `false`: a missing item is a target
   * without a stored value (a feature or limit at its plan value): the snapshot's fields are null
   * and the state digest is `stateDigest({}, stateFields)`; the confirm-time re-read must find it
   * absent again (or its digest differs and the confirm is refused as changed).
   */
  required: boolean;
}

/** A read of one target. `params` maps the read tool's path parameters to argument paths. */
export interface SinglePrecondition {
  kind: 'single';
  tool: string;
  params: Readonly<Record<string, string>>;
  /** The target is an item of a list read (D5); the field paths below are then item-relative. */
  select?: PreconditionSelect;
  /** Fields of the read whose change between proposal and confirm refuses the confirm. */
  stateFields: readonly string[];
  /** Field holding the CAS counter (injected when the spec has `inject`). */
  rowVersionField?: string;
  /**
   * Further fields the impact template shows (sanitized, ≤ 300 characters). A path with `[]`
   * projects an array (`roles[].key`: the key of every role, kept as a JSON list).
   */
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
  /** Proposal guards (step AI-3 D3), evaluated by `guardRefusal` at proposal and at confirm. */
  guards?: readonly ProposalGuard[];
  /** Conditional risk escalation (step AI-3 D4), evaluated by `effectiveRisk`. */
  escalate?: readonly RiskEscalation[];
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

// --- step AI-3 (design 30 D3–D6) ---

/** I12: no change of the caller's own account, roles, status, MFA or sessions through chat. */
const NOT_SELF: readonly ProposalGuard[] = [{ kind: 'not_self_user', arg: 'id' }];
/** A3-4: the assistant cannot turn itself on or off. */
const NOT_ASSISTANT_FEATURE: readonly ProposalGuard[] = [
  {
    kind: 'deny_values',
    arg: 'featureKey',
    values: ['ai_assistant'],
    message: 'assistant_feature',
  },
];
const ASSISTANT_CONFIGURE = ['assistant:configure'] as const;

const user = (
  stateFields: readonly string[],
  displayFields: readonly string[],
): SinglePrecondition => ({
  kind: 'single',
  tool: 'users_get',
  params: { id: 'id' },
  stateFields,
  displayFields,
});
const USER_DISPLAY = ['email', 'displayName'] as const;
const USER_ROLES_DISPLAY = ['email', 'displayName', 'roles[].key'] as const;

const role = (
  stateFields: readonly string[],
  displayFields: readonly string[],
): SinglePrecondition => ({
  kind: 'single',
  tool: 'roles_get',
  params: { key: 'key' },
  stateFields,
  displayFields,
});

const department = (stateFields: readonly string[], cas: boolean): SinglePrecondition => ({
  kind: 'single',
  tool: 'departments_get',
  params: { departmentId: 'departmentId' },
  stateFields,
  ...(cas ? { rowVersionField: 'rowVersion' } : {}),
  displayFields: ['name', 'memberCount'],
});

const domain = (
  tool: string,
  stateFields: readonly string[],
  displayFields: readonly string[],
): SinglePrecondition => ({
  kind: 'single',
  tool,
  params: { id: 'id' },
  stateFields,
  displayFields,
});
const DESTINATION_DISPLAY = [
  'provider',
  'servers[].host',
  'servers[].port',
  'servers[].priority',
] as const;

const feature = (): SinglePrecondition => ({
  kind: 'single',
  tool: 'organization_configuration_list_features',
  params: { id: 'id' },
  select: { array: 'data', field: 'key', arg: 'featureKey', required: false },
  stateFields: ['enabled', 'config', 'source'],
});
const limit = (): SinglePrecondition => ({
  kind: 'single',
  tool: 'organization_configuration_list_limits',
  params: { id: 'id' },
  select: { array: 'data', field: 'key', arg: 'limitKey', required: false },
  stateFields: ['value', 'source'],
});
const scanEngine = (): SinglePrecondition => ({
  kind: 'single',
  tool: 'scan_settings_list',
  params: {},
  select: { array: 'data', field: 'engine', arg: 'engine', required: true },
  stateFields: ['version', 'override'],
  rowVersionField: 'version',
  displayFields: ['required', 'overrideApplied'],
});
const connector = (stateFields: readonly string[]): SinglePrecondition => ({
  kind: 'single',
  tool: 'smtp_connectors_get',
  params: { id: 'id' },
  stateFields,
  displayFields: ['authType', 'networks[].cidr'],
});
const webhook = (stateFields: readonly string[], cas = false): SinglePrecondition => ({
  kind: 'single',
  tool: 'webhooks_get',
  params: { webhookId: 'webhookId' },
  stateFields,
  ...(cas ? { rowVersionField: 'rowVersion' } : {}),
  displayFields: ['name', 'url', 'status'],
});
const NOTIFICATION_SETTINGS_DISPLAY = [
  'settings.alerts.threatDetected.enabled',
  'settings.alerts.threatDetected.minSeverity',
  'settings.alerts.threatDetected.throttleMinutes',
  'settings.alerts.domainDnsFailed.enabled',
  'settings.alerts.domainDnsFailed.throttleMinutes',
  'settings.alerts.webhookDisabled.enabled',
  'settings.alerts.webhookDisabled.throttleMinutes',
  'settings.alerts.includeOrganizationContact',
] as const;

/** Escalation warnings (design 30 D4; fixed English). */
export const ESCALATION_WARNINGS = {
  userEmail:
    'Changing the email address sends sign-in, invitation and password-reset mail to the new address.',
  smtpNetworks: 'Changes which networks may relay mail through the gateway.',
  smtpTls: 'Allows sessions without TLS on this connector.',
  webhookUrl: "Sends this webhook's event data to a new address.",
  initialAdmin: 'Invites an administrator with full access to the new organization.',
  planCode: "Changes the plan, and with it the organization's features and limits.",
  mfaOff: 'Users of the organization will no longer have to use MFA.',
  notificationEmail: 'Organization notifications go to a new address.',
} as const;

/**
 * The 78 enabled writes: the 31 of step AI-2 (design 29 D4) and the 47 of step AI-3 (design 30
 * D6). Field names checked against docs/api/openapi.json (request and response schemas; the
 * package tests resolve every state, row-version, display and select path).
 */
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

  // ===== step AI-3 (47) =====
  // --- users (9) ---
  { operationId: 'UsersController_invite_v1', precondition: null },
  {
    operationId: 'UsersController_update_v1',
    precondition: user(['email', 'displayName', 'status'], [...USER_DISPLAY, 'roles[].key']),
    guards: NOT_SELF,
    escalate: [
      { when: { present: 'body.email' }, risk: 'high', warning: ESCALATION_WARNINGS.userEmail },
    ],
  },
  {
    operationId: 'UsersController_changeStatus_v1',
    precondition: user(['status', 'lockedUntil'], USER_ROLES_DISPLAY),
    guards: NOT_SELF,
  },
  {
    operationId: 'UsersController_replaceRoles_v1',
    precondition: user(['roles', 'status'], USER_ROLES_DISPLAY),
    guards: NOT_SELF,
  },
  {
    operationId: 'UsersController_resetMfa_v1',
    precondition: user(['mfaEnabled', 'status'], USER_DISPLAY),
    guards: NOT_SELF,
  },
  {
    operationId: 'UsersController_remove_v1',
    precondition: user(['status', 'roles'], USER_ROLES_DISPLAY),
    guards: NOT_SELF,
  },
  {
    operationId: 'UsersController_resendInvitation_v1',
    precondition: user(['status'], USER_DISPLAY),
    guards: NOT_SELF,
  },
  {
    operationId: 'UsersController_revokeAllSessions_v1',
    precondition: user(['status'], USER_DISPLAY),
    guards: NOT_SELF,
  },
  {
    operationId: 'UsersController_revokeSession_v1',
    precondition: {
      kind: 'single',
      tool: 'users_list_sessions',
      params: { id: 'id' },
      select: { array: 'data', field: 'id', arg: 'sessionId', required: true },
      stateFields: ['authenticatedAt', 'expiresAt'],
      displayFields: ['ipAddress', 'userAgent', 'lastUsedAt', 'mfaAuthenticated'],
    },
    guards: NOT_SELF,
  },
  // --- roles (3) ---
  {
    operationId: 'RolesController_create_v1',
    precondition: null,
    guards: [
      {
        kind: 'deny_permission_change',
        arg: 'body.permissions',
        permissions: ASSISTANT_CONFIGURE,
        message: 'assistant_configure',
      },
    ],
  },
  {
    operationId: 'RolesController_update_v1',
    precondition: role(['name', 'description', 'permissions', 'system'], ['name', 'system']),
    guards: [
      {
        kind: 'deny_permission_change',
        arg: 'body.permissions',
        beforeField: 'permissions',
        permissions: ASSISTANT_CONFIGURE,
        message: 'assistant_configure',
      },
    ],
  },
  {
    operationId: 'RolesController_remove_v1',
    precondition: role(['permissions', 'system'], ['name', 'system']),
  },
  // --- departments (5) ---
  { operationId: 'DepartmentsController_create_v1', precondition: null },
  {
    operationId: 'DepartmentsController_update_v1',
    precondition: department(['rowVersion', 'name', 'description'], true),
    inject: BODY_ROW_VERSION,
  },
  {
    operationId: 'DepartmentsController_remove_v1',
    precondition: department(['rowVersion'], true),
    inject: QUERY_ROW_VERSION,
  },
  {
    operationId: 'DepartmentsController_addMember_v1',
    precondition: department(['rowVersion'], false),
  },
  {
    operationId: 'DepartmentsController_removeMember_v1',
    precondition: department(['rowVersion'], false),
  },
  // --- API keys (1) ---
  {
    operationId: 'ApiKeysController_revoke_v1',
    precondition: {
      kind: 'single',
      tool: 'api_keys_get',
      params: { id: 'id' },
      stateFields: ['revokedAt', 'expiresAt'],
      displayFields: ['name', 'prefix', 'scopes', 'lastUsedAt', 'createdBy.displayName'],
    },
  },
  // --- domains (10) ---
  { operationId: 'DomainsController_create_v1', precondition: null },
  {
    operationId: 'DomainsController_remove_v1',
    precondition: domain(
      'domains_get',
      ['status', 'inboundEnabled', 'outboundEnabled'],
      ['name', 'unicodeName'],
    ),
  },
  {
    operationId: 'DomainsController_changeStatus_v1',
    precondition: domain('domains_get', ['status'], ['name', 'unicodeName', 'statusReason']),
  },
  {
    operationId: 'DomainDnsController_verify_v1',
    precondition: domain(
      'domain_dns_status',
      ['status'],
      ['name', 'readyForActivation', 'mailFlowReady'],
    ),
  },
  {
    operationId: 'DomainDnsController_rotate_v1',
    precondition: domain(
      'domains_get',
      ['status', 'dkimKeys'],
      ['name', 'dkimKeys[].selector', 'dkimKeys[].status'],
    ),
  },
  {
    operationId: 'DomainDestinationsController_replace_v1',
    precondition: domain('domain_destinations_get', ['provider', 'servers'], DESTINATION_DISPLAY),
  },
  {
    operationId: 'DomainDestinationsController_remove_v1',
    precondition: domain('domain_destinations_get', ['provider', 'servers'], DESTINATION_DISPLAY),
  },
  {
    operationId: 'DomainRecipientsController_set_v1',
    precondition: domain('domain_recipients_get', ['mode', 'enforcement'], ['addressCount']),
  },
  {
    operationId: 'DomainRecipientsController_add_v1',
    precondition: domain('domain_recipients_get', ['mode'], ['enforcement', 'addressCount']),
  },
  {
    operationId: 'DomainRecipientsController_remove_v1',
    precondition: domain('domain_recipients_get', ['mode'], ['enforcement', 'addressCount']),
  },
  // --- notifications (2) ---
  {
    operationId: 'NotificationsController_putPreferences_v1',
    precondition: {
      kind: 'single',
      tool: 'notifications_preferences',
      params: {},
      stateFields: ['optOut', 'quarantineDigestOptOut'],
      displayFields: ['quarantineDigestOptOutAllowed'],
    },
  },
  {
    operationId: 'NotificationsController_putSettings_v1',
    precondition: {
      kind: 'single',
      tool: 'notifications_settings',
      params: {},
      stateFields: ['rowVersion'],
      rowVersionField: 'rowVersion',
      displayFields: NOTIFICATION_SETTINGS_DISPLAY,
    },
    inject: { in: 'body', field: 'expectedRowVersion', min: 0 },
  },
  // --- organizations (8) ---
  {
    operationId: 'OrganizationsController_create_v1',
    precondition: null,
    escalate: [
      {
        when: { present: 'body.initialAdmin' },
        risk: 'high',
        warning: ESCALATION_WARNINGS.initialAdmin,
      },
    ],
  },
  {
    operationId: 'OrganizationsController_update_v1',
    precondition: {
      kind: 'single',
      tool: 'organizations_get',
      params: { id: 'id' },
      stateFields: ['name', 'plan.code', 'status'],
      displayFields: ['slug', 'kind'],
    },
    escalate: [
      { when: { present: 'body.planCode' }, risk: 'high', warning: ESCALATION_WARNINGS.planCode },
    ],
  },
  {
    operationId: 'OrganizationDeletionController_cancel_v1',
    precondition: {
      kind: 'single',
      tool: 'organization_deletion_get',
      params: { id: 'id' },
      stateFields: ['state', 'cancellable', 'requestedAt'],
      displayFields: ['status', 'purgeAfter'],
    },
  },
  {
    operationId: 'OrganizationConfigurationController_overrideFeature_v1',
    precondition: feature(),
    guards: NOT_ASSISTANT_FEATURE,
  },
  {
    operationId: 'OrganizationConfigurationController_resetFeature_v1',
    precondition: feature(),
    guards: NOT_ASSISTANT_FEATURE,
  },
  { operationId: 'OrganizationConfigurationController_overrideLimit_v1', precondition: limit() },
  { operationId: 'OrganizationConfigurationController_resetLimit_v1', precondition: limit() },
  {
    operationId: 'OrganizationConfigurationController_updateSettings_v1',
    precondition: {
      kind: 'single',
      tool: 'organization_configuration_get_settings',
      params: { id: 'id' },
      stateFields: [
        'timezone',
        'locale',
        'quarantineRetentionDays',
        'digestEnabled',
        'digestSchedule',
        'notificationEmail',
        'mfaRequired',
        'preferences',
        'updatedAt',
      ],
    },
    escalate: [
      {
        when: { equals: { path: 'body.mfaRequired', value: false } },
        risk: 'high',
        warning: ESCALATION_WARNINGS.mfaOff,
      },
      {
        when: { present: 'body.notificationEmail' },
        risk: 'high',
        warning: ESCALATION_WARNINGS.notificationEmail,
      },
    ],
  },
  // --- scan settings (2) ---
  {
    operationId: 'ScanSettingsController_replace_v1',
    precondition: scanEngine(),
    inject: { in: 'body', field: 'expectedVersion', min: 0 },
  },
  {
    operationId: 'ScanSettingsController_reset_v1',
    precondition: scanEngine(),
    inject: { in: 'query', field: 'expectedVersion', min: 0 },
  },
  // --- SMTP connectors (2) ---
  {
    operationId: 'SmtpConnectorsController_update_v1',
    precondition: connector(['name', 'status', 'networks', 'requireTls']),
    escalate: [
      {
        when: { present: 'body.networks' },
        risk: 'high',
        warning: ESCALATION_WARNINGS.smtpNetworks,
      },
      {
        when: { equals: { path: 'body.requireTls', value: false } },
        risk: 'high',
        warning: ESCALATION_WARNINGS.smtpTls,
      },
    ],
  },
  {
    operationId: 'SmtpConnectorsController_remove_v1',
    precondition: connector(['name', 'status']),
  },
  // --- webhooks (5) ---
  {
    operationId: 'WebhooksController_update_v1',
    precondition: webhook(['rowVersion'], true),
    inject: BODY_ROW_VERSION,
    escalate: [
      { when: { present: 'body.url' }, risk: 'high', warning: ESCALATION_WARNINGS.webhookUrl },
    ],
  },
  {
    operationId: 'WebhooksController_delete_v1',
    precondition: webhook(['rowVersion', 'status']),
  },
  { operationId: 'WebhooksController_test_v1', precondition: webhook(['status']) },
  {
    operationId: 'WebhookDeliveriesController_replay_v1',
    precondition: {
      kind: 'single',
      tool: 'webhook_deliveries_get',
      params: { webhookId: 'webhookId', deliveryId: 'deliveryId' },
      stateFields: ['status', 'attemptCount'],
      displayFields: ['eventType', 'lastResponseCode'],
    },
  },
  {
    operationId: 'WebhookDeliveriesController_createReplay_v1',
    precondition: webhook(['status']),
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
/**
 * A list of scalars (permissions, scopes, role keys, server hosts) is kept as a JSON array of up
 * to this many characters, so impact templates can show before → after diffs (step AI-3 D7); a
 * longer list is cut and no longer parses (`snapshotList` then returns null).
 */
export const SNAPSHOT_LIST_MAX_CHARS = 4096;

const isScalar = (value: unknown): value is string | number | boolean | null =>
  value === null || ['string', 'number', 'boolean'].includes(typeof value);

function snapshotValue(value: unknown): SnapshotValue {
  if (value === undefined || value === null) return null;
  if (typeof value === 'string') return sanitizeText(value, SNAPSHOT_STRING_MAX_CHARS);
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean') return value;
  try {
    if (Array.isArray(value) && value.every(isScalar)) {
      const list = JSON.stringify(
        value.map((item) =>
          typeof item === 'string' ? sanitizeText(item, SNAPSHOT_STRING_MAX_CHARS) : item,
        ),
      );
      return list.length <= SNAPSHOT_LIST_MAX_CHARS
        ? list
        : sanitizeText(list, SNAPSHOT_STRING_MAX_CHARS);
    }
    // Objects: credential-pattern keys are dropped before the JSON text is kept (step AI-3 D7).
    return sanitizeText(JSON.stringify(scrubValue(value)), SNAPSHOT_STRING_MAX_CHARS);
  } catch {
    return null;
  }
}

/**
 * The value at a snapshot path: a dotted path (`valueAtPath`), or a projection over an array
 * (`servers[].host` → the `host` of every item; non-record items and missing fields are null).
 */
export function snapshotPathValue(body: unknown, path: string): unknown {
  const index = path.indexOf('[]');
  if (index < 0) return valueAtPath(body, path);
  const array: unknown = valueAtPath(body, path.slice(0, index));
  if (!Array.isArray(array)) return undefined;
  const list: unknown[] = array;
  const rest = path.slice(index + 2).replace(/^\./, '');
  return list.map((item) => {
    const value = rest ? snapshotPathValue(item, rest) : item;
    return value === undefined ? null : value;
  });
}

/** A list kept in a snapshot (`SNAPSHOT_LIST_MAX_CHARS`), or null (absent, not a list, cut). */
export function snapshotList(
  value: SnapshotValue | undefined,
): Array<string | number | boolean | null> | null {
  if (typeof value !== 'string' || !value.startsWith('[')) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) && parsed.every(isScalar) ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * The fields of a single precondition read kept with the confirmation (state + row version +
 * display). With `select` (D5) pass the selected item (`targetOf`), not the list body.
 */
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
  for (const path of paths) out[path] = snapshotValue(snapshotPathValue(body, path));
  return out;
}

// ---------------------------------------------------------------------------------------------
// Selected-item preconditions (step AI-3 D5)
// ---------------------------------------------------------------------------------------------

export interface SelectedTarget {
  /** True without `select` (the body is the target) and when the item was found. */
  found: boolean;
  /** The selected item, the body (no `select`), or null (not found). */
  item: unknown;
}

const comparable = (value: unknown): string | null =>
  typeof value === 'string' ? value : typeof value === 'number' ? String(value) : null;

/**
 * The target of a single precondition read: without `select` the read body itself; with
 * `select` the first item of `select.array` whose `select.field` equals the argument at
 * `select.arg` (string compare; non-string, non-number values never match).
 *
 * The api treats a not-found item of a `required` select like a `404` read of the target (the
 * proposal fails with `kind: 'response'`, status 404, code `not_found`, "The target was not
 * found"); a not-found item of an optional select is the empty target (`targetOf` → `{}`).
 */
export function selectTarget(
  body: unknown,
  precondition: SinglePrecondition,
  args: Readonly<Record<string, unknown>>,
): SelectedTarget {
  const select = precondition.select;
  if (!select) return { found: true, item: body };
  const wanted = comparable(readArgPath(args, select.arg));
  const value: unknown = valueAtPath(body, select.array);
  if (wanted === null || !Array.isArray(value)) return { found: false, item: null };
  const list: unknown[] = value;
  const item = list.find(
    (candidate) =>
      candidate !== null &&
      typeof candidate === 'object' &&
      !Array.isArray(candidate) &&
      comparable((candidate as Record<string, unknown>)[select.field]) === wanted,
  );
  return item === undefined ? { found: false, item: null } : { found: true, item };
}

/**
 * The value the state digest, row version, snapshot and after-read guards apply to: the read
 * body, the selected item, or `{}` for a not-found item (an optional select; for a required one
 * the caller has already failed the proposal). `stateDigest(targetOf(...), stateFields)`,
 * `rowVersionOf(targetOf(...), precondition)` and `buildSnapshot(targetOf(...), precondition)`
 * are then the same calls as for an AI-2 spec (without `select`, `targetOf` returns the body).
 */
export function targetOf(
  body: unknown,
  precondition: SinglePrecondition,
  args: Readonly<Record<string, unknown>>,
): unknown {
  const selected = selectTarget(body, precondition, args);
  return selected.found ? selected.item : {};
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
