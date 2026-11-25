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
 *
 * Step AI-4 (design 32 D3–D5) adds the security-operations specs, the ATO four-eyes guards and
 * the CAS field names `version`, `rowVersion` and `expectedProfileVersion`.
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
  /** Step AI-4 adds `version` (BEC, DLP), `rowVersion` (IdP integrations), `expectedProfileVersion`. */
  field:
    'expectedRowVersion' | 'expectedVersion' | 'version' | 'rowVersion' | 'expectedProfileVersion';
  /** The schema minimum; also the placeholder used before the read (D1). */
  min: 0 | 1;
}

/**
 * The allow-listed side-effect-free POST reads whose `impactToken` the proposer may inject into
 * a write (step AI-5 D5, ADR-0093 amendment AI-5 (w)). The api's precondition `get()` keeps
 * refusing every non-GET tool; only its separate preview path accepts these.
 */
export const IMPACT_PREVIEW_TOOLS = ['provider_mail_flow_preview'] as const;
export type ImpactPreviewTool = (typeof IMPACT_PREVIEW_TOOLS)[number];

/** The key under which the api merges the preview response into the precondition target. */
export const IMPACT_PREVIEW_KEY = 'preview';

/**
 * The value `body.impactToken` holds before the preview ran (the first schema check of the
 * executor; valid against the write's schema: a 1–128 character string). Never sent to a route:
 * the proposer always replaces it with the preview's token before the final schema check.
 */
export const IMPACT_TOKEN_PLACEHOLDER = 'pending-preview';

/** Longest impact token the writes accept (`impactToken` `maxLength`). */
export const IMPACT_TOKEN_MAX_CHARS = 128;

/**
 * A server-filled impact token (step AI-5 D5): after the single precondition read the proposer
 * sends the preview through the loopback (`POST`, the caller's token), merges its response under
 * `preview` into the precondition target (state and display fields address it as
 * `preview.<path>`), and sets `body.impactToken` from the preview and `body.confirm = true`,
 * always replacing any model value. The confirm route re-runs the read and the preview and
 * compares the state digest (the preview's change set is part of the state fields).
 */
export interface ImpactTokenInjection {
  /** The allow-listed side-effect-free POST read (`IMPACT_PREVIEW_TOOLS`). */
  previewTool: ImpactPreviewTool;
  /** Path parameters of the preview from the write's arguments (`{ id: 'id' }`). */
  params: Readonly<Record<string, string>>;
  /** The preview body's `change`: the write's `body.change`, or a constant change. */
  change: { from: 'body.change' } | { constant: Readonly<Record<string, unknown>> };
}

export interface ConfirmationSpec {
  operationId: string;
  precondition: ConfirmationPrecondition | null;
  inject?: CasInjection;
  /** A server-filled impact token (step AI-5 D5); requires a `single` precondition. */
  impactToken?: ImpactTokenInjection;
  validateDefinition?: 'body.definition';
  /** Proposal guards (step AI-3 D3), evaluated by `guardRefusal` at proposal and at confirm. */
  guards?: readonly ProposalGuard[];
  /** Conditional risk escalation (step AI-3 D4), evaluated by `effectiveRisk`. */
  escalate?: readonly RiskEscalation[];
  /**
   * A native write (step AI-R D5): the api prepares the proposal and re-reads the state with its
   * own native service (`NativeToolsService`) instead of a precondition read; `precondition` is
   * null and the state digest is `reportStateDigest(...)`.
   */
  native?: 'report_send_email';
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

// --- step AI-4 (design 32 D3–D5) ---

/**
 * I18: the requester of an ATO response, or the creator of the API key that requested it, never
 * decides it; deciding needs MFA (`canDecide` of the read, computed for the proposing user).
 */
const ATO_FOUR_EYES: readonly ProposalGuard[] = [
  {
    kind: 'not_self_field',
    field: 'requestedBy.id',
    when: { field: 'requestedBy.type', equals: 'user' },
    message: 'ato_four_eyes',
  },
  {
    kind: 'require_read_value',
    field: 'canDecide',
    equals: true,
    when: { field: 'status', equals: 'pending_approval' },
    message: 'ato_four_eyes',
  },
];

const ATO_ACCOUNT_DISPLAY = [
  'address',
  'displayName',
  'kind',
  'riskLevel',
  'riskScore',
  'protection.protected',
  'protection.reason',
] as const;
const ATO_OVERRIDE_DISPLAY = [
  'address',
  'riskScore',
  'riskLevel',
  'overrideDetail.verdict',
  'overrideDetail.expiresAt',
] as const;

/**
 * An ATO account read. Its `rowVersion` moves with every rescoring, so it is a state field only
 * where the write itself CAS-checks it (`ato_accounts_update`, R4).
 */
const atoAccount = (
  stateFields: readonly string[],
  displayFields: readonly string[],
  accountArg = 'accountId',
  cas = false,
): SinglePrecondition => ({
  kind: 'single',
  tool: 'ato_accounts_get',
  params: { accountId: accountArg },
  stateFields,
  ...(cas ? { rowVersionField: 'rowVersion' } : {}),
  displayFields,
});

const ATO_RESPONSE_DISPLAY = [
  'actionType',
  'provider',
  'impact',
  'account.id',
  'account.kind',
  'target.scope',
  'params.durationMinutes',
  'params.mode',
  'requestedBy.type',
  'requestReason',
  'approvalExpiresAt',
] as const;
const atoResponse = (
  stateFields: readonly string[],
  displayFields: readonly string[] = ATO_RESPONSE_DISPLAY,
): SinglePrecondition => ({
  kind: 'single',
  tool: 'ato_responses_get',
  params: { responseId: 'responseId' },
  stateFields,
  displayFields,
});

const atoProvider = (stateFields: readonly string[], cas = false): SinglePrecondition => ({
  kind: 'single',
  tool: 'ato_providers_get',
  params: { integrationId: 'integrationId' },
  stateFields,
  ...(cas ? { rowVersionField: 'rowVersion' } : {}),
  displayFields: cas
    ? ['displayName', 'provider', 'status', 'settingsVersion']
    : ['displayName', 'provider', 'status', 'health.status'],
});

/** A BEC or DLP record read by `{id}` with its `version` CAS counter. */
const versioned = (tool: string, displayFields: readonly string[]): SinglePrecondition => ({
  kind: 'single',
  tool,
  params: { id: 'id' },
  stateFields: ['version'],
  rowVersionField: 'version',
  displayFields,
});
const BODY_VERSION: CasInjection = { in: 'body', field: 'version', min: 1 };
const QUERY_VERSION: CasInjection = { in: 'query', field: 'version', min: 1 };

const EXECUTIVE_DISPLAY = ['displayName', 'title', 'enabled', 'knownAddresses'] as const;
const TRUSTED_SENDER_DISPLAY = ['kind', 'value', 'reason', 'expiresAt'] as const;
const VENDOR_DISPLAY = [
  'name',
  'enabled',
  'paymentChangeSensitive',
  'domains',
  'knownSenders',
] as const;
const DICTIONARY_DISPLAY = ['name', 'category', 'severity', 'enabled', 'termCount'] as const;
const EXCEPTION_DISPLAY = ['scope', 'value', 'policyId', 'reason', 'expiresAt', 'enabled'] as const;
/** Never the pattern text (D6: it is not shown in impact or warnings). */
const PATTERN_DISPLAY = ['name', 'severity', 'validator', 'enabled'] as const;
const DLP_POLICY_DISPLAY = ['name', 'enabled', 'mode', 'priority', 'ruleCount'] as const;

const dlpRule = (): SinglePrecondition => ({
  kind: 'single',
  tool: 'dlp_policies_get',
  params: { id: 'id' },
  select: { array: 'rules', field: 'id', arg: 'ruleId', required: true },
  stateFields: ['version'],
  rowVersionField: 'version',
  displayFields: ['name', 'enabled', 'priority', 'action'],
});

const dlpCompliance = (): SinglePrecondition => ({
  kind: 'single',
  tool: 'dlp_compliance_get',
  params: {},
  stateFields: ['version', 'aadhaar.enabled'],
  rowVersionField: 'version',
  displayFields: [
    'aadhaar.enabled',
    'aadhaar.active',
    'aadhaar.basis',
    'aadhaar.reference',
    'aadhaar.attested',
    'aadhaar.reviewDueAt',
  ],
});

const INCIDENT_DISPLAY = [
  'category',
  'status',
  'severity',
  'subject.display',
  'assigneeId',
] as const;
const incident = (
  stateFields: readonly string[],
  cas = false,
  displayFields: readonly string[] = INCIDENT_DISPLAY,
): SinglePrecondition => ({
  kind: 'single',
  tool: 'incidents_get',
  params: { incidentId: 'incidentId' },
  stateFields,
  ...(cas ? { rowVersionField: 'rowVersion' } : {}),
  displayFields,
});

const riskVersion = (): SinglePrecondition => ({
  kind: 'single',
  tool: 'risk_profiles_get_version',
  params: { versionId: 'versionId' },
  stateFields: ['rowVersion', 'status'],
  rowVersionField: 'rowVersion',
  displayFields: ['versionNo', 'status', 'active', 'changeNote'],
});
const riskProfile = (): SinglePrecondition => ({
  kind: 'single',
  tool: 'risk_profiles_profile',
  params: {},
  stateFields: ['profileVersion'],
  rowVersionField: 'profileVersion',
  displayFields: ['profileVersion', 'active.source', 'active.versionId', 'active.versionNo'],
});
const BODY_PROFILE_VERSION: CasInjection = {
  in: 'body',
  field: 'expectedProfileVersion',
  min: 0,
};

/** Escalation warnings of step AI-4 (design 32 D4; fixed English). */
export const AI4_ESCALATION_WARNINGS = {
  atoProtected: 'Automated responses will never act on this account, even when it is compromised.',
  atoBenign:
    "The account's risk is held below the medium band and automation never acts on it until a strong new signal arrives.",
  idpSettings:
    'Sets which data the gateway reads and which response actions it may take in the identity provider.',
  incidentResolved: 'The incident is closed and cannot be re-opened.',
  incidentFalsePositive:
    'Marks the incident a false positive: its signals are dismissed and the account is rescored.',
  incidentFeedback: 'Feedback can add trusted contexts for the account and dismiss its signals.',
  becSuppress: 'Suppresses these BEC findings for the sender scope for the given days.',
  trustedSenderExpiry: 'Changes how long this sender stays trusted (null: no expiry).',
  executiveDisabled: 'Impersonation of this executive is no longer detected.',
  executiveAddresses: "Mail from these addresses is treated as the executive's own.",
  vendorDisabled: 'Impersonation of this vendor is no longer detected.',
  vendorSenders: "Mail from these senders or domains is treated as the vendor's own.",
  vendorPaymentChange: 'Payment-change requests from this vendor are no longer flagged.',
  dlpPolicyDisabled: 'This DLP policy stops evaluating mail.',
  dlpPolicyMonitor: 'Matches are only recorded; mail is no longer blocked or held.',
  dlpAllowRule: 'Matching mail is allowed without further DLP action.',
  dlpRuleDisabled: 'This rule stops matching.',
  dlpDetectorDisabled: 'This detector stops matching in every policy that uses it.',
  dlpPatternChanged: 'Changes what the detector matches.',
  dlpExceptionWidened: 'Widens or extends who is exempt from DLP.',
} as const;
const W = AI4_ESCALATION_WARNINGS;
const high = (when: RiskEscalation['when'], warning: string): RiskEscalation => ({
  when,
  risk: 'high',
  warning,
});
const disabled = (path = 'body.enabled') => ({ equals: { path, value: false } });

// --- step AI-5 (design 33 D3–D6) ---

/** Escalation warnings of step AI-5 (design 33 D3, I22; fixed English). */
export const AI5_ESCALATION_WARNINGS = {
  retentionShortened:
    'Shortens retention: mail captured from now on that this policy matches is kept for fewer days (records already archived keep their stored dates).',
  expiryDelete: 'Expired records are deleted without a review step.',
  retentionScope:
    'Changes which new captures this policy applies to; mail that no longer matches falls to another policy, possibly with a shorter retention.',
  archiveOff: 'Archiving stops: mail received from now on is not captured.',
  archiveSettings:
    'Replaces the whole archive settings document (directions, included outcomes, scope, policy archiving, access, intake scanning); keys you leave out return to their defaults.',
  archiveImmutability:
    'Changes the S3 Object Lock mode of new captures; compliance mode can never be weakened afterwards.',
  archiveDefaultPolicy: 'Changes the retention of every new capture that no other policy matches.',
  journalingOff: 'Journaling stops: mail received from now on is not captured.',
  journalingSettings:
    'Replaces the given journaling sections (directions, included outcomes, scope, policy archiving, intake scanning); keys left out inside a given section return to their defaults.',
  intakePaused:
    'Journal intake stops: senders get a temporary failure and retry; nothing is captured from this source while it is paused.',
  intakeNetworks: 'Changes which networks may deliver journal mail to this source.',
  intakeTls: 'Journal mail may then arrive without TLS.',
  intakeCertificates: 'Changes which client certificates this source accepts.',
  intakeSize:
    'Lowers the largest journal message this source accepts: larger messages are refused permanently and are not captured.',
  intakeSilenceOff:
    'Turns the silence alert off: a source that stops delivering journal mail is no longer reported.',
  caseCustodians:
    'Replaces the case custodians; later searches and holds that use the case custodians change (existing holds keep theirs).',
  exportMalicious: 'The export includes messages flagged as malicious.',
} as const;
const W5 = AI5_ESCALATION_WARNINGS;

/** The PUT defaults of a retention policy (`onExpiry`, `priority`, `criteria`; design 23). */
const RETENTION_DEFAULTS = { onExpiry: 'delete', priority: 100, criteria: {} } as const;

const retentionPolicy = (
  stateFields: readonly string[],
  displayFields: readonly string[],
  cas: boolean,
): SinglePrecondition => ({
  kind: 'single',
  tool: 'archive_retention_get',
  params: { policyId: 'policyId' },
  stateFields,
  ...(cas ? { rowVersionField: 'rowVersion' } : {}),
  displayFields,
});

const SETTINGS_SECTIONS_DISPLAY = [
  'settings.directions.inbound',
  'settings.directions.outbound',
  'settings.directions.internal',
  'settings.include.rejected',
  'settings.include.quarantined',
  'settings.include.failed',
  'settings.scope.mode',
  'settings.policyArchive.enabled',
  'settings.intake.scanEnabled',
] as const;
const BODY_ROW_VERSION_0: CasInjection = { in: 'body', field: 'expectedRowVersion', min: 0 };

/** A journal intake source read: never `reveal` (D7; the tool has no such input any more). */
const intakeSource = (
  stateFields: readonly string[],
  displayFields: readonly string[],
  cas = false,
): SinglePrecondition => ({
  kind: 'single',
  tool: 'intake_sources_get',
  params: { sourceId: 'sourceId' },
  stateFields,
  ...(cas ? { rowVersionField: 'rowVersion' } : {}),
  displayFields,
});
const INTAKE_DISPLAY = ['displayName', 'kind', 'status'] as const;

const ediscoveryCase = (
  stateFields: readonly string[],
  displayFields: readonly string[],
  cas = false,
): SinglePrecondition => ({
  kind: 'single',
  tool: 'ediscovery_cases_get',
  params: { caseId: 'caseId' },
  stateFields,
  ...(cas ? { rowVersionField: 'rowVersion' } : {}),
  displayFields,
});
const SEARCH_DISPLAY = ['status', 'hitCount', 'truncated', 'indexComplete'] as const;

const PROVIDER_DISPLAY = ['displayName', 'provider', 'status'] as const;
/** A provider connection read. Health columns move without `rowVersion` (never state fields). */
const providerConnection = (
  stateFields: readonly string[],
  displayFields: readonly string[] = PROVIDER_DISPLAY,
  cas = false,
): SinglePrecondition => ({
  kind: 'single',
  tool: 'provider_connections_get',
  params: { id: 'id' },
  stateFields,
  ...(cas ? { rowVersionField: 'rowVersion' } : {}),
  displayFields,
});
const providerGrant = (): SinglePrecondition => ({
  kind: 'single',
  tool: 'provider_connections_get',
  params: { id: 'id' },
  select: { array: 'grants', field: 'profile', arg: 'profile', required: true },
  stateFields: ['status'],
  displayFields: ['profile', 'status', 'authMethod'],
});

/**
 * The preview's change set and warning codes (`POST …/mail-flow/preview`, merged under
 * `preview`): the whole change set and the warnings bind the confirmation (state digest); the
 * card shows its parts. Never `preview.impactToken` (a credential-pattern key).
 */
export const MAIL_FLOW_PREVIEW_STATE = ['preview.changeSet', 'preview.warnings'] as const;
export const MAIL_FLOW_PREVIEW_DISPLAY = [
  'preview.changeSet.kind',
  'preview.changeSet.domains[].name',
  'preview.changeSet.domains[].changed',
  'preview.changeSet.domains[].current.provider',
  'preview.changeSet.domains[].proposed.provider',
  'preview.changeSet.domains[].current.servers',
  'preview.changeSet.domains[].proposed.servers',
  'preview.changeSet.connector.action',
  'preview.changeSet.connection[].field',
  'preview.changeSet.connection[].from',
  'preview.changeSet.connection[].to',
  'preview.changeSet.grantsRevoked',
  'preview.warnings',
] as const;
const mailFlow = (): SinglePrecondition =>
  providerConnection(
    ['rowVersion', 'status', ...MAIL_FLOW_PREVIEW_STATE],
    [...PROVIDER_DISPLAY, 'outboundMode', 'internalRouting', ...MAIL_FLOW_PREVIEW_DISPLAY],
  );

/**
 * The 168 enabled writes: the 31 of step AI-2 (design 29 D4), the 47 of step AI-3 (design 30
 * D6), the native report_send_email of step AI-R (design 31 D5), the 64 of step AI-4 (design
 * 32 D5) and the 25 of step AI-5 (design 33 D6). Field names checked against
 * docs/api/openapi.json (request and response schemas; the
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
  // ===== step AI-4 (64) =====
  // --- ATO accounts (6) ---
  {
    operationId: 'AtoAccountsController_update_v1',
    precondition: atoAccount(
      ['rowVersion', 'protection.protected'],
      ATO_ACCOUNT_DISPLAY,
      'accountId',
      true,
    ),
    inject: BODY_ROW_VERSION,
    escalate: [high({ equals: { path: 'body.protected', value: true } }, W.atoProtected)],
  },
  {
    operationId: 'AtoAccountMailboxController_refresh_v1',
    precondition: atoAccount(['status'], ['address', 'kind']),
  },
  {
    operationId: 'AtoAccountsController_setOverride_v1',
    precondition: atoAccount(['overrideDetail.id', 'overrideDetail.verdict'], ATO_OVERRIDE_DISPLAY),
    escalate: [high({ equals: { path: 'body.verdict', value: 'benign' } }, W.atoBenign)],
  },
  {
    operationId: 'AtoAccountsController_clearOverride_v1',
    precondition: atoAccount(['overrideDetail.id'], ATO_OVERRIDE_DISPLAY),
  },
  {
    operationId: 'AtoAccountsController_addTrustedContext_v1',
    precondition: atoAccount(['status'], ['address', 'riskLevel', 'trustedContexts[].kind']),
  },
  {
    operationId: 'AtoAccountsController_removeTrustedContext_v1',
    precondition: {
      kind: 'single',
      tool: 'ato_accounts_get',
      params: { accountId: 'accountId' },
      select: { array: 'trustedContexts', field: 'id', arg: 'contextId', required: true },
      stateFields: ['id', 'expiresAt'],
      displayFields: ['kind', 'value', 'reason', 'source', 'expiresAt'],
    },
  },
  // --- ATO responses (5): the existing approval model, four eyes in chat (D3) ---
  {
    operationId: 'AtoResponsesController_request_v1',
    precondition: incident(['status'], false, [
      'category',
      'status',
      'severity',
      'subject.display',
    ]),
  },
  {
    operationId: 'AtoResponsesController_approve_v1',
    precondition: atoResponse(['status', 'approvalExpiresAt']),
    guards: ATO_FOUR_EYES,
  },
  {
    operationId: 'AtoResponsesController_reject_v1',
    precondition: atoResponse(['status']),
    guards: ATO_FOUR_EYES,
  },
  { operationId: 'AtoResponsesController_cancel_v1', precondition: atoResponse(['status']) },
  {
    operationId: 'AtoResponsesController_rollback_v1',
    precondition: atoResponse(
      ['status'],
      [...ATO_RESPONSE_DISPLAY, 'executedAt', 'effectiveUntil'],
    ),
  },
  // --- ATO settings (1) ---
  {
    operationId: 'AtoSettingsController_update_v1',
    precondition: {
      kind: 'single',
      tool: 'ato_settings_get',
      params: {},
      stateFields: ['rowVersion'],
      rowVersionField: 'rowVersion',
      displayFields: [
        'featureEnabled',
        'version',
        'effective.mode',
        'learning.active',
        'automation.platformEnabled',
        'automation.approvalTtlHours',
      ],
    },
    inject: { in: 'body', field: 'expectedRowVersion', min: 0 },
  },
  // --- ATO identity-provider integrations (7; non-secret fields only) ---
  {
    operationId: 'AtoProvidersController_create_v1',
    precondition: {
      kind: 'single',
      tool: 'ato_providers_connections',
      params: {},
      select: { array: 'data', field: 'id', arg: 'body.connectionId', required: true },
      stateFields: ['status'],
      displayFields: ['displayName', 'provider', 'status', 'eligibility'],
    },
    escalate: [high({ present: 'body.settings' }, W.idpSettings)],
  },
  {
    operationId: 'AtoProvidersController_update_v1',
    precondition: atoProvider(['rowVersion', 'status'], true),
    inject: { in: 'body', field: 'rowVersion', min: 1 },
  },
  { operationId: 'AtoProvidersController_remove_v1', precondition: atoProvider(['status']) },
  { operationId: 'AtoProvidersController_backfill_v1', precondition: atoProvider(['status']) },
  { operationId: 'AtoProvidersController_healthCheck_v1', precondition: atoProvider(['status']) },
  { operationId: 'AtoProvidersController_pause_v1', precondition: atoProvider(['status']) },
  { operationId: 'AtoProvidersController_resume_v1', precondition: atoProvider(['status']) },
  // --- incidents (3) ---
  {
    // ATO is the only incident category (a subject of another category fails this read).
    operationId: 'IncidentsController_create_v1',
    precondition: atoAccount(
      ['status'],
      ['address', 'riskLevel', 'activeIncident.id', 'activeIncident.status'],
      'body.subject.id',
    ),
  },
  {
    operationId: 'IncidentsController_update_v1',
    precondition: incident(['rowVersion', 'status'], true),
    inject: BODY_ROW_VERSION,
    escalate: [
      {
        when: { equals: { path: 'body.status', value: 'resolved' } },
        risk: 'medium',
        warning: W.incidentResolved,
      },
      high({ equals: { path: 'body.status', value: 'false_positive' } }, W.incidentFalsePositive),
      high({ present: 'body.categoryFeedback' }, W.incidentFeedback),
    ],
  },
  {
    operationId: 'IncidentsController_addNote_v1',
    precondition: incident(['status'], false, ['category', 'status', 'subject.display']),
  },
  // --- BEC (11) ---
  // A new profile with known addresses / senders / domains suppresses impersonation findings of
  // its name as much as the same fields on an update (the first profile whose name matches wins
  // in packages/bec evaluate), so the create escalates exactly as the update does (I20, A4-2). A
  // disabled new profile is not escalated: the detection snapshot loads enabled profiles only, so
  // it weakens nothing.
  {
    operationId: 'BecExecutivesController_create_v1',
    precondition: null,
    escalate: [high({ present: 'body.knownAddresses' }, W.executiveAddresses)],
  },
  {
    operationId: 'BecExecutivesController_update_v1',
    precondition: versioned('bec_executives_get', EXECUTIVE_DISPLAY),
    inject: BODY_VERSION,
    escalate: [
      high(disabled(), W.executiveDisabled),
      high({ present: 'body.knownAddresses' }, W.executiveAddresses),
    ],
  },
  {
    operationId: 'BecExecutivesController_remove_v1',
    precondition: versioned('bec_executives_get', EXECUTIVE_DISPLAY),
    inject: QUERY_VERSION,
  },
  { operationId: 'BecTrustedSendersController_create_v1', precondition: null },
  {
    operationId: 'BecTrustedSendersController_update_v1',
    precondition: versioned('bec_trusted_senders_get', TRUSTED_SENDER_DISPLAY),
    inject: BODY_VERSION,
    escalate: [high({ present: 'body.expiresAt' }, W.trustedSenderExpiry)],
  },
  {
    operationId: 'BecTrustedSendersController_remove_v1',
    precondition: versioned('bec_trusted_senders_get', TRUSTED_SENDER_DISPLAY),
    inject: QUERY_VERSION,
  },
  {
    operationId: 'BecVendorsController_create_v1',
    precondition: null,
    escalate: [
      high({ present: 'body.knownSenders' }, W.vendorSenders),
      high({ present: 'body.domains' }, W.vendorSenders),
      high(disabled('body.paymentChangeSensitive'), W.vendorPaymentChange),
    ],
  },
  {
    operationId: 'BecVendorsController_update_v1',
    precondition: versioned('bec_vendors_get', VENDOR_DISPLAY),
    inject: BODY_VERSION,
    escalate: [
      high(disabled(), W.vendorDisabled),
      high({ present: 'body.knownSenders' }, W.vendorSenders),
      high({ present: 'body.domains' }, W.vendorSenders),
      high(disabled('body.paymentChangeSensitive'), W.vendorPaymentChange),
    ],
  },
  {
    operationId: 'BecVendorsController_remove_v1',
    precondition: versioned('bec_vendors_get', VENDOR_DISPLAY),
    inject: QUERY_VERSION,
  },
  {
    operationId: 'BecFeedbackController_deleteSuppression_v1',
    precondition: {
      kind: 'single',
      tool: 'bec_feedback_get_suppression',
      params: { id: 'id' },
      stateFields: ['expiresAt'],
      displayFields: ['reasonCode', 'senderScope', 'senderValue', 'expiresAt'],
    },
  },
  {
    operationId: 'BecMessageFeedbackController_record_v1',
    precondition: {
      kind: 'single',
      tool: MESSAGE_DETAIL,
      params: { messageId: 'messageId' },
      stateFields: ['status'],
      displayFields: ['subject', 'headerFrom', 'direction', 'finalVerdict'],
    },
    escalate: [high({ present: 'body.suppress' }, W.becSuppress)],
  },
  // --- DLP (17) ---
  {
    operationId: 'DlpComplianceController_enable_v1',
    precondition: dlpCompliance(),
    inject: { in: 'body', field: 'expectedVersion', min: 0 },
  },
  {
    operationId: 'DlpComplianceController_disable_v1',
    precondition: dlpCompliance(),
    inject: { in: 'query', field: 'expectedVersion', min: 0 },
  },
  { operationId: 'DlpDictionariesController_create_v1', precondition: null },
  {
    operationId: 'DlpDictionariesController_update_v1',
    precondition: versioned('dlp_dictionaries_get', DICTIONARY_DISPLAY),
    inject: BODY_VERSION,
    escalate: [high(disabled(), W.dlpDetectorDisabled)],
  },
  {
    operationId: 'DlpDictionariesController_remove_v1',
    precondition: versioned('dlp_dictionaries_get', DICTIONARY_DISPLAY),
    inject: QUERY_VERSION,
  },
  { operationId: 'DlpExceptionsController_create_v1', precondition: null },
  {
    operationId: 'DlpExceptionsController_update_v1',
    precondition: versioned('dlp_exceptions_get', EXCEPTION_DISPLAY),
    inject: BODY_VERSION,
    escalate: [
      high({ equals: { path: 'body.enabled', value: true } }, W.dlpExceptionWidened),
      high({ present: 'body.expiresAt' }, W.dlpExceptionWidened),
      high({ present: 'body.filters' }, W.dlpExceptionWidened),
    ],
  },
  {
    operationId: 'DlpExceptionsController_remove_v1',
    precondition: versioned('dlp_exceptions_get', EXCEPTION_DISPLAY),
    inject: QUERY_VERSION,
  },
  { operationId: 'DlpPatternsController_create_v1', precondition: null },
  {
    operationId: 'DlpPatternsController_update_v1',
    precondition: versioned('dlp_patterns_get', PATTERN_DISPLAY),
    inject: BODY_VERSION,
    escalate: [
      high(disabled(), W.dlpDetectorDisabled),
      { when: { present: 'body.pattern' }, risk: 'medium', warning: W.dlpPatternChanged },
    ],
  },
  {
    operationId: 'DlpPatternsController_remove_v1',
    precondition: versioned('dlp_patterns_get', PATTERN_DISPLAY),
    inject: QUERY_VERSION,
  },
  { operationId: 'DlpPoliciesController_create_v1', precondition: null },
  {
    operationId: 'DlpPoliciesController_update_v1',
    precondition: versioned('dlp_policies_get', DLP_POLICY_DISPLAY),
    inject: BODY_VERSION,
    escalate: [
      high(disabled(), W.dlpPolicyDisabled),
      high({ equals: { path: 'body.mode', value: 'monitor' } }, W.dlpPolicyMonitor),
    ],
  },
  {
    operationId: 'DlpPoliciesController_remove_v1',
    precondition: versioned('dlp_policies_get', DLP_POLICY_DISPLAY),
    inject: QUERY_VERSION,
  },
  {
    operationId: 'DlpPoliciesController_createRule_v1',
    precondition: {
      kind: 'single',
      tool: 'dlp_policies_get',
      params: { id: 'id' },
      stateFields: ['version'],
      displayFields: ['name', 'mode', 'ruleCount'],
    },
    escalate: [high({ equals: { path: 'body.action', value: 'allow' } }, W.dlpAllowRule)],
  },
  {
    operationId: 'DlpPoliciesController_updateRule_v1',
    precondition: dlpRule(),
    inject: BODY_VERSION,
    escalate: [
      high({ equals: { path: 'body.action', value: 'allow' } }, W.dlpAllowRule),
      high(disabled(), W.dlpRuleDisabled),
    ],
  },
  {
    operationId: 'DlpPoliciesController_removeRule_v1',
    precondition: dlpRule(),
    inject: QUERY_VERSION,
  },
  // --- risk-scoring profiles (6) ---
  { operationId: 'RiskProfilesController_createDraft_v1', precondition: null },
  {
    operationId: 'RiskProfilesController_updateDraft_v1',
    precondition: riskVersion(),
    inject: BODY_ROW_VERSION,
  },
  {
    operationId: 'RiskProfilesController_deleteDraft_v1',
    precondition: riskVersion(),
    inject: QUERY_ROW_VERSION,
  },
  {
    operationId: 'RiskProfilesController_publish_v1',
    precondition: riskVersion(),
    inject: BODY_ROW_VERSION,
  },
  {
    operationId: 'RiskProfilesController_activate_v1',
    precondition: riskProfile(),
    inject: BODY_PROFILE_VERSION,
  },
  {
    operationId: 'RiskProfilesController_reset_v1',
    precondition: riskProfile(),
    inject: BODY_PROFILE_VERSION,
  },
  // --- platform operations (8; platform users without an override only) ---
  { operationId: 'AttachmentRescansController_request_v1', precondition: null },
  {
    operationId: 'AttachmentRescansController_cancel_v1',
    precondition: {
      kind: 'single',
      tool: 'attachment_rescans_get',
      params: { jobId: 'jobId' },
      stateFields: ['status'],
      displayFields: [
        'status',
        'windowStart',
        'windowEnd',
        'organizationId',
        'maxMessages',
        'selectedCount',
      ],
    },
  },
  // The stats read is a queue summary without a stable state: the impact is from the arguments.
  { operationId: 'DeadLettersController_replay_v1', precondition: null },
  // A platform principal reads no tenant message without an override.
  { operationId: 'ScanTrainingController_train_v1', precondition: null },
  { operationId: 'ThreatHashesController_add_v1', precondition: null },
  {
    operationId: 'ThreatHashesController_remove_v1',
    precondition: {
      kind: 'single',
      tool: 'threat_hashes_list',
      params: { sha256: 'sha256' },
      select: { array: 'data', field: 'sha256', arg: 'sha256', required: true },
      stateFields: ['severity', 'expiresAt'],
      displayFields: ['sha256', 'severity', 'family', 'source'],
    },
  },
  { operationId: 'ThreatIndicatorsController_add_v1', precondition: null },
  {
    operationId: 'ThreatIndicatorsController_remove_v1',
    precondition: {
      kind: 'single',
      tool: 'threat_indicators_get',
      params: { id: 'id' },
      stateFields: ['severity', 'expiresAt'],
      displayFields: ['type', 'value', 'severity', 'category', 'source'],
    },
  },
  // ===== step AI-5 (25; design 33 D6) =====
  // --- archive (5) ---
  // A new policy can take precedence over the default: always high (D2, A5-1).
  { operationId: 'ArchiveRetentionController_create_v1', precondition: null },
  {
    operationId: 'ArchiveRetentionController_update_v1',
    precondition: retentionPolicy(
      ['rowVersion', 'retentionDays', 'onExpiry', 'priority', 'criteria', 'isDefault'],
      ['name', 'retentionDays', 'onExpiry', 'priority', 'isDefault'],
      true,
    ),
    inject: BODY_ROW_VERSION,
    // The PUT replaces the whole policy: an omitted field returns to its default (`absentAs`).
    escalate: [
      high(
        { below: { path: 'body.retentionDays', field: 'retentionDays' } },
        W5.retentionShortened,
      ),
      high(
        {
          becomes: {
            path: 'body.onExpiry',
            field: 'onExpiry',
            value: 'delete',
            absentAs: RETENTION_DEFAULTS.onExpiry,
          },
        },
        W5.expiryDelete,
      ),
      high(
        {
          differs: {
            path: 'body.criteria',
            field: 'criteria',
            absentAs: RETENTION_DEFAULTS.criteria,
          },
        },
        W5.retentionScope,
      ),
      high(
        {
          differs: {
            path: 'body.priority',
            field: 'priority',
            absentAs: RETENTION_DEFAULTS.priority,
          },
        },
        W5.retentionScope,
      ),
    ],
  },
  {
    operationId: 'ArchiveRetentionController_delete_v1',
    precondition: retentionPolicy(
      ['rowVersion', 'isDefault'],
      ['name', 'retentionDays', 'onExpiry', 'isDefault'],
      false,
    ),
    guards: [
      {
        kind: 'require_read_value',
        field: 'isDefault',
        equals: false,
        message: 'retention_default_policy',
      },
    ],
  },
  {
    operationId: 'ArchiveAdminController_retry_v1',
    precondition: {
      kind: 'single',
      tool: 'archive_admin_capture_issue',
      params: { messageId: 'messageId' },
      stateFields: ['status', 'attempts'],
      displayFields: [
        'receivedAt',
        'status',
        'code',
        'attempts',
        'sources.journal',
        'sources.policy',
      ],
    },
    guards: [
      {
        kind: 'require_read_value',
        field: 'status',
        equals: 'failed',
        message: 'capture_not_retryable',
      },
    ],
  },
  {
    operationId: 'ArchiveAdminController_update_v1',
    precondition: {
      kind: 'single',
      tool: 'archive_admin_get',
      params: {},
      stateFields: ['rowVersion', 'enabled', 'immutability', 'defaultRetentionPolicyId'],
      rowVersionField: 'rowVersion',
      displayFields: [
        'enabled',
        'entitled',
        'immutability',
        'objectLockAvailable',
        'defaultRetentionPolicyId',
        ...SETTINGS_SECTIONS_DISPLAY,
        'settings.access.previewEnabled',
        'settings.access.downloadEnabled',
      ],
    },
    inject: BODY_ROW_VERSION_0,
    escalate: [
      high(disabled(), W5.archiveOff),
      high({ present: 'body.settings' }, W5.archiveSettings),
      high(
        { differs: { path: 'body.immutability', field: 'immutability' } },
        W5.archiveImmutability,
      ),
      high(
        { differs: { path: 'body.defaultRetentionPolicyId', field: 'defaultRetentionPolicyId' } },
        W5.archiveDefaultPolicy,
      ),
    ],
  },
  // --- journaling (4) ---
  {
    operationId: 'JournalingController_update_v1',
    precondition: {
      kind: 'single',
      tool: 'journaling_get',
      params: {},
      stateFields: ['rowVersion', 'enabled'],
      rowVersionField: 'rowVersion',
      displayFields: ['enabled', 'entitled', ...SETTINGS_SECTIONS_DISPLAY],
    },
    inject: BODY_ROW_VERSION_0,
    escalate: [
      high(disabled(), W5.journalingOff),
      high({ present: 'body.settings' }, W5.journalingSettings),
    ],
  },
  {
    operationId: 'IntakeSourcesController_update_v1',
    precondition: intakeSource(
      ['rowVersion', 'status', 'maxMessageBytes'],
      [
        ...INTAKE_DISPLAY,
        'requireTls',
        'health.status',
        'networks',
        'clientCertFingerprints',
        'maxMessageBytes',
        'silenceAlertMinutes',
      ],
      true,
    ),
    inject: BODY_ROW_VERSION,
    escalate: [
      high({ equals: { path: 'body.status', value: 'paused' } }, W5.intakePaused),
      high({ present: 'body.networks' }, W5.intakeNetworks),
      high(disabled('body.requireTls'), W5.intakeTls),
      high({ present: 'body.clientCertFingerprints' }, W5.intakeCertificates),
      // A lower size limit refuses larger journal messages permanently (`552 5.3.4`, design 27
      // §D step 7), stronger than a pause. Fail closed: a read without a source limit (`null`,
      // the platform limit applies) or clearing the limit (`null` argument) also matches.
      high({ below: { path: 'body.maxMessageBytes', field: 'maxMessageBytes' } }, W5.intakeSize),
      high({ equals: { path: 'body.silenceAlertMinutes', value: null } }, W5.intakeSilenceOff),
    ],
  },
  {
    operationId: 'IntakeSourcesController_disable_v1',
    precondition: intakeSource(['status'], INTAKE_DISPLAY),
  },
  {
    operationId: 'IntakeSourcesController_attest_v1',
    precondition: intakeSource(['status'], INTAKE_DISPLAY),
  },
  // --- eDiscovery (7) ---
  { operationId: 'EdiscoveryCasesController_create_v1', precondition: null },
  {
    operationId: 'EdiscoveryCasesController_update_v1',
    precondition: ediscoveryCase(
      ['rowVersion', 'status'],
      ['name', 'matterReference', 'status', 'counts.custodians'],
      true,
    ),
    inject: BODY_ROW_VERSION,
    escalate: [
      { when: { present: 'body.custodians' }, risk: 'medium', warning: W5.caseCustodians },
    ],
  },
  {
    operationId: 'EdiscoveryCasesController_close_v1',
    precondition: ediscoveryCase(
      ['status', 'counts.activeHolds'],
      ['name', 'status', 'counts.activeHolds', 'counts.searches', 'counts.exports'],
    ),
    guards: [
      {
        kind: 'require_read_value',
        field: 'counts.activeHolds',
        equals: 0,
        message: 'case_active_holds',
      },
    ],
  },
  {
    operationId: 'EdiscoveryCasesController_createHold_v1',
    precondition: ediscoveryCase(
      ['status'],
      ['name', 'status', 'counts.custodians', 'counts.activeHolds'],
    ),
  },
  {
    operationId: 'EdiscoverySearchesController_create_v1',
    precondition: ediscoveryCase(['status'], ['name', 'status']),
  },
  {
    operationId: 'EdiscoverySearchesController_review_v1',
    precondition: {
      kind: 'single',
      tool: 'ediscovery_searches_get',
      params: { caseId: 'caseId', searchId: 'searchId' },
      stateFields: ['status'],
      displayFields: SEARCH_DISPLAY,
    },
  },
  {
    operationId: 'EdiscoveryExportsController_create_v1',
    precondition: {
      kind: 'single',
      tool: 'ediscovery_searches_get',
      params: { caseId: 'caseId', searchId: 'body.searchId' },
      stateFields: ['status', 'hitCount'],
      displayFields: [...SEARCH_DISPLAY, 'incompleteReason'],
    },
    escalate: [
      high({ equals: { path: 'body.acknowledgeMalicious', value: true } }, W5.exportMalicious),
    ],
  },
  // --- provider connections (9) ---
  { operationId: 'ProviderConnectionsController_create_v1', precondition: null },
  {
    operationId: 'ProviderConnectionsController_update_v1',
    precondition: providerConnection(['rowVersion'], PROVIDER_DISPLAY, true),
    inject: { in: 'body', field: 'rowVersion', min: 1 },
  },
  {
    operationId: 'ProviderConnectionsController_disconnect_v1',
    precondition: mailFlow(),
    impactToken: {
      previewTool: 'provider_mail_flow_preview',
      params: { id: 'id' },
      change: { constant: { kind: 'disable' } },
    },
  },
  {
    operationId: 'ProviderAttestationsController_record_v1',
    precondition: providerConnection(['status']),
  },
  {
    operationId: 'ProviderDomainsController_replace_v1',
    precondition: providerConnection(
      ['rowVersion', 'status'],
      [...PROVIDER_DISPLAY, 'domains[].name'],
    ),
  },
  { operationId: 'ProviderGrantsController_revoke_v1', precondition: providerGrant() },
  // `body.subjectEmail` is omitted from the tool (D7): chat only re-verifies a set-up grant.
  { operationId: 'ProviderGrantsController_verify_v1', precondition: providerGrant() },
  {
    operationId: 'ProviderHealthController_checkNow_v1',
    precondition: providerConnection(['status'], [...PROVIDER_DISPLAY, 'health']),
  },
  {
    operationId: 'ProviderMailFlowController_apply_v1',
    precondition: mailFlow(),
    impactToken: {
      previewTool: 'provider_mail_flow_preview',
      params: { id: 'id' },
      change: { from: 'body.change' },
    },
  },
  // --- native (step AI-R D5) ---
  {
    operationId: 'AssistantNative_reportSendEmail',
    precondition: null,
    native: 'report_send_email',
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
// Server-filled impact tokens (step AI-5 D5; pure, the api's executor and proposer use them)
// ---------------------------------------------------------------------------------------------

const asBody = (value: unknown): Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};

/**
 * Arguments for the executor's first schema check (D5 step 1): when the spec has `impactToken`,
 * `body.impactToken` is set to `IMPACT_TOKEN_PLACEHOLDER` and `body.confirm` to `true` when they
 * are absent, so the write's required fields never block a proposal. Other specs: a copy.
 */
export function withImpactTokenPlaceholder(
  args: Readonly<Record<string, unknown>>,
  spec: Pick<ConfirmationSpec, 'impactToken'>,
): Record<string, unknown> {
  const out = cloneArgs(args);
  if (!spec.impactToken) return out;
  const body = asBody(out.body);
  if (body.impactToken === undefined) body.impactToken = IMPACT_TOKEN_PLACEHOLDER;
  if (body.confirm === undefined) body.confirm = true;
  out.body = body;
  return out;
}

/**
 * The preview call's arguments from the write's arguments (D5 step 2): the mapped path
 * parameters and `body: { change }` (the write's `body.change`, or the spec's constant change).
 */
export function impactPreviewArgs(
  injection: ImpactTokenInjection,
  args: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [param, path] of Object.entries(injection.params))
    out[param] = readArgPath(args, path);
  const change =
    'constant' in injection.change
      ? structuredClone(injection.change.constant)
      : structuredClone(readArgPath(args, injection.change.from));
  out.body = change === undefined ? {} : { change };
  return out;
}

/** The precondition target with the preview response merged under `preview` (D5 step 2). */
export function withImpactPreview(target: unknown, preview: unknown): Record<string, unknown> {
  return { ...asBody(target), [IMPACT_PREVIEW_KEY]: preview };
}

export type ImpactTokenInjectionResult =
  | { ok: true; args: Record<string, unknown> }
  /** The preview answered without a usable `impactToken` (absent, not a string, empty or too long). */
  | { ok: false; reason: 'impact_token_missing' };

/**
 * Arguments with `body.impactToken` set from the preview response's `impactToken` and
 * `body.confirm` set to `true`, always replacing the model's values (D5 step 2). A preview
 * without a usable token fails (the api fails the proposal like a failed read).
 */
export function withInjectedImpactToken(
  args: Readonly<Record<string, unknown>>,
  previewBody: unknown,
): ImpactTokenInjectionResult {
  const token = asBody(previewBody).impactToken;
  if (typeof token !== 'string' || token.length === 0 || token.length > IMPACT_TOKEN_MAX_CHARS)
    return { ok: false, reason: 'impact_token_missing' };
  const out = cloneArgs(args);
  const body = asBody(out.body);
  body.impactToken = token;
  body.confirm = true;
  out.body = body;
  return { ok: true, args: out };
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
