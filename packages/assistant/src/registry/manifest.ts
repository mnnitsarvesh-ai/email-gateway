import type {
  DisplayHints,
  HttpMethod,
  OperationOverride,
  ProgramPhase,
  ToolAccess,
  ToolConfirm,
  ToolRisk,
} from './types';

/**
 * The registry manifest (design D3, §4.4): the classification **rules** that produced the
 * design's Appendix A, plus per-operation **overrides** (risk overrides, display hints,
 * `untrustedFields`, portal routes, bindings). `scripts/generate-registry.ts` applies them to
 * every operation of `docs/api/openapi.json`; the registry check fails when an operation is not
 * classified or a consistency rule breaks.
 *
 * Rule for later steps (ATP-1..9, 8.3, …): a step that adds or changes API operations classifies
 * them here (tool or `not_applicable` with a reason), adds display hints and `untrustedFields`,
 * and runs `pnpm --filter @email-gateway/assistant registry:generate`.
 */

/**
 * Phase the program has reached: tools of this phase and earlier are enabled (reads; writes with
 * a `testedBy` suite and a confirmation spec, step AI-2; identity and tenant administration
 * writes, step AI-3; the native report tools, step AI-R, which adds no OpenAPI tool; security
 * operations, step AI-4; compliance and integrations, step AI-5, after which every planned
 * OpenAPI tool of the program is enabled).
 */
export const ASSISTANT_PROGRAM_PHASE: ProgramPhase = 'AI-5';

/** Phase from which write tools can execute (the confirmation manager, ADR-0093). */
export const CONFIRMATION_SUPPORT_PHASE: ProgramPhase = 'AI-2';

/** The AI-1 tool sweep suite that covers every enabled read (design §9 item 4). */
export const READ_TOOLS_TESTED_BY = 'apps/api/integration/assistant-tools.test.ts';

/** Integration suites of the AI-2 writes (design 29 §4.3, §9 item 4). */
export const POLICY_WRITES_TESTED_BY = 'apps/api/integration/assistant-writes-policies.test.ts';
export const MAIL_OPS_WRITES_TESTED_BY = 'apps/api/integration/assistant-writes-mail-ops.test.ts';

/** The 31 write operations of step AI-2 and the suite that covers each (`testedBy`). */
export const AI2_WRITES_TESTED_BY: Readonly<Record<string, string>> = {
  ...Object.fromEntries(
    [
      'PolicyManagementController_create_v1',
      'PolicyManagementController_update_v1',
      'PolicyManagementController_enable_v1',
      'PolicyManagementController_disable_v1',
      'PolicyManagementController_remove_v1',
      'PolicyManagementController_createDraft_v1',
      'PolicyManagementController_updateDraft_v1',
      'PolicyManagementController_deleteDraft_v1',
      'PolicyManagementController_publish_v1',
      'PolicyManagementController_activate_v1',
      'PolicySettingsController_put_v1',
    ].map((id) => [id, POLICY_WRITES_TESTED_BY]),
  ),
  ...Object.fromEntries(
    [
      'QuarantineEntriesController_release_v1',
      'QuarantineEntriesController_reject_v1',
      'QuarantineEntriesController_delete_v1',
      'QuarantineEntriesController_requestRelease_v1',
      'QuarantineEntriesController_manual_v1',
      'QuarantineSelfController_release_v1',
      'QuarantineSelfController_requestRelease_v1',
      'QuarantineSelfController_putPreferences_v1',
      'QuarantineToolsController_putSettings_v1',
      'QuarantineToolsController_bulk_v1',
      'QuarantineApprovalsController_approve_v1',
      'QuarantineApprovalsController_deny_v1',
      'QuarantineApprovalsController_cancel_v1',
      'MessageLifecycleController_release_v1',
      'MessageLifecycleController_rescan_v1',
      'RecipientSuppressionsController_create_v1',
      'RecipientSuppressionsController_delete_v1',
      'SavedViewsController_create_v1',
      'SavedViewsController_update_v1',
      'SavedViewsController_remove_v1',
    ].map((id) => [id, MAIL_OPS_WRITES_TESTED_BY]),
  ),
};

/** Integration suites of the AI-3 writes (design 30 §4.3, §9 item 4). */
export const IDENTITY_WRITES_TESTED_BY = 'apps/api/integration/assistant-writes-identity.test.ts';
export const DOMAIN_WRITES_TESTED_BY = 'apps/api/integration/assistant-writes-domains.test.ts';
export const TENANT_ADMIN_WRITES_TESTED_BY =
  'apps/api/integration/assistant-writes-tenant-admin.test.ts';

/**
 * The 47 write operations of step AI-3 and the suite that covers each (`testedBy`).
 *
 * Rule for later steps (design 30 R7): when the request body of one of these routes gains a field
 * that redirects mail, events, sign-in mail or relay rights, or weakens MFA, add a risk
 * escalation for it to the operation's confirmation spec (`confirmations/specs.ts`).
 */
export const AI3_WRITES_TESTED_BY: Readonly<Record<string, string>> = {
  ...Object.fromEntries(
    [
      'UsersController_invite_v1',
      'UsersController_update_v1',
      'UsersController_changeStatus_v1',
      'UsersController_replaceRoles_v1',
      'UsersController_resetMfa_v1',
      'UsersController_remove_v1',
      'UsersController_resendInvitation_v1',
      'UsersController_revokeAllSessions_v1',
      'UsersController_revokeSession_v1',
      'RolesController_create_v1',
      'RolesController_update_v1',
      'RolesController_remove_v1',
      'DepartmentsController_create_v1',
      'DepartmentsController_update_v1',
      'DepartmentsController_remove_v1',
      'DepartmentsController_addMember_v1',
      'DepartmentsController_removeMember_v1',
      'ApiKeysController_revoke_v1',
    ].map((id) => [id, IDENTITY_WRITES_TESTED_BY]),
  ),
  ...Object.fromEntries(
    [
      'DomainsController_create_v1',
      'DomainsController_remove_v1',
      'DomainsController_changeStatus_v1',
      'DomainDnsController_verify_v1',
      'DomainDnsController_rotate_v1',
      'DomainDestinationsController_replace_v1',
      'DomainDestinationsController_remove_v1',
      'DomainRecipientsController_set_v1',
      'DomainRecipientsController_add_v1',
      'DomainRecipientsController_remove_v1',
    ].map((id) => [id, DOMAIN_WRITES_TESTED_BY]),
  ),
  ...Object.fromEntries(
    [
      'NotificationsController_putPreferences_v1',
      'NotificationsController_putSettings_v1',
      'OrganizationsController_create_v1',
      'OrganizationsController_update_v1',
      'OrganizationDeletionController_cancel_v1',
      'OrganizationConfigurationController_overrideFeature_v1',
      'OrganizationConfigurationController_resetFeature_v1',
      'OrganizationConfigurationController_overrideLimit_v1',
      'OrganizationConfigurationController_resetLimit_v1',
      'OrganizationConfigurationController_updateSettings_v1',
      'ScanSettingsController_replace_v1',
      'ScanSettingsController_reset_v1',
      'SmtpConnectorsController_update_v1',
      'SmtpConnectorsController_remove_v1',
      'WebhooksController_update_v1',
      'WebhooksController_delete_v1',
      'WebhooksController_test_v1',
      'WebhookDeliveriesController_replay_v1',
      'WebhookDeliveriesController_createReplay_v1',
    ].map((id) => [id, TENANT_ADMIN_WRITES_TESTED_BY]),
  ),
};

/** Integration suites of the AI-4 writes (design 32 §4.4, §9 item 3). */
export const ATO_WRITES_TESTED_BY = 'apps/api/integration/assistant-writes-ato.test.ts';
export const DETECTION_WRITES_TESTED_BY = 'apps/api/integration/assistant-writes-detection.test.ts';
export const PLATFORM_OPS_WRITES_TESTED_BY =
  'apps/api/integration/assistant-writes-platform-ops.test.ts';

/**
 * The 64 write operations of step AI-4 and the suite that covers each (`testedBy`): 19 ATO and
 * 3 incident writes, 11 BEC, 17 DLP and 6 risk-scoring writes, 8 platform writes.
 *
 * Rule for later steps (design 32 I20): when the request body of one of these routes gains a
 * field that adds trust or an exception, suppresses findings, disables a detector or switches it
 * to monitor-only, add a risk escalation for it to the operation's confirmation spec.
 */
export const AI4_WRITES_TESTED_BY: Readonly<Record<string, string>> = {
  ...Object.fromEntries(
    [
      'AtoAccountsController_update_v1',
      'AtoAccountMailboxController_refresh_v1',
      'AtoAccountsController_setOverride_v1',
      'AtoAccountsController_clearOverride_v1',
      'AtoAccountsController_addTrustedContext_v1',
      'AtoAccountsController_removeTrustedContext_v1',
      'AtoResponsesController_request_v1',
      'AtoResponsesController_approve_v1',
      'AtoResponsesController_reject_v1',
      'AtoResponsesController_cancel_v1',
      'AtoResponsesController_rollback_v1',
      'AtoSettingsController_update_v1',
      'AtoProvidersController_create_v1',
      'AtoProvidersController_update_v1',
      'AtoProvidersController_remove_v1',
      'AtoProvidersController_backfill_v1',
      'AtoProvidersController_healthCheck_v1',
      'AtoProvidersController_pause_v1',
      'AtoProvidersController_resume_v1',
      'IncidentsController_create_v1',
      'IncidentsController_update_v1',
      'IncidentsController_addNote_v1',
    ].map((id) => [id, ATO_WRITES_TESTED_BY]),
  ),
  ...Object.fromEntries(
    [
      'BecExecutivesController_create_v1',
      'BecExecutivesController_update_v1',
      'BecExecutivesController_remove_v1',
      'BecTrustedSendersController_create_v1',
      'BecTrustedSendersController_update_v1',
      'BecTrustedSendersController_remove_v1',
      'BecVendorsController_create_v1',
      'BecVendorsController_update_v1',
      'BecVendorsController_remove_v1',
      'BecFeedbackController_deleteSuppression_v1',
      'BecMessageFeedbackController_record_v1',
      'DlpComplianceController_enable_v1',
      'DlpComplianceController_disable_v1',
      'DlpDictionariesController_create_v1',
      'DlpDictionariesController_update_v1',
      'DlpDictionariesController_remove_v1',
      'DlpExceptionsController_create_v1',
      'DlpExceptionsController_update_v1',
      'DlpExceptionsController_remove_v1',
      'DlpPatternsController_create_v1',
      'DlpPatternsController_update_v1',
      'DlpPatternsController_remove_v1',
      'DlpPoliciesController_create_v1',
      'DlpPoliciesController_update_v1',
      'DlpPoliciesController_remove_v1',
      'DlpPoliciesController_createRule_v1',
      'DlpPoliciesController_updateRule_v1',
      'DlpPoliciesController_removeRule_v1',
      'RiskProfilesController_createDraft_v1',
      'RiskProfilesController_updateDraft_v1',
      'RiskProfilesController_deleteDraft_v1',
      'RiskProfilesController_publish_v1',
      'RiskProfilesController_activate_v1',
      'RiskProfilesController_reset_v1',
    ].map((id) => [id, DETECTION_WRITES_TESTED_BY]),
  ),
  ...Object.fromEntries(
    [
      'AttachmentRescansController_request_v1',
      'AttachmentRescansController_cancel_v1',
      'DeadLettersController_replay_v1',
      'ScanTrainingController_train_v1',
      'ThreatHashesController_add_v1',
      'ThreatHashesController_remove_v1',
      'ThreatIndicatorsController_add_v1',
      'ThreatIndicatorsController_remove_v1',
    ].map((id) => [id, PLATFORM_OPS_WRITES_TESTED_BY]),
  ),
};

/** Integration suites of the AI-5 writes (design 33 §4.3, §9 item 3). */
export const COMPLIANCE_WRITES_TESTED_BY =
  'apps/api/integration/assistant-writes-compliance.test.ts';
export const INTEGRATIONS_WRITES_TESTED_BY =
  'apps/api/integration/assistant-writes-integrations.test.ts';

/**
 * The 25 write operations of step AI-5 and the suite that covers each (`testedBy`): 5 archive,
 * 4 journaling and 7 eDiscovery writes (16), 9 provider-connection writes.
 *
 * Rule for later steps (design 33 I22): when the request body of one of these routes gains a
 * field that shortens retention, deletes records without review, changes which mail a retention
 * policy matches, turns capture off or narrows it, or loosens a journal intake source, add a risk
 * escalation for it to the operation's confirmation spec.
 */
export const AI5_WRITES_TESTED_BY: Readonly<Record<string, string>> = {
  ...Object.fromEntries(
    [
      'ArchiveRetentionController_create_v1',
      'ArchiveRetentionController_update_v1',
      'ArchiveRetentionController_delete_v1',
      'ArchiveAdminController_retry_v1',
      'ArchiveAdminController_update_v1',
      'JournalingController_update_v1',
      'IntakeSourcesController_update_v1',
      'IntakeSourcesController_disable_v1',
      'IntakeSourcesController_attest_v1',
      'EdiscoveryCasesController_create_v1',
      'EdiscoveryCasesController_update_v1',
      'EdiscoveryCasesController_close_v1',
      'EdiscoveryCasesController_createHold_v1',
      'EdiscoverySearchesController_create_v1',
      'EdiscoverySearchesController_review_v1',
      'EdiscoveryExportsController_create_v1',
    ].map((id) => [id, COMPLIANCE_WRITES_TESTED_BY]),
  ),
  ...Object.fromEntries(
    [
      'ProviderConnectionsController_create_v1',
      'ProviderConnectionsController_update_v1',
      'ProviderConnectionsController_disconnect_v1',
      'ProviderAttestationsController_record_v1',
      'ProviderDomainsController_replace_v1',
      'ProviderGrantsController_revoke_v1',
      'ProviderGrantsController_verify_v1',
      'ProviderHealthController_checkNow_v1',
      'ProviderMailFlowController_apply_v1',
    ].map((id) => [id, INTEGRATIONS_WRITES_TESTED_BY]),
  ),
};

/**
 * Input properties of enabled writes whose key matches the credential-key pattern
 * (`isCredentialKey`) but which are not credentials (step AI-3 D6, I14). Named per operation and
 * argument path with the reason; the credential safe list (`SAFE_KEYS`) is never widened for
 * them. Role keys are identifiers such as `security_analyst` (`^[a-z][a-z0-9_]*$`).
 */
export const CREDENTIAL_KEY_EXCEPTIONS: Readonly<Record<string, Readonly<Record<string, string>>>> =
  {
    RolesController_create_v1: { 'body.key': 'role key (an identifier, not a credential)' },
    RolesController_update_v1: { key: 'role key path parameter (an identifier)' },
    RolesController_remove_v1: { key: 'role key path parameter (an identifier)' },
    // Step AI-4: response action names and reason/resolution codes (enum identifiers).
    AtoProvidersController_create_v1: {
      'body.settings.actions.require_password_reset':
        'the IdP response action "require password reset" (an on/off setting, not a password)',
    },
    AtoProvidersController_update_v1: {
      'body.settings.actions.require_password_reset':
        'the IdP response action "require password reset" (an on/off setting, not a password)',
    },
    AtoSettingsController_update_v1: {
      'body.settings.automation.require_password_reset':
        'automation of the response action "require password reset" (a setting, not a password)',
    },
    BecMessageFeedbackController_record_v1: {
      'body.reasonCodes': 'BEC reason codes (rule identifiers)',
      'body.suppress.codes': 'BEC reason codes to suppress (rule identifiers)',
    },
    IncidentsController_update_v1: {
      'body.resolution.code': 'incident resolution code (an enum value)',
    },
    // Step AI-5: attestation codes name the attested setup step (identifiers).
    IntakeSourcesController_attest_v1: {
      'body.code': 'attestation code (the identifier of an attested setup step)',
    },
    ProviderAttestationsController_record_v1: {
      'body.code': 'attestation code (the identifier of an attested setup step)',
    },
  };

/**
 * State and display fields of confirmation specs whose path has a segment matching the
 * credential-key pattern but which are not credentials (step AI-5 §4.3: no state or display
 * field may hold a credential-pattern key, such as the preview's `impactToken`). Named per
 * operation and field path with the reason.
 */
export const CREDENTIAL_FIELD_EXCEPTIONS: Readonly<
  Record<string, Readonly<Record<string, string>>>
> = {
  UsersController_update_v1: { 'roles[].key': 'role keys (identifiers)' },
  UsersController_changeStatus_v1: { 'roles[].key': 'role keys (identifiers)' },
  UsersController_replaceRoles_v1: { 'roles[].key': 'role keys (identifiers)' },
  UsersController_remove_v1: { 'roles[].key': 'role keys (identifiers)' },
  DomainsController_remove_v1: { unicodeName: 'the Unicode form of the domain name' },
  DomainsController_changeStatus_v1: { unicodeName: 'the Unicode form of the domain name' },
  OrganizationsController_update_v1: { 'plan.code': 'plan code (an identifier)' },
  WebhookDeliveriesController_replay_v1: { lastResponseCode: 'HTTP status of the last attempt' },
  BecFeedbackController_deleteSuppression_v1: { reasonCode: 'BEC reason code (a rule identifier)' },
  ArchiveAdminController_retry_v1: {
    code: 'capture failure code (an error identifier, never text)',
  },
};

export const NOT_APPLICABLE_REASONS = {
  ceremony: 'credential/session ceremony (portal only)',
  assistant: "the assistant's own routes are never tools (no recursion)",
  identity: 'changes the caller identity/tenant (portal only)',
  secret: 'returns a secret (never through chat)',
  content: 'content, preview, download or unmasking (portal only, ADR-0048/0062)',
  consent: 'credential or OAuth consent ceremony (portal only)',
  fileExport: 'file export stream (portal only; chat links to the page)',
  critical: 'critical: portal only by policy (chat links to the page)',
} as const;

/** Tags whose operations are never tools (D3 consistency rule). */
export const NOT_APPLICABLE_TAGS: Readonly<Record<string, string>> = {
  auth: NOT_APPLICABLE_REASONS.ceremony,
  mfa: NOT_APPLICABLE_REASONS.ceremony,
  sessions: NOT_APPLICABLE_REASONS.ceremony,
  meta: NOT_APPLICABLE_REASONS.ceremony,
  assistant: NOT_APPLICABLE_REASONS.assistant,
};

/**
 * Critical actions (§4.4): portal only. Organization status and deletion, legal-hold release,
 * archive disposal, archive key rotation, DLP evidence purges, BEC history purge.
 */
export const CRITICAL_OPERATIONS: ReadonlySet<string> = new Set([
  'OrganizationsController_changeStatus_v1',
  'OrganizationDeletionController_request_v1',
  'OrganizationDeletionController_confirm_v1',
  'LegalHoldsController_release_v1',
  'ArchiveMessagesController_dispose_v1',
  'ArchiveAdminController_rotate_v1',
  'DlpEvidenceController_purgeAll_v1',
  'DlpMessageEvidenceController_purge_v1',
  'BecFeedbackController_purgeHistory_v1',
]);

/** Planned phase of each module's writes and side-effect-free POSTs (§6). Reads (GET) are AI-1. */
export const MODULE_WRITE_PHASE: Readonly<Record<string, ProgramPhase>> = {
  policies: 'AI-2',
  quarantine: 'AI-2',
  messages: 'AI-2',
  recipients: 'AI-2',
  'saved-views': 'AI-2',
  'api-keys': 'AI-3',
  departments: 'AI-3',
  domains: 'AI-3',
  notifications: 'AI-3',
  organizations: 'AI-3',
  roles: 'AI-3',
  users: 'AI-3',
  'smtp-connectors': 'AI-3',
  webhooks: 'AI-3',
  'scan-settings': 'AI-3',
  ato: 'AI-4',
  bec: 'AI-4',
  dlp: 'AI-4',
  incidents: 'AI-4',
  platform: 'AI-4',
  'risk-scoring': 'AI-4',
  archive: 'AI-5',
  journaling: 'AI-5',
  ediscovery: 'AI-5',
  'provider-connections': 'AI-5',
};

/** The facts of one operation the rules look at. */
export interface OperationFacts {
  operationId: string;
  method: HttpMethod;
  /** Path without the `/api/v1` prefix. */
  path: string;
  tags: readonly string[];
  returnsSecret: boolean;
}

export type Classification =
  | { kind: 'not_applicable'; reason: string; access: ToolAccess; risk: 'critical' | null }
  | { kind: 'tool'; access: ToolAccess; risk: ToolRisk; confirm: ToolConfirm; phase: ProgramPhase };

const SIDE_EFFECT_FREE_POST = /\/(test|validate|dry-run|mail-flow\/preview)$/;
const HIGH_VERBS = new Set([
  'delete',
  'remove',
  'purge',
  'revoke',
  'rotate',
  'reset',
  'rollback',
  'bulk',
]);
const MEDIUM_VERBS = new Set([
  'enable',
  'disable',
  'publish',
  'activate',
  'approve',
  'deny',
  'release',
  'reject',
  'rescan',
  'retry',
  'replay',
  'replays',
  'pause',
  'resume',
  'verify',
  'cancel',
  'close',
  'review',
  'refresh',
  'backfill',
  'health-check',
  'check',
  'attestations',
  'request-release',
  'invitation',
  'invitations',
]);
/**
 * High-risk writes by path (§4.4): user status/roles, feature and limit overrides, exports,
 * holds, mail-flow apply, ATO response request/approve, policy settings, DLP compliance, role
 * creation, status changes.
 */
const HIGH_PATHS: ReadonlyArray<{ method?: HttpMethod; path: RegExp }> = [
  { path: /^\/users\/\{id\}\/(status|roles)$/ },
  { method: 'PATCH', path: /\/status$/ },
  { path: /^\/organizations\/\{id\}\/(features|limits)\/\{[^}]+\}$/ },
  { method: 'POST', path: /\/exports$/ },
  { method: 'POST', path: /\/holds$/ },
  { path: /\/mail-flow\/apply$/ },
  { path: /^\/ato\/incidents\/\{incidentId\}\/responses$/ },
  { path: /^\/ato\/responses\/\{responseId\}\/approve$/ },
  { path: /^\/policy-settings$/ },
  { path: /^\/dlp\/compliance\// },
  { method: 'POST', path: /^\/roles$/ },
];
/** Own preferences are `low` (§4.4). */
const OWN_PREFERENCES = /^\/(notifications|quarantine\/me)\/preferences$/;

/**
 * Explicit risk overrides named by §4.4 and by step AI-3 D2 (invitations grant roles, role edits
 * change every holder's permissions, destination replacement reroutes inbound mail, scan settings
 * can lower detection, SMTP connector state affects outbound relay, organization creation).
 */
export const RISK_OVERRIDES: Readonly<Record<string, ToolRisk>> = {
  SavedViewsController_remove_v1: 'low',
  NotificationsController_putPreferences_v1: 'low',
  QuarantineSelfController_putPreferences_v1: 'low',
  UsersController_invite_v1: 'high',
  RolesController_update_v1: 'high',
  DomainDestinationsController_replace_v1: 'high',
  ScanSettingsController_replace_v1: 'high',
  SmtpConnectorsController_update_v1: 'medium',
  OrganizationsController_create_v1: 'medium',
  UsersController_resendInvitation_v1: 'medium',
  DepartmentsController_removeMember_v1: 'medium',
  BecFeedbackController_deleteSuppression_v1: 'medium',
  WebhookDeliveriesController_replay_v1: 'medium',
  DomainsController_create_v1: 'medium',
  // Step AI-4 D2 (I20: weakening detection needs re-authentication).
  AtoAccountsController_addTrustedContext_v1: 'high',
  BecTrustedSendersController_create_v1: 'high',
  DlpExceptionsController_create_v1: 'high',
  AtoSettingsController_update_v1: 'high',
  AtoProvidersController_update_v1: 'high',
  AtoProvidersController_create_v1: 'medium',
  AtoProvidersController_healthCheck_v1: 'low',
  AtoAccountMailboxController_refresh_v1: 'low',
  // Step AI-5 D2 (I22): a new retention policy can take precedence and shorten retention or
  // delete on expiry; a provider health check only queues a read-only probe.
  ArchiveRetentionController_create_v1: 'high',
  ProviderHealthController_checkNow_v1: 'low',
};

export const CONFIRM_OF_RISK: Readonly<Record<ToolRisk, ToolConfirm>> = {
  read: 'none',
  read_audited: 'none',
  low: 'confirm',
  medium: 'confirm+impact',
  high: 'confirm+impact+reauth',
  critical: 'confirm+impact+reauth',
};

function notApplicableReason(facts: OperationFacts): string | null {
  for (const tag of facts.tags) {
    const reason = NOT_APPLICABLE_TAGS[tag];
    if (reason) return reason;
  }
  const { method, path } = facts;
  if (path.startsWith('/platform/overrides')) return NOT_APPLICABLE_REASONS.identity;
  if (facts.returnsSecret) return NOT_APPLICABLE_REASONS.secret;
  if (
    (method === 'GET' && (/\/preview$/.test(path) || /\/downloads\//.test(path))) ||
    /\/download-grants$/.test(path) ||
    /\/reveal$/.test(path) ||
    (method === 'GET' && /\/dlp-evidence$/.test(path))
  )
    return NOT_APPLICABLE_REASONS.content;
  if (/\/credentials$/.test(path) || /\/consent\//.test(path))
    return NOT_APPLICABLE_REASONS.consent;
  if (method === 'GET' && /\/export$/.test(path)) return NOT_APPLICABLE_REASONS.fileExport;
  return null;
}

function writeRisk(facts: OperationFacts): ToolRisk {
  const override = RISK_OVERRIDES[facts.operationId];
  if (override) return override;
  const { method, path } = facts;
  const last = path.split('/').pop() ?? '';
  if (method === 'DELETE') return 'high';
  if (facts.tags.includes('platform')) return 'high';
  if (HIGH_VERBS.has(last)) return 'high';
  if (HIGH_PATHS.some((rule) => (!rule.method || rule.method === method) && rule.path.test(path)))
    return 'high';
  if (OWN_PREFERENCES.test(path)) return 'low';
  if (MEDIUM_VERBS.has(last)) return 'medium';
  if (method === 'PUT') return 'medium';
  return 'low';
}

function readRisk(facts: OperationFacts): ToolRisk {
  const { method, path } = facts;
  if (
    facts.tags.includes('audit') ||
    path.startsWith('/platform/audit/') ||
    (method === 'GET' && /^\/archive\/messages\/\{messageId\}/.test(path)) ||
    /\/hits$/.test(path)
  )
    return 'read_audited';
  return 'read';
}

function modulePhase(facts: OperationFacts): ProgramPhase {
  for (const tag of facts.tags) {
    const phase = MODULE_WRITE_PHASE[tag];
    if (phase) return phase;
  }
  throw new Error(
    `${facts.operationId}: no planned phase for module ${facts.tags.join(',')}; add it to MODULE_WRITE_PHASE`,
  );
}

/** The §4.4 rules for one operation (before per-operation overrides). */
export function classifyOperation(facts: OperationFacts): Classification {
  const access: ToolAccess =
    facts.method === 'GET' || (facts.method === 'POST' && SIDE_EFFECT_FREE_POST.test(facts.path))
      ? 'read'
      : 'write';
  const reason = notApplicableReason(facts);
  if (reason) return { kind: 'not_applicable', reason, access, risk: null };
  if (CRITICAL_OPERATIONS.has(facts.operationId))
    return {
      kind: 'not_applicable',
      reason: NOT_APPLICABLE_REASONS.critical,
      access,
      risk: 'critical',
    };
  const risk = access === 'read' ? readRisk(facts) : writeRisk(facts);
  const phase = facts.method === 'GET' ? 'AI-1' : modulePhase(facts);
  return { kind: 'tool', access, risk, confirm: CONFIRM_OF_RISK[risk], phase };
}

// ---------------------------------------------------------------------------------------------
// Portal pages and deep links (Appendix B)
// ---------------------------------------------------------------------------------------------

/** Portal feature folder → page label used in the capability matrix. */
export const FEATURE_PAGES: Readonly<Record<string, string>> = {
  account: 'Account menu',
  archive: '/archive',
  assistant: '/assistant',
  ato: '/ato',
  attachments: '/attachments',
  audit: '/audit-logs',
  auth: '/login',
  billing: '/billing',
  dashboard: '/dashboard',
  domains: '/domains',
  ediscovery: '/ediscovery, /legal-holds',
  incidents: '/incidents',
  integrations: '/integrations',
  journaling: '/settings (Journaling)',
  'mail-servers': '/mail-servers',
  messages: '/messages',
  organizations: '/organizations',
  policies: '/policies',
  quarantine: '/quarantine',
  reports: '/reports',
  roles: '/roles',
  settings: '/settings',
  'threat-intel': '/threat-intelligence',
  'url-protection': '/url-protection',
  users: '/users',
};

/** Feature folders that are not pages (the app shell). */
export const NON_PAGE_FEATURES: ReadonlySet<string> = new Set(['shell']);

/**
 * Controller → portal deep-link template and the resource type of its rows' refs. Templates are
 * portal routes of Appendix B; `{param}` is filled from the call arguments, then the row's id.
 */
export const CONTROLLER_HINTS: Readonly<
  Record<string, { portalRoute: string; resourceType: string }>
> = {
  ApiKeysController: { portalRoute: '/integrations/api-keys', resourceType: 'api_key' },
  ArchiveAdminController: { portalRoute: '/archive', resourceType: 'archive' },
  ArchiveMessagesController: {
    portalRoute: '/archive/{messageId}',
    resourceType: 'archive_message',
  },
  ArchiveRetentionController: {
    portalRoute: '/archive/retention',
    resourceType: 'retention_policy',
  },
  AtoAccountsController: { portalRoute: '/ato/accounts/{accountId}', resourceType: 'ato_account' },
  AtoAccountMailboxController: {
    portalRoute: '/ato/accounts/{accountId}',
    resourceType: 'ato_account',
  },
  AtoIncidentEvidenceController: {
    portalRoute: '/incidents/{incidentId}',
    resourceType: 'ato_signal',
  },
  AtoOverviewController: { portalRoute: '/ato', resourceType: 'ato_account' },
  AtoProvidersController: {
    portalRoute: '/ato/providers/{integrationId}',
    resourceType: 'ato_provider',
  },
  AtoResponsesController: { portalRoute: '/ato/responses', resourceType: 'ato_response' },
  AtoRestrictionsController: { portalRoute: '/ato/responses', resourceType: 'ato_restriction' },
  AtoRulesController: { portalRoute: '/ato/settings', resourceType: 'ato_rule' },
  AtoSettingsController: { portalRoute: '/ato/settings', resourceType: 'ato_settings' },
  AttachmentsController: { portalRoute: '/attachments', resourceType: 'attachment' },
  AttachmentRescansController: { portalRoute: '/attachments', resourceType: 'attachment_rescan' },
  AuditLogsController: { portalRoute: '/audit-logs', resourceType: 'audit_log' },
  BecExecutivesController: { portalRoute: '/policies', resourceType: 'bec_executive' },
  BecFeedbackController: { portalRoute: '/policies', resourceType: 'bec_feedback' },
  BecMessageFeedbackController: {
    portalRoute: '/messages/{messageId}',
    resourceType: 'bec_feedback',
  },
  BecTrustedSendersController: { portalRoute: '/policies', resourceType: 'bec_trusted_sender' },
  BecVendorsController: { portalRoute: '/policies', resourceType: 'bec_vendor' },
  BillingController: { portalRoute: '/billing', resourceType: 'billing' },
  DeadLettersController: { portalRoute: '/organizations', resourceType: 'dead_letter_queue' },
  DeliveriesController: { portalRoute: '/messages/{messageId}', resourceType: 'delivery' },
  DepartmentsController: { portalRoute: '/users', resourceType: 'department' },
  DestinationProvidersController: { portalRoute: '/domains', resourceType: 'destination_provider' },
  DlpComplianceController: { portalRoute: '/policies', resourceType: 'dlp_compliance' },
  DlpDictionariesController: { portalRoute: '/policies', resourceType: 'dlp_dictionary' },
  DlpExceptionsController: { portalRoute: '/policies', resourceType: 'dlp_exception' },
  DlpIncidentsController: { portalRoute: '/policies', resourceType: 'dlp_incident' },
  DlpPatternsController: { portalRoute: '/policies', resourceType: 'dlp_pattern' },
  DlpPoliciesController: { portalRoute: '/policies', resourceType: 'dlp_policy' },
  DomainsController: { portalRoute: '/domains/{domainId}', resourceType: 'domain' },
  DomainDestinationsController: { portalRoute: '/domains/{domainId}', resourceType: 'domain' },
  DomainDnsController: { portalRoute: '/domains/{domainId}', resourceType: 'domain' },
  DomainRecipientsController: { portalRoute: '/domains/{domainId}', resourceType: 'domain' },
  EdiscoveryCasesController: {
    portalRoute: '/ediscovery/{caseId}',
    resourceType: 'ediscovery_case',
  },
  EdiscoveryExportsController: {
    portalRoute: '/ediscovery/{caseId}',
    resourceType: 'ediscovery_export',
  },
  EdiscoverySearchesController: {
    portalRoute: '/ediscovery/{caseId}/searches/{searchId}',
    resourceType: 'ediscovery_search',
  },
  IncidentsController: { portalRoute: '/incidents/{incidentId}', resourceType: 'incident' },
  IntakeSourcesController: {
    portalRoute: '/settings/journaling/intake/{sourceId}',
    resourceType: 'intake_source',
  },
  JournalingController: { portalRoute: '/settings', resourceType: 'journaling' },
  LegalHoldsController: { portalRoute: '/legal-holds/{holdId}', resourceType: 'legal_hold' },
  LoginEventsController: { portalRoute: '/audit-logs', resourceType: 'login_event' },
  MessagesController: { portalRoute: '/messages/{messageId}', resourceType: 'message' },
  MessageHeadersController: { portalRoute: '/messages/{messageId}', resourceType: 'message' },
  MessageLifecycleController: { portalRoute: '/messages/{messageId}', resourceType: 'message' },
  MessageScansController: {
    portalRoute: '/messages/{messageId}/scans',
    resourceType: 'message_scan',
  },
  NotificationsController: { portalRoute: '/settings', resourceType: 'notification_settings' },
  OrganizationsController: {
    portalRoute: '/organizations/{organizationId}',
    resourceType: 'organization',
  },
  OrganizationConfigurationController: {
    portalRoute: '/organizations/{organizationId}',
    resourceType: 'organization',
  },
  OrganizationDeletionController: {
    portalRoute: '/organizations/{organizationId}',
    resourceType: 'organization',
  },
  PermissionsController: { portalRoute: '/roles', resourceType: 'permission' },
  PlatformAuditLogsController: { portalRoute: '/audit-logs', resourceType: 'audit_log' },
  PolicyManagementController: { portalRoute: '/policies/{policyId}', resourceType: 'policy' },
  PolicyMessagesController: {
    portalRoute: '/messages/{messageId}',
    resourceType: 'policy_evaluation',
  },
  PolicySettingsController: { portalRoute: '/policies', resourceType: 'policy_settings' },
  PolicyToolsController: { portalRoute: '/policies', resourceType: 'policy_execution' },
  ProviderAttestationsController: {
    portalRoute: '/integrations/providers/{connectionId}',
    resourceType: 'provider_connection',
  },
  ProviderCatalogController: {
    portalRoute: '/integrations/providers/new',
    resourceType: 'provider',
  },
  ProviderConnectionsController: {
    portalRoute: '/integrations/providers/{connectionId}',
    resourceType: 'provider_connection',
  },
  ProviderDomainsController: {
    portalRoute: '/integrations/providers/{connectionId}',
    resourceType: 'provider_connection',
  },
  ProviderGrantsController: {
    portalRoute: '/integrations/providers/{connectionId}',
    resourceType: 'provider_connection',
  },
  ProviderGuideController: {
    portalRoute: '/integrations/providers/{connectionId}',
    resourceType: 'provider_connection',
  },
  ProviderHealthController: {
    portalRoute: '/integrations/providers/{connectionId}',
    resourceType: 'provider_connection',
  },
  ProviderMailFlowController: {
    portalRoute: '/integrations/providers/{connectionId}',
    resourceType: 'provider_connection',
  },
  ProviderValidationsController: {
    portalRoute: '/integrations/providers/{connectionId}',
    resourceType: 'provider_validation',
  },
  QuarantineApprovalsController: {
    portalRoute: '/quarantine/approvals/{approvalId}',
    resourceType: 'quarantine_approval',
  },
  QuarantineEntriesController: {
    portalRoute: '/quarantine/{entryId}',
    resourceType: 'quarantine_entry',
  },
  QuarantineSelfController: {
    portalRoute: '/quarantine/me/{entryId}',
    resourceType: 'quarantine_entry',
  },
  QuarantineToolsController: { portalRoute: '/quarantine', resourceType: 'quarantine' },
  RecipientSuppressionsController: {
    portalRoute: '/mail-servers',
    resourceType: 'recipient_suppression',
  },
  ReportsController: { portalRoute: '/reports', resourceType: 'report' },
  RiskDryRunController: {
    portalRoute: '/messages/{messageId}/scans',
    resourceType: 'risk_dry_run',
  },
  RiskProfilesController: {
    portalRoute: '/policies/risk-profile/{versionId}',
    resourceType: 'risk_profile_version',
  },
  RolesController: { portalRoute: '/roles/{roleKey}', resourceType: 'role' },
  SavedViewsController: { portalRoute: '/messages', resourceType: 'saved_view' },
  ScanSettingsController: { portalRoute: '/policies', resourceType: 'scan_settings' },
  ScanTrainingController: { portalRoute: '/messages/{messageId}', resourceType: 'scan_training' },
  SmtpConnectorsController: { portalRoute: '/mail-servers', resourceType: 'smtp_connector' },
  ThreatHashesController: { portalRoute: '/threat-intelligence', resourceType: 'threat_hash' },
  ThreatIndicatorsController: {
    portalRoute: '/threat-intelligence',
    resourceType: 'threat_indicator',
  },
  ThreatIntelligenceController: {
    portalRoute: '/threat-intelligence',
    resourceType: 'threat_lookup',
  },
  UrlProtectionController: { portalRoute: '/url-protection', resourceType: 'url' },
  UsageController: { portalRoute: '/dashboard', resourceType: 'usage' },
  UsersController: { portalRoute: '/users/{userId}', resourceType: 'user' },
  WebhooksController: { portalRoute: '/webhooks/{webhookId}', resourceType: 'webhook' },
  WebhookDeliveriesController: {
    portalRoute: '/webhooks/{webhookId}',
    resourceType: 'webhook_delivery',
  },
};

// ---------------------------------------------------------------------------------------------
// Per-operation overrides
// ---------------------------------------------------------------------------------------------

/** Organization reads bind `{id}` to the caller's own organization when the model omits it. */
const SELF_ORGANIZATION = { id: 'self_organization' } as const;

const columns = (...names: string[]): DisplayHints => ({ columns: names });

/** DNS data of a domain's check results (`GET /domains/{id}/status`, `POST /domains/{id}/verify`). */
const DNS_STATUS_UNTRUSTED = [
  'checks.mx.observed',
  'checks.mx.propagation',
  ...['ownership', 'mx', 'spf', 'dkim', 'dmarc'].map((check) => `checks.${check}.warnings`),
];

/**
 * Per-operation overrides: display hints, mail-derived `untrustedFields` (response paths; `[]`
 * marks array items; every string under a listed path is wrapped as `untrusted_text`), bindings
 * and the few deep links that differ from the controller's. The generator adds every free-form
 * response path (objects without declared properties, maps, untyped values: evidence, detail,
 * metadata, criteria, params) that the list does not cover (`freeFormResponsePaths`), so only
 * typed strings need listing here.
 */
const BASE_OVERRIDES: Readonly<Record<string, OperationOverride>> = {
  // --- messages and their evidence (mail-derived strings) ---
  MessagesController_list_v1: {
    display: columns('receivedAt', 'direction', 'subject', 'headerFrom', 'status', 'finalVerdict'),
    untrustedFields: ['data[].subject', 'data[].envelopeFrom', 'data[].headerFrom'],
  },
  MessagesController_detail_v1: {
    untrustedFields: [
      'subject',
      'envelopeFrom',
      'headerFrom',
      'internetMessageId',
      'clientHelo',
      'statusReason',
    ],
  },
  MessagesController_recipients_v1: { untrustedFields: ['data[].address'] },
  MessageHeadersController_headers_v1: { untrustedFields: ['headers[].name', 'headers[].value'] },
  MessageScansController_scansOf_v1: {
    untrustedFields: [
      'data[].auth.spfDomain',
      'data[].auth.dkimSignatures[].domain',
      'data[].auth.dmarcDomain',
      'data[].engines[].attachments[].filename',
      'data[].engines[].attachments[].archive.findings[].path',
      'data[].engines[].urls[].url',
      'data[].engines[].urls[].host',
      'data[].engines[].urls[].unicodeHost',
      'data[].engines[].urls[].registrableDomain',
      'data[].engines[].urls[].fetch',
      'data[].engines[].bec.rules[].evidence',
      'data[].engines[].dlp.coverageDetail[].path',
      'data[].engines[].dlp.findings[].sources[].path',
      'data[].policy.delivery.headers[].value',
    ],
  },
  DeliveriesController_list_v1: {
    display: { linkField: 'messageId' },
    untrustedFields: ['data[].recipient'],
  },
  DeliveriesController_forMessage_v1: {
    untrustedFields: [
      'deliveries[].recipient',
      'deliveries[].remoteHost',
      'deliveries[].finalSmtpResponse',
      'deliveries[].failureReason',
    ],
  },
  DeliveriesController_events_v1: { untrustedFields: ['data[].remoteHost', 'data[].detail'] },
  PolicyMessagesController_evaluations_v1: {
    untrustedFields: ['data[].delivery.headers[].value'],
  },
  AttachmentsController_search_v1: {
    display: columns('filename', 'detectedContentType', 'sizeBytes', 'verdict'),
    untrustedFields: ['data[].filename'],
  },
  AttachmentsController_ofMessage_v1: {
    untrustedFields: ['data[].filename', 'data[].latestScan.archive.findings[].path'],
  },
  UrlProtectionController_ofMessage_v1: {
    untrustedFields: [
      'data[].url',
      'data[].host',
      'data[].unicodeHost',
      'data[].registrableDomain',
    ],
  },
  UrlProtectionController_clicks_v1: {
    untrustedFields: ['data[].host', 'data[].registrableDomain'],
  },

  // --- quarantine ---
  QuarantineEntriesController_search_v1: {
    display: columns('quarantinedAt', 'subject', 'sender', 'recipient', 'reason', 'state'),
    untrustedFields: ['items[].subject', 'items[].sender', 'items[].recipient'],
  },
  QuarantineEntriesController_detail_v1: {
    untrustedFields: ['subject', 'sender', 'recipient'],
  },
  QuarantineSelfController_search_v1: {
    display: columns('quarantinedAt', 'subject', 'sender', 'reason', 'state'),
    untrustedFields: ['items[].subject', 'items[].sender', 'items[].recipient'],
  },
  QuarantineSelfController_detail_v1: { untrustedFields: ['subject', 'sender', 'recipient'] },

  // --- archive and eDiscovery ---
  ArchiveMessagesController_list_v1: {
    display: { ...columns('receivedAt', 'subject', 'headerFrom', 'status'), refField: 'messageId' },
    untrustedFields: [
      'data[].subject',
      'data[].envelopeFrom',
      'data[].headerFrom',
      'data[].recipients',
      'data[].attachmentNames',
    ],
  },
  ArchiveMessagesController_detail_v1: {
    untrustedFields: [
      'subject',
      'envelopeFrom',
      'headerFrom',
      'internetMessageId',
      'parties',
      'attachmentNames',
    ],
  },
  ArchiveMessagesController_journal_v1: {
    untrustedFields: [
      'message.internetMessageId',
      'message.envelopeFrom',
      'message.headerFrom',
      'message.subject',
      'message.clientHelo',
      'envelope.recipients[].address',
      'intake.envelope',
      'headers[].name',
      'headers[].value',
      'attachments[].fileName',
    ],
  },
  EdiscoverySearchesController_hits_v1: {
    display: { refField: 'messageId', resourceType: 'archive_message' },
    portalRoute: '/archive/{messageId}',
    untrustedFields: [
      'data[].message.subject',
      'data[].message.envelopeFrom',
      'data[].message.headerFrom',
      'data[].message.recipients',
      'data[].message.attachmentNames',
    ],
  },

  // --- incidents and ATO ---
  IncidentsController_list_v1: {
    display: columns('detectedAt', 'category', 'severity', 'status', 'titleCode'),
    untrustedFields: ['data[].subject.display'],
  },
  // Incident evidence/detail are detector output over mail and sign-ins; notes are free text.
  IncidentsController_get_v1: {
    untrustedFields: ['subject.display', 'evidence', 'detail', 'resolution.note'],
  },
  IncidentsController_report_v1: {
    untrustedFields: [
      'incident',
      'timeline',
      'evidence',
      'resolution.note',
      'notes[].note',
      'messages[].senderMasked',
    ],
  },
  IncidentsController_timeline_v1: { untrustedFields: ['data[].details', 'data[].note'] },
  AtoAccountsController_list_v1: {
    display: columns('address', 'displayName', 'riskLevel', 'riskScore', 'status'),
    untrustedFields: ['data[].address', 'data[].displayName'],
  },
  AtoAccountsController_get_v1: {
    untrustedFields: ['address', 'displayName', 'identities[].userPrincipalName'],
  },
  AtoAccountsController_authEvents_v1: {
    untrustedFields: ['data[].device.label', 'data[].asnOrg'],
  },
  AtoIncidentEvidenceController_authEvents_v1: {
    untrustedFields: ['data[].device.label', 'data[].asnOrg'],
  },
  AtoAccountsController_activity_v1: {
    untrustedFields: ['days[].topRecipientDomains[].domain'],
  },
  // Signal evidence carries the sign-in's device label (user agent) and ASN organization, and
  // the explanation is rendered from that evidence: both attacker-influenced (`evidence` is
  // free-form and would be untrusted by default; listed explicitly for the record).
  AtoAccountsController_signals_v1: {
    untrustedFields: ['data[].evidence', 'data[].explanation'],
  },
  AtoIncidentEvidenceController_signals_v1: {
    portalRoute: '/incidents/{incidentId}',
    untrustedFields: ['data[].evidence', 'data[].explanation'],
  },
  AtoAccountsController_scoreHistory_v1: { untrustedFields: ['data[].explanation'] },

  // --- audit ---
  AuditLogsController_search_v1: {
    display: columns('occurredAt', 'action', 'resourceType', 'resourceId', 'actor'),
    untrustedFields: ['data[].metadata'],
  },
  PlatformAuditLogsController_search_v1: {
    display: columns('occurredAt', 'action', 'resourceType', 'resourceId', 'actor'),
    untrustedFields: ['data[].metadata'],
  },
  LoginEventsController_list_v1: {
    untrustedFields: ['data[].email', 'data[].userAgent'],
  },

  // --- policy writes (step AI-2): the created policy is row ref r<seq>.1 ("publish it") ---
  PolicyManagementController_create_v1: { display: { refField: 'policy.id' } },

  // --- administration lists (display hints) ---
  PolicyManagementController_list_v1: {
    display: columns('name', 'status', 'direction', 'priority', 'activeVersionNo'),
  },
  DomainsController_list_v1: { display: columns('name', 'status', 'verifiedAt') },
  RolesController_list_v1: { display: { columns: ['key', 'name', 'system'], refField: 'key' } },
  RolesController_get_v1: { display: { refField: 'key' } },

  // --- identity and tenant administration (step AI-3 D9): attacker-influenced strings ---
  // A user may set their own display name; a session's user agent is sent by the client.
  UsersController_list_v1: {
    display: columns('email', 'displayName', 'status', 'roles'),
    untrustedFields: ['data[].displayName'],
  },
  UsersController_get_v1: { untrustedFields: ['displayName'] },
  UsersController_listSessions_v1: { untrustedFields: ['data[].userAgent'] },
  // Members have an address (kind `address`) or a user id; the response has no display name.
  DepartmentsController_listMembers_v1: { untrustedFields: ['data[].address'] },
  // The remote webhook server's answer.
  WebhookDeliveriesController_get_v1: {
    untrustedFields: ['attempts[].responseSnippet', 'attempts[].errorCode', 'lastError'],
  },
  WebhookDeliveriesController_list_v1: { untrustedFields: ['data[].lastError'] },
  // The domain owner's DNS (observed records, resolver warnings that echo record values).
  DomainDnsController_status_v1: { untrustedFields: DNS_STATUS_UNTRUSTED },
  DomainDnsController_verify_v1: { untrustedFields: DNS_STATUS_UNTRUSTED },
  DomainDnsController_dnsRecords_v1: {
    untrustedFields: ['records[].observedValue', 'records[].lastError', 'records[].warnings'],
  },
  DomainsController_get_v1: { untrustedFields: ['verification.lastError'] },
  DomainsController_create_v1: {
    untrustedFields: [
      'verification.lastError',
      'dnsRecords[].observedValue',
      'dnsRecords[].lastError',
      'dnsRecords[].warnings',
    ],
  },

  // --- identity and tenant administration writes (step AI-3) ---
  // Write responses that return the user view carry the same display name.
  UsersController_invite_v1: { untrustedFields: ['displayName'] },
  UsersController_update_v1: { untrustedFields: ['displayName'] },
  UsersController_changeStatus_v1: { untrustedFields: ['displayName'] },
  UsersController_replaceRoles_v1: { untrustedFields: ['displayName'] },
  // The created role is row ref r<seq>.1 by its key.
  RolesController_create_v1: { display: { refField: 'key' } },
  // Sends an event to the tenant's external URL: a low write with a confirmation (D2, A3-3).
  WebhooksController_test_v1: { access: 'write', risk: 'low' },
  // The read a revocation card needs (D8); covered by the read sweep.
  ApiKeysController_get_v1: { phase: 'AI-3' },
  // Customer-reachable organization writes bind {id} to the caller's own organization; the
  // platform-only ones (deletion cancel, feature and limit overrides) always name it.
  OrganizationsController_update_v1: { bind: SELF_ORGANIZATION },
  OrganizationConfigurationController_updateSettings_v1: { bind: SELF_ORGANIZATION },

  // --- security operations (step AI-4 D7, D8, D9) ---
  // Another user's or an API key's free text (request, decision and rollback reasons).
  AtoResponsesController_get_v1: {
    untrustedFields: ['requestReason', 'decisionReason', 'rollbackReason', 'params.description'],
  },
  AtoResponsesController_list_v1: {
    untrustedFields: [
      'data[].requestReason',
      'data[].decisionReason',
      'data[].rollbackReason',
      'data[].params.description',
    ],
  },
  // Provider-reported mailbox state: forwarding target domains and directory principal names.
  AtoAccountMailboxController_get_v1: {
    untrustedFields: ['items[].targetDomain', 'identities[].userPrincipalName'],
  },
  // The explanation is rendered from engine evidence over the message (free-form params too).
  RiskDryRunController_dryRun_v1: {
    untrustedFields: [
      'result.explanation.text',
      'result.explanation.lines[].params',
      'result.evidence.unmappedCodes',
    ],
  },
  // The four single reads the confirmation cards need (D8).
  BecTrustedSendersController_get_v1: { phase: 'AI-4' },
  BecFeedbackController_getSuppression_v1: { phase: 'AI-4', untrustedFields: ['senderValue'] },
  DlpExceptionsController_get_v1: { phase: 'AI-4' },
  ThreatIndicatorsController_get_v1: { phase: 'AI-4', untrustedFields: ['value'] },
  // The api never logs, audits or echoes the sample and the pattern (D9).
  DlpPatternsController_test_v1: { redactParams: ['body.sample', 'body.pattern'] },
  // The created hash is row ref r<seq>.1 by its SHA-256 (it has no other id).
  ThreatHashesController_add_v1: { display: { refField: 'sha256' } },

  // --- compliance and integrations (step AI-5 D7, D8, D10) ---
  // Tenant-authored free text: retention policy, case and hold names and descriptions, intake
  // source and provider connection display names; the provider-reported tenant name.
  ArchiveRetentionController_list_v1: {
    display: columns('name', 'retentionDays', 'onExpiry', 'priority', 'isDefault'),
    untrustedFields: ['data[].name'],
  },
  ArchiveRetentionController_get_v1: { untrustedFields: ['name'] },
  ArchiveRetentionController_create_v1: { untrustedFields: ['name'] },
  ArchiveRetentionController_update_v1: { untrustedFields: ['name'] },
  // The single read the capture-retry card needs (D8); covered by the read sweep.
  ArchiveAdminController_captureIssue_v1: { phase: 'AI-5', display: { refField: 'messageId' } },
  EdiscoveryCasesController_list_v1: {
    display: columns('name', 'status', 'matterReference', 'createdAt'),
    untrustedFields: ['data[].name', 'data[].description', 'data[].matterReference'],
  },
  EdiscoveryCasesController_get_v1: { untrustedFields: ['name', 'description', 'matterReference'] },
  EdiscoveryCasesController_create_v1: {
    untrustedFields: ['name', 'description', 'matterReference'],
  },
  EdiscoveryCasesController_update_v1: {
    untrustedFields: ['name', 'description', 'matterReference'],
  },
  EdiscoveryCasesController_close_v1: {
    untrustedFields: ['name', 'description', 'matterReference'],
  },
  EdiscoveryCasesController_createHold_v1: { untrustedFields: ['name', 'reason'] },
  LegalHoldsController_list_v1: {
    display: columns('name', 'status', 'caseId', 'createdAt'),
    untrustedFields: ['data[].name', 'data[].reason', 'data[].releaseReason'],
  },
  LegalHoldsController_get_v1: { untrustedFields: ['name', 'reason', 'releaseReason'] },
  IntakeSourcesController_list_v1: {
    display: columns('displayName', 'kind', 'status', 'requireTls'),
    untrustedFields: ['data[].displayName'],
  },
  // The intake address is the source's credential: never revealed through chat (I23, A5-5).
  IntakeSourcesController_get_v1: {
    description:
      'The source with its health and the counters of the last 7 UTC days (accepted, duplicates, bytes, refusals by reason, proof drops, unwrap failures). The intake address and the Google header token are always masked here; showing them in clear is done only in the portal.',
    untrustedFields: ['displayName'],
    omitInputs: ['reveal'],
  },
  IntakeSourcesController_update_v1: { untrustedFields: ['displayName'] },
  IntakeSourcesController_disable_v1: { untrustedFields: ['displayName'] },
  ProviderConnectionsController_list_v1: {
    display: columns('displayName', 'provider', 'status', 'health', 'domainCount'),
    untrustedFields: ['data[].displayName', 'data[].tenantName'],
  },
  ProviderConnectionsController_get_v1: { untrustedFields: ['displayName', 'tenantName'] },
  ProviderConnectionsController_create_v1: { untrustedFields: ['displayName', 'tenantName'] },
  ProviderConnectionsController_update_v1: { untrustedFields: ['displayName', 'tenantName'] },
  ProviderConnectionsController_disconnect_v1: {
    description:
      'Disconnects the provider connection: grants are revoked and their credentials wiped, outbound and internal routing stop, inbound destinations are kept. Pass only `id`; the server previews the disconnect and fills `impactToken` and `confirm`.',
    untrustedFields: ['connection.displayName', 'connection.tenantName'],
  },
  ProviderConnectionsController_wizard_v1: {
    description:
      'The setup wizard of a provider connection: six steps with their status and blockers. Use `nextAction` to guide the setup; steps `connect` (grants, credentials, consent) and `validate` are done in the portal.',
  },
  ProviderMailFlowController_apply_v1: {
    description:
      'Applies a mail-flow change of the connection (`inbound`, `outbound`, `activate`, `proof`, `suspend`, `disable_outbound`). `impactToken` and `confirm` are filled by the server from a fresh preview; pass only `change`.',
    untrustedFields: ['connection.displayName', 'connection.tenantName'],
  },
  // The Google delegation confirmation is part of the consent ceremony (portal only, A5-4).
  ProviderGrantsController_verify_v1: { omitInputs: ['body.subjectEmail'] },

  // --- own organization (bind {id}) ---
  OrganizationsController_get_v1: { bind: SELF_ORGANIZATION },
  OrganizationsController_getUsage_v1: { bind: SELF_ORGANIZATION },
  OrganizationDeletionController_get_v1: { bind: SELF_ORGANIZATION },
  OrganizationConfigurationController_listFeatures_v1: { bind: SELF_ORGANIZATION },
  OrganizationConfigurationController_listLimits_v1: { bind: SELF_ORGANIZATION },
  OrganizationConfigurationController_getSettings_v1: { bind: SELF_ORGANIZATION },
};

/** The overrides with the AI-2, AI-3, AI-4 and AI-5 writes' `testedBy` merged in. */
export const OPERATION_OVERRIDES: Readonly<Record<string, OperationOverride>> = (() => {
  const out: Record<string, OperationOverride> = { ...BASE_OVERRIDES };
  for (const [operationId, testedBy] of Object.entries({
    ...AI2_WRITES_TESTED_BY,
    ...AI3_WRITES_TESTED_BY,
    ...AI4_WRITES_TESTED_BY,
    ...AI5_WRITES_TESTED_BY,
  }))
    out[operationId] = { ...out[operationId], testedBy };
  return out;
})();
