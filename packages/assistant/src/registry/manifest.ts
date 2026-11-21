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
 * a `testedBy` suite and a confirmation spec, step AI-2).
 */
export const ASSISTANT_PROGRAM_PHASE: ProgramPhase = 'AI-2';

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

/** Explicit risk overrides named by §4.4. */
export const RISK_OVERRIDES: Readonly<Record<string, ToolRisk>> = {
  SavedViewsController_remove_v1: 'low',
  NotificationsController_putPreferences_v1: 'low',
  QuarantineSelfController_putPreferences_v1: 'low',
  UsersController_invite_v1: 'medium',
  UsersController_resendInvitation_v1: 'medium',
  DepartmentsController_removeMember_v1: 'medium',
  BecFeedbackController_deleteSuppression_v1: 'medium',
  WebhookDeliveriesController_replay_v1: 'medium',
  DomainsController_create_v1: 'medium',
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
  UsersController_list_v1: { display: columns('email', 'displayName', 'status', 'roles') },
  DomainsController_list_v1: { display: columns('name', 'status', 'verifiedAt') },
  RolesController_list_v1: { display: { columns: ['key', 'name', 'system'], refField: 'key' } },
  RolesController_get_v1: { display: { refField: 'key' } },

  // --- own organization (bind {id}) ---
  OrganizationsController_get_v1: { bind: SELF_ORGANIZATION },
  OrganizationsController_getUsage_v1: { bind: SELF_ORGANIZATION },
  OrganizationDeletionController_get_v1: { bind: SELF_ORGANIZATION },
  OrganizationConfigurationController_listFeatures_v1: { bind: SELF_ORGANIZATION },
  OrganizationConfigurationController_listLimits_v1: { bind: SELF_ORGANIZATION },
  OrganizationConfigurationController_getSettings_v1: { bind: SELF_ORGANIZATION },
};

/** The overrides with the AI-2 writes' `testedBy` merged in. */
export const OPERATION_OVERRIDES: Readonly<Record<string, OperationOverride>> = (() => {
  const out: Record<string, OperationOverride> = { ...BASE_OVERRIDES };
  for (const [operationId, testedBy] of Object.entries(AI2_WRITES_TESTED_BY))
    out[operationId] = { ...out[operationId], testedBy };
  return out;
})();
