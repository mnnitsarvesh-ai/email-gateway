/**
 * Route inventory of step 6.1 (docs/plan/steps/18-rest-api.md §9 "Route inventory", D3, D7, D9,
 * D13, D14, §3.5, §3.8): every route the running api serves (Nest discovery on the stubbed
 * AppModule) is checked against the conventions, so a route added later without its
 * authorization, documentation, tests, cursor encoding, strict schemas or idempotency metadata
 * fails here. The checks:
 *
 * 1. boundary — under `/api/v1`, or one of the three internal endpoints (D13);
 * 2. authorization — a documented `@Public()` route, a permission requirement, or an explicit
 *    `@AuthenticatedOnly()` self-service route (D7);
 * 3. OpenAPI — an operation with a tag, a summary, a security requirement (non-public), the
 *    standard error responses, a request body schema when the handler takes a body, a 2xx schema
 *    unless 204, and explicit examples on the routes new in 6.1 (D14);
 * 4. coverage — an entry in test/route-coverage (§3.8) whose e2e, integration and cross-tenant
 *    files exist and carry `@covers <method> <path>`; the manifests name no route that does not
 *    exist;
 * 5. lists — a route whose 2xx body has `nextCursor` declares `@CursorList`, the manifest agrees,
 *    and every list new in 6.1 is `v1` (D3);
 * 6. strict request schemas — every body and query schema rejects unknown fields (D1);
 * 7. sensitive mutations — every §3.5 route has idempotency metadata and the `sensitive` class;
 *    no route is both `@Idempotent()` and `@ReturnsSecret()` (D9, D10); a `@ReturnsSecret()`
 *    route takes an Idempotency-Key only when it is one of the two step 6.2 webhook secret
 *    routes and declares the redacted replay (ADR-0057).
 *
 * Step 6.2 (docs/plan/steps/19-webhooks-notifications.md §6.2) adds the 17 webhook and
 * notification routes (`NEW_IN_6_2`, examples required, lists v1), five transactional keyed
 * routes and the `SECRET_BEARING_REDACTED_REPLAY` allow-list. Step 7.1
 * (docs/plan/steps/20-admin-portal.md §3.3) adds three expensive report routes (`NEW_IN_7_1`).
 * Step 7.2 (docs/plan/steps/21-email-explorer-details.md §3.3) adds the five saved views routes
 * (WP1) and the headers route and the two audited reveal operations (WP2) (`NEW_IN_7_2`,
 * examples required, the list v1, in the explorer manifest). Step 7.3
 * (docs/plan/steps/22-policy-builder.md §4.4) adds policy validation and the sample dry-run
 * (`NEW_IN_7_3`, examples required, the policy-builder manifest; the sample dry-run is
 * `expensive`). Step 8.1 (docs/plan/steps/23-journaling-archiving.md §4.4) adds the 41 archive,
 * legal hold and eDiscovery operations (`NEW_IN_8_1`, examples required, every list v1, the
 * archive manifest): 15 transactional keyed mutations (13 `sensitive`, the case search and
 * export requests `expensive`), the expensive archive search. Step 8.4
 * (docs/plan/steps/24-account-takeover-core.md §5) adds the 26 account takeover and 8 security
 * incident operations (`NEW_IN_8_4`, examples required, every list v1, the ato and incidents
 * manifests): 14 transactional keyed mutations (`sensitive`), the expensive overview and report.
 * Step 8.2 (docs/plan/steps/25-m365-google-connectors.md §5.2) adds the 24 Microsoft 365 and
 * Google Workspace connection operations (`NEW_IN_8_2`, examples required, both lists v1, the
 * provider-connections manifest): 12 transactional keyed mutations — the grant, consent and
 * disconnect mutations `sensitive` (D17; grant creation and validation creation are ADR-0057
 * redacted-replay secret-bearing routes: the consent URL and the probe address), the other five
 * keyed without a class (`KEYED_8_2`; the apply and the per-connection routes have their own
 * limits). Step 8.5 (docs/plan/steps/26-ato-provider-adapters.md §6) adds the 13 identity-provider
 * and mailbox state operations (`NEW_IN_8_5`, examples required, no paged list, the ato-providers
 * manifest): 8 transactional keyed mutations (`sensitive`). Step 8.6 adds the 12 journaling
 * operations (`NEW_IN_8_6`). Step AI-1 (docs/plan/steps/28-ai-chat-management.md §4.1) adds the 15
 * assistant operations (`NEW_IN_AI_1`, examples required, both lists v1, the assistant manifest):
 * no keyed route, the settings update `sensitive` (`SENSITIVE_UNKEYED_AI_1`), turns and "more"
 * pages `expensive`. Step AI-2 (docs/plan/steps/29-ai-chat-confirmations-mail-writes.md §4.1) adds
 * the 3 confirmation routes (`NEW_IN_AI_2`, examples required, the assistant manifest): confirm
 * and cancel `sensitive` without an Idempotency-Key (`SENSITIVE_UNKEYED_AI_2`: single use is the
 * confirmation row's atomic transition). Step AI-R (docs/plan/steps/31-ai-chat-reports.md §4.1)
 * adds the report read (`NEW_IN_AI_R`, example required, the assistant manifest). Step AI-4
 * (docs/plan/steps/32-ai-chat-security-operations.md D8) adds four single-item reads of existing
 * modules (`NEW_IN_AI_4`, examples required, in the legacy manifest next to their lists). Step
 * AI-5 (docs/plan/steps/33-ai-chat-compliance-integrations.md D8) adds the capture-issue read
 * (`NEW_IN_AI_5`, example required, in the archive manifest next to its list). Step AI-6
 * (docs/plan/steps/34-ai-chat-hardening-operations.md §4.1) adds the 11 hardening operations
 * (`NEW_IN_AI_6`, examples required, the assistant manifest): the three tenant-key routes
 * `sensitive` without an Idempotency-Key (`SENSITIVE_UNKEYED_AI_6`: CAS on the settings
 * `rowVersion`, validate changes a status only), the content search `expensive` and a v1 list,
 * and the four admin/audit lists v1. Step API-1 (docs/plan/steps/35-api-mode-protection.md D12)
 * adds 16 operations (`NEW_IN_API_1`, examples required, the api-mode manifest): five keyed
 * `sensitive` mutations, two v1 lists (mailboxes, detections) and the two public Graph callbacks
 * (`PROVIDER_CALLBACKS`: documented public routes, an empty `202`, a deliberately non-strict body).
 */
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ROUTE_ARGS_METADATA } from '@nestjs/common/constants';
import { RouteParamtypes } from '@nestjs/common/enums/route-paramtypes.enum';
import { DiscoveryService } from '@nestjs/core';
import { graphNotificationSchema } from '@email-gateway/mailbox-api';
import type { OpenAPIObject } from '@nestjs/swagger';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { z } from 'zod';
import { buildOpenApiDocument } from '../src/http/openapi';
import { TRANSACTIONAL_IDEMPOTENCY_KEY } from '../src/modules/messages/api-docs';
import { LifecycleOperationBodySchema } from '../src/modules/messages/dto/messages.schemas';
import { BulkBodySchema } from '../src/modules/quarantine/dto/quarantine.schemas';
import { SettingsUpdateBodySchema } from '../src/modules/notifications/notifications.schemas';
import { CreateSuppressionBodySchema } from '../src/modules/recipients/recipient-suppressions.schemas';
import {
  CreateReplayBodySchema,
  CreateWebhookBodySchema,
  RotateSecretBodySchema,
} from '../src/modules/webhooks/webhooks.schemas';
import {
  ApplyBodySchema,
  AttestationBodySchema,
  CompleteConsentBodySchema,
  CreateConnectionBodySchema,
  CreateGrantBodySchema,
  CreateValidationBodySchema,
  DisconnectBodySchema,
  ReplaceDomainsBodySchema,
  SetCredentialsBodySchema,
  VerifyGrantBodySchema,
} from '../src/modules/provider-connections/dto/provider-connections.schemas';
import {
  AttestationBodySchema as IntakeAttestationBodySchema,
  CreateIntakeSourceBodySchema,
  UpdateIntakeSourceBodySchema,
} from '../src/modules/journaling/dto/journaling.schemas';
import {
  PutDomainModeBodySchema,
  PutOrganizationModeBodySchema,
  UpdateSettingsBodySchema,
} from '../src/modules/api-mode/dto/api-mode.schemas';
import {
  PutRemediationPolicyBodySchema,
  RemediateBodySchema,
  RestoreBodySchema,
} from '../src/modules/api-mode/dto/api-mode-remediation.schemas';
import {
  AddReportMailboxBodySchema,
  CreateClawbackBodySchema,
  DecisionBodySchema,
  PutOrgSettingsBodySchema,
  ReasonBodySchema,
  ReportClawbackBodySchema,
  SetReportMailboxBodySchema,
  SubmitClawbackBodySchema,
  TriageBodySchema,
} from '../src/modules/api-mode/dto/api-mode-clawback.schemas';
import { PutDomainScopeBodySchema } from '../src/modules/api-mode/dto/api-mode-onboarding.schemas';
import { ProviderOwnershipCheckBodySchema } from '../src/modules/domains/dto/domains.schemas';
import { isStrictRequestSchema } from '../src/validation/strict-schema';
import { ZodValidationPipe } from '../src/validation/zod-validation.pipe';
import { COVERAGE, COVERAGE_BY_AREA, type RouteCoverage } from './route-coverage';
import { createStubbedApiApp, type StubbedApiApp } from './support/api-test-app';
import { type DiscoveredRoute, discoverRoutes } from './support/route-discovery';

const REPO_ROOT = resolve(__dirname, '../../..');

/** D13: the only routes outside `/api/v1` (internal port; never in an Ingress or the document). */
const INTERNAL_ROUTES = ['get /health/live', 'get /health/ready', 'get /metrics'];

/**
 * Step API-1 D12.4: the public Graph callbacks. Their body is Graph's notification collection,
 * parsed in the service with `graphNotificationSchema`, which deliberately ALLOWS unknown keys
 * (Graph sends `resource`, `resourceData` and more; they are dropped, never refused), so it is
 * exempt from the strict-schema rule (D1); they answer `202` without a body.
 */
const PROVIDER_CALLBACKS = [
  'post /api/v1/provider-notifications/graph',
  'post /api/v1/provider-notifications/graph/lifecycle',
];

/** D7: the documented `@Public()` routes (unchanged by 6.1) and the internal endpoints. */
const PUBLIC_ROUTES = [
  ...INTERNAL_ROUTES,
  'get /api/v1/meta',
  'post /api/v1/auth/login',
  'post /api/v1/auth/mfa/verify',
  'post /api/v1/auth/refresh',
  'post /api/v1/auth/password/forgot',
  'post /api/v1/auth/password/reset',
  'post /api/v1/auth/email/verify',
  'post /api/v1/auth/invitations/inspect',
  'post /api/v1/auth/invitations/accept',
  // Step API-1 D12.4: the Microsoft Graph change and lifecycle notification callbacks.
  ...PROVIDER_CALLBACKS,
];

/**
 * D7: the self-service routes that need a principal but no permission (`@AuthenticatedOnly()`),
 * read from the code: the caller's own profile, sessions, password, email verification, MFA
 * enrollment and the end of the caller's own platform override. Everything else names a
 * permission.
 */
const AUTHENTICATED_ONLY_ROUTES = [
  'get /api/v1/auth/me',
  'post /api/v1/auth/logout',
  'post /api/v1/auth/logout-all',
  'post /api/v1/auth/password/change',
  'post /api/v1/auth/email/verification',
  'get /api/v1/auth/sessions',
  'delete /api/v1/auth/sessions/:sessionId',
  'post /api/v1/auth/mfa/totp/setup',
  'post /api/v1/auth/mfa/totp/enable',
  'post /api/v1/auth/mfa/totp/disable',
  'post /api/v1/auth/mfa/recovery-codes',
  'delete /api/v1/platform/overrides/:overrideId',
  // Step 6.2 N3: the caller's own notification preferences (users only).
  'get /api/v1/notifications/preferences',
  'put /api/v1/notifications/preferences',
];

/** §3.3: the 20 routes new in step 6.1 (examples required, lists must be v1). */
const NEW_IN_6_1 = [
  'get /api/v1/messages',
  'get /api/v1/messages/:messageId',
  'get /api/v1/messages/:messageId/recipients',
  'get /api/v1/messages/:messageId/attachments',
  'get /api/v1/attachments',
  'get /api/v1/messages/:messageId/urls',
  'get /api/v1/url-protection/clicks',
  'get /api/v1/recipients/suppressions',
  'get /api/v1/recipients/suppressions/:suppressionId',
  'post /api/v1/recipients/suppressions',
  'delete /api/v1/recipients/suppressions/:suppressionId',
  'get /api/v1/audit/logs',
  'get /api/v1/platform/audit/logs',
  'get /api/v1/reports/traffic',
  'get /api/v1/reports/threats',
  'get /api/v1/reports/url-clicks',
  'get /api/v1/usage',
  'get /api/v1/billing/plan',
  'get /api/v1/billing/usage',
  'get /api/v1/threat-intelligence/lookup',
];

/** Step 6.2 §6.1: the 17 webhook and notification routes (examples required, lists v1). */
const NEW_IN_6_2 = [
  'get /api/v1/webhooks',
  'post /api/v1/webhooks',
  'get /api/v1/webhooks/event-types',
  'get /api/v1/webhooks/:webhookId',
  'patch /api/v1/webhooks/:webhookId',
  'delete /api/v1/webhooks/:webhookId',
  'post /api/v1/webhooks/:webhookId/rotate-secret',
  'post /api/v1/webhooks/:webhookId/test',
  'get /api/v1/webhooks/:webhookId/deliveries',
  'get /api/v1/webhooks/:webhookId/deliveries/:deliveryId',
  'post /api/v1/webhooks/:webhookId/deliveries/:deliveryId/replay',
  'post /api/v1/webhooks/:webhookId/replays',
  'get /api/v1/webhooks/:webhookId/replays/:replayId',
  'get /api/v1/notifications/settings',
  'put /api/v1/notifications/settings',
  'get /api/v1/notifications/preferences',
  'put /api/v1/notifications/preferences',
];

/**
 * ADR-0057: the only routes allowed to combine `@ReturnsSecret()` with an Idempotency-Key, and
 * only as `@ReturnsSecret({ redactedReplay: true })` with the transactional mechanism (the
 * stored response carries `secret: null`).
 */
const SECRET_BEARING_REDACTED_REPLAY = [
  'post /api/v1/webhooks',
  'post /api/v1/webhooks/:webhookId/rotate-secret',
  // Step 8.2: the admin-consent URL (its single-use state) and the single-use probe address.
  'post /api/v1/provider-connections/:id/grants',
  'post /api/v1/provider-connections/:id/validations',
  // Step 8.6 D11: the intake address (and Google header token) shown once on creation and rotation.
  'post /api/v1/journaling/intake-sources',
  'post /api/v1/journaling/intake-sources/:sourceId/rotate-address',
];

/** §3.5: sensitive mutations keyed transactionally (IdempotencyService.execute). */
const SENSITIVE_TRANSACTIONAL = [
  // Step API-1 D12 (the keyed protection-mode and API-mode mutations).
  'put /api/v1/organizations/:id/protection-mode',
  'put /api/v1/domains/:domainId/protection-mode',
  'put /api/v1/api-mode/connections/:connectionId/settings',
  'post /api/v1/api-mode/connections/:connectionId/inventory-sync',
  'post /api/v1/api-mode/mailboxes/:mailboxId/resync',
  // Step API-2 R13 (the keyed remediation mutations).
  'put /api/v1/api-mode/remediation-policy',
  'put /api/v1/api-mode/remediation-policy/domains/:domainId',
  'delete /api/v1/api-mode/remediation-policy/domains/:domainId',
  'post /api/v1/api-mode/remediations/:remediationId/retry',
  'post /api/v1/api-mode/detections/:detectionId/remediate',
  'post /api/v1/api-mode/detections/:detectionId/restore',
  // Step API-3 C14 (the keyed clawback, report and settings mutations).
  'post /api/v1/api-mode/clawbacks',
  'post /api/v1/api-mode/clawbacks/:clawbackId/submit',
  'post /api/v1/api-mode/clawbacks/:clawbackId/submit-hard-delete',
  'post /api/v1/api-mode/clawbacks/:clawbackId/approve',
  'post /api/v1/api-mode/clawbacks/:clawbackId/deny',
  'post /api/v1/api-mode/clawbacks/:clawbackId/cancel',
  'post /api/v1/api-mode/clawbacks/:clawbackId/restore',
  'post /api/v1/api-mode/reports/:reportId/triage',
  'post /api/v1/api-mode/reports/:reportId/clawback',
  'post /api/v1/api-mode/report-mailboxes',
  'put /api/v1/api-mode/mailboxes/:mailboxId/report-mailbox',
  'put /api/v1/api-mode/settings',
  // Step API-4 B3, B6 (the keyed scope write and provider ownership check).
  'put /api/v1/api-mode/domains/:domainId/scope',
  'post /api/v1/domains/:domainId/ownership/provider-check',
  'post /api/v1/messages/:messageId/rescan',
  'post /api/v1/messages/:messageId/release',
  'post /api/v1/quarantine/bulk',
  'post /api/v1/quarantine/entries',
  'post /api/v1/quarantine/entries/:entryId/release',
  'post /api/v1/quarantine/entries/:entryId/request-release',
  'post /api/v1/quarantine/entries/:entryId/reject',
  'post /api/v1/quarantine/entries/:entryId/delete',
  'post /api/v1/quarantine/approvals/:approvalId/approve',
  'post /api/v1/quarantine/approvals/:approvalId/deny',
  'post /api/v1/quarantine/approvals/:approvalId/cancel',
  'post /api/v1/quarantine/me/entries/:entryId/release',
  'post /api/v1/quarantine/me/entries/:entryId/request-release',
  'post /api/v1/recipients/suppressions',
  'delete /api/v1/recipients/suppressions/:suppressionId',
  // Step 6.2 §6.1 (ADR-0057 for the first and third).
  'post /api/v1/webhooks',
  'delete /api/v1/webhooks/:webhookId',
  'post /api/v1/webhooks/:webhookId/rotate-secret',
  'post /api/v1/webhooks/:webhookId/deliveries/:deliveryId/replay',
  'post /api/v1/webhooks/:webhookId/replays',
  // Step 8.1 §4.4 (the keyed archive, legal hold and eDiscovery mutations).
  'put /api/v1/archive/settings',
  'post /api/v1/archive/retention-policies',
  'put /api/v1/archive/retention-policies/:policyId',
  'delete /api/v1/archive/retention-policies/:policyId',
  'post /api/v1/archive/keys/rotate',
  'post /api/v1/archive/capture-issues/:messageId/retry',
  'post /api/v1/archive/messages/:messageId/dispose',
  'post /api/v1/legal-holds/:holdId/release',
  'post /api/v1/ediscovery/cases/:caseId/holds',
  'post /api/v1/ediscovery/cases',
  'patch /api/v1/ediscovery/cases/:caseId',
  'post /api/v1/ediscovery/cases/:caseId/close',
  'post /api/v1/ediscovery/cases/:caseId/searches/:searchId/review',
  // Step 8.4 §5.1, §5.2 (every ATO and incident mutation).
  'patch /api/v1/ato/accounts/:accountId',
  'put /api/v1/ato/accounts/:accountId/override',
  'post /api/v1/ato/accounts/:accountId/override/clear',
  'post /api/v1/ato/accounts/:accountId/trusted-contexts',
  'delete /api/v1/ato/accounts/:accountId/trusted-contexts/:contextId',
  'post /api/v1/ato/incidents/:incidentId/responses',
  'post /api/v1/ato/responses/:responseId/approve',
  'post /api/v1/ato/responses/:responseId/reject',
  'post /api/v1/ato/responses/:responseId/cancel',
  'post /api/v1/ato/responses/:responseId/rollback',
  'put /api/v1/ato/settings',
  'post /api/v1/incidents',
  'patch /api/v1/incidents/:incidentId',
  'post /api/v1/incidents/:incidentId/notes',
  // Step 8.2 D17 (the grant, consent and disconnect mutations; ADR-0057 for grant creation and
  // validation creation).
  'delete /api/v1/provider-connections/:id',
  'post /api/v1/provider-connections/:id/grants',
  'post /api/v1/provider-connections/consent/complete',
  'put /api/v1/provider-connections/:id/grants/:profile/credentials',
  'post /api/v1/provider-connections/:id/grants/:profile/verify',
  'delete /api/v1/provider-connections/:id/grants/:profile',
  'post /api/v1/provider-connections/:id/validations',
  // Step 8.5 §6: every identity-provider mutation and the mailbox state refresh.
  'post /api/v1/ato/providers',
  'patch /api/v1/ato/providers/:integrationId',
  'post /api/v1/ato/providers/:integrationId/pause',
  'post /api/v1/ato/providers/:integrationId/resume',
  'post /api/v1/ato/providers/:integrationId/health-check',
  'post /api/v1/ato/providers/:integrationId/backfill',
  'delete /api/v1/ato/providers/:integrationId',
  'post /api/v1/ato/accounts/:accountId/mailbox-state/refresh',
  // Step 8.6 D11: the keyed journaling mutations (creation and rotation are ADR-0057 routes).
  'put /api/v1/journaling/settings',
  'post /api/v1/journaling/intake-sources',
  'patch /api/v1/journaling/intake-sources/:sourceId',
  'post /api/v1/journaling/intake-sources/:sourceId/rotate-address',
];

/** Step 8.6 D11: MFA mutations in the sensitive class without an Idempotency-Key. */
const SENSITIVE_UNKEYED_8_6 = [
  'delete /api/v1/journaling/intake-sources/:sourceId',
  'post /api/v1/journaling/intake-sources/:sourceId/attestations',
];

/**
 * Step 8.2 §5.1: keyed transactional mutations without a rate class (the connection create, the
 * domain links, the mail-flow apply with its own 30/min limit, attestations and the per-connection
 * health check with its own 6/hour limit).
 */
const KEYED_8_2 = [
  'post /api/v1/provider-connections',
  'put /api/v1/provider-connections/:id/domains',
  'post /api/v1/provider-connections/:id/mail-flow/apply',
  'post /api/v1/provider-connections/:id/attestations',
  'post /api/v1/provider-connections/:id/health/check',
];

/** §3.5: the legacy sensitive mutations keyed by the reservation interceptor (`@Idempotent`). */
const SENSITIVE_LEGACY = [
  'post /api/v1/domains/:id/dkim/rotate',
  'patch /api/v1/organizations/:id/status',
  'post /api/v1/organizations/:id/deletion',
  'post /api/v1/organizations/:id/deletion/confirm',
  'post /api/v1/users/invitations',
  'post /api/v1/users/:id/invitation',
  'post /api/v1/users/:id/mfa/reset',
  'post /api/v1/policies/:policyId/versions/:versionNo/publish',
  'post /api/v1/policies/:policyId/versions/:versionNo/activate',
  'post /api/v1/risk-scoring/profile/versions/:versionId/publish',
  'post /api/v1/risk-scoring/profile/versions/:versionId/activate',
  'post /api/v1/risk-scoring/profile/reset',
  'delete /api/v1/bec/history',
  'delete /api/v1/dlp/evidence',
  'delete /api/v1/messages/:messageId/scans/:scanId/dlp-evidence',
  'put /api/v1/dlp/compliance/aadhaar',
  'delete /api/v1/dlp/compliance/aadhaar',
  'post /api/v1/platform/dead-letters/replay',
  'post /api/v1/platform/attachment-rescans',
  'post /api/v1/platform/organizations/:organizationId/messages/:messageId/scan-training',
  'post /api/v1/platform/threat-hashes',
  'post /api/v1/platform/threat-indicators',
];

/**
 * Step 7.1 §3.3 (docs/plan/steps/20-admin-portal.md): the three reports of the admin dashboard
 * (examples required, class `expensive`, in the insights manifest).
 */
const NEW_IN_7_1 = [
  'get /api/v1/reports/delivery',
  'get /api/v1/reports/processing',
  'get /api/v1/reports/top-domains',
];

/**
 * Step 7.2 §3.3 (docs/plan/steps/21-email-explorer-details.md), WP1: the saved views routes; WP2:
 * the headers route and the two reveal operations (examples required, the list v1, exactly the
 * explorer manifest).
 */
const NEW_IN_7_2 = [
  'get /api/v1/saved-views',
  'post /api/v1/saved-views',
  'get /api/v1/saved-views/:viewId',
  'put /api/v1/saved-views/:viewId',
  'delete /api/v1/saved-views/:viewId',
  'get /api/v1/messages/:messageId/headers',
  'post /api/v1/messages/reveal',
  'post /api/v1/messages/:messageId/reveal',
];

/**
 * Step 7.3 §4.4 (docs/plan/steps/22-policy-builder.md): validation without saving and the sample
 * dry-run (examples required, exactly the policy-builder manifest).
 */
const NEW_IN_7_3 = ['post /api/v1/policies/validate', 'post /api/v1/policies/dry-run'];

/**
 * Step 8.1 §4.4 (docs/plan/steps/23-journaling-archiving.md): the 41 archive, legal hold and
 * eDiscovery operations (examples required, lists v1, exactly the archive manifest).
 */
const NEW_IN_8_1 = [
  'get /api/v1/archive/settings',
  'put /api/v1/archive/settings',
  'get /api/v1/archive/retention-policies',
  'post /api/v1/archive/retention-policies',
  'get /api/v1/archive/retention-policies/:policyId',
  'put /api/v1/archive/retention-policies/:policyId',
  'delete /api/v1/archive/retention-policies/:policyId',
  'get /api/v1/archive/keys',
  'post /api/v1/archive/keys/rotate',
  'get /api/v1/archive/status',
  'get /api/v1/archive/capture-issues',
  'post /api/v1/archive/capture-issues/:messageId/retry',
  'get /api/v1/archive/disposals',
  'get /api/v1/archive/export-signing-keys',
  'get /api/v1/archive/messages',
  'get /api/v1/archive/messages/:messageId',
  'get /api/v1/archive/messages/:messageId/journal',
  'get /api/v1/archive/messages/:messageId/security',
  'post /api/v1/archive/messages/:messageId/reveal',
  'get /api/v1/archive/messages/:messageId/preview',
  'post /api/v1/archive/messages/:messageId/download-grants',
  'get /api/v1/archive/downloads/:token',
  'post /api/v1/archive/messages/:messageId/dispose',
  'get /api/v1/legal-holds',
  'get /api/v1/legal-holds/:holdId',
  'post /api/v1/legal-holds/:holdId/release',
  'post /api/v1/ediscovery/cases/:caseId/holds',
  'get /api/v1/ediscovery/cases',
  'post /api/v1/ediscovery/cases',
  'get /api/v1/ediscovery/cases/:caseId',
  'patch /api/v1/ediscovery/cases/:caseId',
  'post /api/v1/ediscovery/cases/:caseId/close',
  'post /api/v1/ediscovery/cases/:caseId/searches',
  'get /api/v1/ediscovery/cases/:caseId/searches',
  'get /api/v1/ediscovery/cases/:caseId/searches/:searchId',
  'get /api/v1/ediscovery/cases/:caseId/searches/:searchId/hits',
  'post /api/v1/ediscovery/cases/:caseId/searches/:searchId/review',
  'post /api/v1/ediscovery/cases/:caseId/exports',
  'get /api/v1/ediscovery/cases/:caseId/exports',
  'get /api/v1/ediscovery/cases/:caseId/exports/:exportId',
  'post /api/v1/ediscovery/cases/:caseId/exports/:exportId/download-grants',
];

/**
 * Step 8.4 §5.1, §5.2 (docs/plan/steps/24-account-takeover-core.md): the 26 account takeover and
 * 8 security incident operations (examples required, lists v1, exactly the ato and incidents
 * manifests).
 */
const NEW_IN_8_4 = [
  'get /api/v1/ato/overview',
  'get /api/v1/ato/attention',
  'get /api/v1/ato/accounts',
  'get /api/v1/ato/accounts/:accountId',
  'patch /api/v1/ato/accounts/:accountId',
  'get /api/v1/ato/accounts/:accountId/signals',
  'get /api/v1/ato/accounts/:accountId/auth-events',
  'get /api/v1/ato/accounts/:accountId/activity',
  'get /api/v1/ato/accounts/:accountId/score-history',
  'put /api/v1/ato/accounts/:accountId/override',
  'post /api/v1/ato/accounts/:accountId/override/clear',
  'post /api/v1/ato/accounts/:accountId/trusted-contexts',
  'delete /api/v1/ato/accounts/:accountId/trusted-contexts/:contextId',
  'get /api/v1/ato/incidents/:incidentId/signals',
  'get /api/v1/ato/incidents/:incidentId/auth-events',
  'post /api/v1/ato/incidents/:incidentId/responses',
  'get /api/v1/ato/responses',
  'get /api/v1/ato/responses/:responseId',
  'post /api/v1/ato/responses/:responseId/approve',
  'post /api/v1/ato/responses/:responseId/reject',
  'post /api/v1/ato/responses/:responseId/cancel',
  'post /api/v1/ato/responses/:responseId/rollback',
  'get /api/v1/ato/restrictions',
  'get /api/v1/ato/settings',
  'put /api/v1/ato/settings',
  'get /api/v1/ato/rules',
  'get /api/v1/incidents',
  'post /api/v1/incidents',
  'get /api/v1/incidents/:incidentId',
  'patch /api/v1/incidents/:incidentId',
  'post /api/v1/incidents/:incidentId/notes',
  'get /api/v1/incidents/:incidentId/timeline',
  'get /api/v1/incidents/:incidentId/messages',
  'get /api/v1/incidents/:incidentId/report',
];

/**
 * Step 8.2 §5.2 (docs/plan/steps/25-m365-google-connectors.md): the 24 Microsoft 365 and Google
 * Workspace connection operations (examples required, lists v1, exactly the provider-connections
 * manifest).
 */
const NEW_IN_8_2 = [
  'get /api/v1/provider-integrations/catalog',
  'get /api/v1/provider-connections',
  'post /api/v1/provider-connections',
  'get /api/v1/provider-connections/:id',
  'patch /api/v1/provider-connections/:id',
  'delete /api/v1/provider-connections/:id',
  'get /api/v1/provider-connections/:id/wizard',
  'post /api/v1/provider-connections/:id/grants',
  'post /api/v1/provider-connections/consent/complete',
  'put /api/v1/provider-connections/:id/grants/:profile/credentials',
  'post /api/v1/provider-connections/:id/grants/:profile/verify',
  'delete /api/v1/provider-connections/:id/grants/:profile',
  'get /api/v1/provider-connections/:id/domains',
  'put /api/v1/provider-connections/:id/domains',
  'post /api/v1/provider-connections/:id/mail-flow/preview',
  'post /api/v1/provider-connections/:id/mail-flow/apply',
  'get /api/v1/provider-connections/:id/mail-flow',
  'post /api/v1/provider-connections/:id/attestations',
  'post /api/v1/provider-connections/:id/validations',
  'get /api/v1/provider-connections/:id/validations',
  'get /api/v1/provider-connections/:id/validations/:runId',
  'get /api/v1/provider-connections/:id/health',
  'post /api/v1/provider-connections/:id/health/check',
  'get /api/v1/provider-connections/:id/setup-guide',
];

/**
 * Step 8.5 §6 (docs/plan/steps/26-ato-provider-adapters.md): the 13 identity-provider and mailbox
 * state operations (examples required, no paged list, exactly the ato-providers manifest).
 */
/**
 * Step 8.6 D11 (docs/plan/steps/27-journal-intake-and-archive-split.md): the 12 journaling
 * operations (examples required, one v1 list, exactly the journaling manifest).
 */
const NEW_IN_8_6 = [
  'get /api/v1/journaling/settings',
  'put /api/v1/journaling/settings',
  'get /api/v1/journaling/status',
  'get /api/v1/journaling/intake-sources',
  'post /api/v1/journaling/intake-sources',
  'get /api/v1/journaling/intake-sources/:sourceId',
  'patch /api/v1/journaling/intake-sources/:sourceId',
  'delete /api/v1/journaling/intake-sources/:sourceId',
  'post /api/v1/journaling/intake-sources/:sourceId/rotate-address',
  'get /api/v1/journaling/intake-sources/:sourceId/wizard',
  'get /api/v1/journaling/intake-sources/:sourceId/setup-guide',
  'post /api/v1/journaling/intake-sources/:sourceId/attestations',
];

/**
 * Step AI-1 §4.1 (docs/plan/steps/28-ai-chat-management.md): the 15 assistant operations
 * (examples required, two v1 lists, exactly the assistant manifest).
 */
const NEW_IN_AI_1 = [
  'get /api/v1/assistant/status',
  'get /api/v1/assistant/settings',
  'put /api/v1/assistant/settings',
  'get /api/v1/assistant/usage',
  'get /api/v1/assistant/tools',
  'get /api/v1/assistant/conversations',
  'post /api/v1/assistant/conversations',
  'get /api/v1/assistant/conversations/:conversationId',
  'patch /api/v1/assistant/conversations/:conversationId',
  'delete /api/v1/assistant/conversations/:conversationId',
  'get /api/v1/assistant/conversations/:conversationId/messages',
  'post /api/v1/assistant/conversations/:conversationId/turns',
  'post /api/v1/assistant/turns/:turnId/cancel',
  'get /api/v1/assistant/executions/:executionId',
  'post /api/v1/assistant/executions/:executionId/more',
];

/** Step AI-1: the settings update is `sensitive` without an Idempotency-Key (CAS on rowVersion). */
const SENSITIVE_UNKEYED_AI_1 = ['put /api/v1/assistant/settings'];

/** Step AI-2 §4.1: the 3 confirmation operations of the assistant. */
const NEW_IN_AI_2 = [
  'get /api/v1/assistant/confirmations/:confirmationId',
  'post /api/v1/assistant/confirmations/:confirmationId/confirm',
  'post /api/v1/assistant/confirmations/:confirmationId/cancel',
];

/** Step AI-R §4.1: the report read of the assistant (owner only, HTML inside JSON). */
const NEW_IN_AI_R = ['get /api/v1/assistant/reports/:reportId'];

/** Step AI-4 D8: the single-item reads the assistant's confirmation cards need (legacy modules). */
const NEW_IN_AI_4 = [
  'get /api/v1/bec/trusted-senders/:id',
  'get /api/v1/bec/suppressions/:id',
  'get /api/v1/dlp/exceptions/:id',
  'get /api/v1/platform/threat-indicators/:id',
];

/** Step AI-5 D8: the capture-issue read the assistant's capture retry card needs (archive). */
const NEW_IN_AI_5 = ['get /api/v1/archive/capture-issues/:messageId'];

/**
 * Step AI-6 §4.1 (docs/plan/steps/34-ai-chat-hardening-operations.md, contracts §35.6): the 11
 * hardening operations (examples required, four v1 lists plus the search, the assistant manifest).
 */
const NEW_IN_AI_6 = [
  'put /api/v1/assistant/settings/provider-key',
  'delete /api/v1/assistant/settings/provider-key',
  'post /api/v1/assistant/settings/provider-key/validate',
  'get /api/v1/assistant/search',
  'put /api/v1/assistant/messages/:messageId/feedback',
  'delete /api/v1/assistant/messages/:messageId/feedback',
  'get /api/v1/assistant/admin/usage/users',
  'get /api/v1/assistant/admin/feedback',
  'get /api/v1/assistant/admin/conversations',
  'get /api/v1/assistant/admin/conversations/:conversationId',
  'get /api/v1/assistant/admin/executions',
];

/**
 * Step API-1 D12 (docs/plan/steps/35-api-mode-protection.md): the 14 protection-mode and
 * API-mode operations (examples required; with PROVIDER_CALLBACKS exactly the api-mode manifest).
 */
const NEW_IN_API_1 = [
  'get /api/v1/organizations/:id/protection-mode',
  'put /api/v1/organizations/:id/protection-mode',
  'put /api/v1/domains/:domainId/protection-mode',
  'get /api/v1/api-mode/overview',
  'get /api/v1/api-mode/connections',
  'get /api/v1/api-mode/connections/:connectionId',
  'get /api/v1/api-mode/connections/:connectionId/setup-guide',
  'put /api/v1/api-mode/connections/:connectionId/settings',
  'post /api/v1/api-mode/connections/:connectionId/inventory-sync',
  'get /api/v1/api-mode/mailboxes',
  'get /api/v1/api-mode/mailboxes/:mailboxId',
  'post /api/v1/api-mode/mailboxes/:mailboxId/resync',
  'get /api/v1/api-mode/detections',
  'get /api/v1/api-mode/detections/:detectionId',
];

/**
 * Step API-2 R13 (docs/plan/steps/36-api-mode-remediation.md): the 9 remediation operations
 * (examples required; in the api-mode manifest): six keyed `sensitive` mutations and one v1 list.
 */
const NEW_IN_API_2 = [
  'get /api/v1/api-mode/remediation-policy',
  'put /api/v1/api-mode/remediation-policy',
  'put /api/v1/api-mode/remediation-policy/domains/:domainId',
  'delete /api/v1/api-mode/remediation-policy/domains/:domainId',
  'get /api/v1/api-mode/remediations',
  'get /api/v1/api-mode/remediations/:remediationId',
  'post /api/v1/api-mode/remediations/:remediationId/retry',
  'post /api/v1/api-mode/detections/:detectionId/remediate',
  'post /api/v1/api-mode/detections/:detectionId/restore',
];

/**
 * Step API-3 C14 (docs/plan/steps/37-api-mode-clawback-reporting.md): the 19 clawback, report and
 * settings operations (examples required; in the api-mode manifest): twelve keyed `sensitive`
 * mutations and three v1 lists (clawbacks, clawback targets, reports).
 */
const NEW_IN_API_3 = [
  'post /api/v1/api-mode/clawbacks',
  'get /api/v1/api-mode/clawbacks',
  'get /api/v1/api-mode/clawbacks/:clawbackId',
  'get /api/v1/api-mode/clawbacks/:clawbackId/targets',
  'post /api/v1/api-mode/clawbacks/:clawbackId/submit',
  'post /api/v1/api-mode/clawbacks/:clawbackId/submit-hard-delete',
  'post /api/v1/api-mode/clawbacks/:clawbackId/approve',
  'post /api/v1/api-mode/clawbacks/:clawbackId/deny',
  'post /api/v1/api-mode/clawbacks/:clawbackId/cancel',
  'post /api/v1/api-mode/clawbacks/:clawbackId/restore',
  'get /api/v1/api-mode/reports',
  'get /api/v1/api-mode/reports/:reportId',
  'post /api/v1/api-mode/reports/:reportId/triage',
  'post /api/v1/api-mode/reports/:reportId/clawback',
  'get /api/v1/api-mode/report-mailboxes',
  'post /api/v1/api-mode/report-mailboxes',
  'put /api/v1/api-mode/mailboxes/:mailboxId/report-mailbox',
  'get /api/v1/api-mode/settings',
  'put /api/v1/api-mode/settings',
];

/**
 * Step API-4 (docs/plan/steps/38-api-mode-parity-onboarding.md A10, B3, B6, B8): the 5
 * onboarding operations (examples required; in the api-mode manifest): two keyed `sensitive`
 * mutations (the scope write and the provider ownership check) and one v1 list (protection by
 * mode).
 */
const NEW_IN_API_4 = [
  'get /api/v1/api-mode/protection-coverage',
  'get /api/v1/api-mode/domains/:domainId/onboarding',
  'get /api/v1/api-mode/domains/:domainId/scope',
  'put /api/v1/api-mode/domains/:domainId/scope',
  'post /api/v1/domains/:domainId/ownership/provider-check',
];

/**
 * Step AI-6 D7, I27: request bodies that carry a write-only secret and therefore no example (an
 * example would be a key-shaped value in the published document); the schema describes it.
 */
const WRITE_ONLY_SECRET_BODIES = ['put /api/v1/assistant/settings/provider-key'];

/** Step AI-6 D7: the tenant-key routes are `sensitive` without an Idempotency-Key (CAS/status). */
const SENSITIVE_UNKEYED_AI_6 = [
  'put /api/v1/assistant/settings/provider-key',
  'delete /api/v1/assistant/settings/provider-key',
  'post /api/v1/assistant/settings/provider-key/validate',
];

/** Step AI-2: confirm and cancel are `sensitive`, unkeyed (the row's transition is single use). */
const SENSITIVE_UNKEYED_AI_2 = [
  'post /api/v1/assistant/confirmations/:confirmationId/confirm',
  'post /api/v1/assistant/confirmations/:confirmationId/cancel',
];

const NEW_IN_8_5 = [
  'get /api/v1/ato/providers',
  'get /api/v1/ato/providers/requirements',
  'get /api/v1/ato/providers/connections',
  'post /api/v1/ato/providers',
  'get /api/v1/ato/providers/:integrationId',
  'patch /api/v1/ato/providers/:integrationId',
  'post /api/v1/ato/providers/:integrationId/pause',
  'post /api/v1/ato/providers/:integrationId/resume',
  'post /api/v1/ato/providers/:integrationId/health-check',
  'post /api/v1/ato/providers/:integrationId/backfill',
  'delete /api/v1/ato/providers/:integrationId',
  'get /api/v1/ato/accounts/:accountId/mailbox-state',
  'post /api/v1/ato/accounts/:accountId/mailbox-state/refresh',
];

/** Step 8.1: binary downloads (`application/octet-stream`; no JSON example applies). */
const BINARY_DOWNLOADS = ['get /api/v1/archive/downloads/:token'];

/** Step 8.1: the two worker-queued keyed requests in the `expensive` class (§4.4 #33, #38). */
const EXPENSIVE_TRANSACTIONAL = [
  'post /api/v1/ediscovery/cases/:caseId/searches',
  'post /api/v1/ediscovery/cases/:caseId/exports',
];

/** D9: secret-bearing responses (sensitive class, never idempotency-stored). */
const SECRET_BEARING = [
  'post /api/v1/api-keys',
  'post /api/v1/smtp-connectors',
  'post /api/v1/smtp-connectors/:id/rotate-secret',
  'post /api/v1/platform/overrides',
  'post /api/v1/auth/mfa/totp/setup',
  'post /api/v1/auth/mfa/recovery-codes',
];

/** §3.5: the `expensive` class (no key). */
const EXPENSIVE = [
  'get /api/v1/reports/traffic',
  'get /api/v1/reports/threats',
  'get /api/v1/reports/url-clicks',
  ...NEW_IN_7_1,
  'get /api/v1/billing/usage',
  'get /api/v1/threat-intelligence/lookup',
  'get /api/v1/attachments',
  'post /api/v1/policies/test',
  'post /api/v1/messages/:messageId/scans/:scanId/policy/dry-run',
  'post /api/v1/messages/:messageId/scans/:scanId/risk/dry-run',
  // Step 7.3 §4.3: the sample dry-run (plus its own per-principal limit).
  'post /api/v1/policies/dry-run',
  // Step 8.1 §4.4: the archive search and the two worker-queued keyed requests.
  'get /api/v1/archive/messages',
  ...EXPENSIVE_TRANSACTIONAL,
  // Step 8.4 §5: the ATO overview and the incident report.
  'get /api/v1/ato/overview',
  'get /api/v1/incidents/:incidentId/report',
  // Step AI-1 §4.1: an assistant turn and the next page of a result (loopback calls count too).
  'post /api/v1/assistant/conversations/:conversationId/turns',
  'post /api/v1/assistant/executions/:executionId/more',
  // Step AI-6 D4: the owner's content search (a bounded replica scan).
  'get /api/v1/assistant/search',
];

/**
 * 2xx responses that deliberately have no body although they are not 204: `202 Accepted` of the
 * enumeration-safe self-service mails (the same empty answer whether or not an account matched).
 */
const EMPTY_ACCEPTED = [
  'post /api/v1/auth/password/forgot',
  'post /api/v1/auth/email/verification',
  // Step API-1 D12.4: the Graph callbacks always answer 202 with an empty body (no oracle).
  ...PROVIDER_CALLBACKS,
];

/**
 * `@Body() body: unknown` handlers whose service parses the body (after the Idempotency-Key
 * checks of the transactional mechanism), with the schema the service applies.
 */
const BODY_PARSED_IN_SERVICE = new Map<string, z.ZodType>([
  ['QuarantineToolsController.bulk', BulkBodySchema],
  ['MessageLifecycleController.rescan', LifecycleOperationBodySchema],
  ['MessageLifecycleController.release', LifecycleOperationBodySchema],
  ['RecipientSuppressionsController.create', CreateSuppressionBodySchema],
  // Step 6.2: keyed routes parse after the key checks; settings map to their coded 400.
  ['WebhooksController.create', CreateWebhookBodySchema],
  ['WebhooksController.rotate', RotateSecretBodySchema],
  ['WebhookDeliveriesController.createReplay', CreateReplayBodySchema],
  ['NotificationsController.putSettings', SettingsUpdateBodySchema],
  // Step 8.2: the keyed provider-connection mutations parse after the key checks.
  ['ProviderConnectionsController.create', CreateConnectionBodySchema],
  ['ProviderConnectionsController.disconnect', DisconnectBodySchema],
  ['ProviderGrantsController.create', CreateGrantBodySchema],
  ['ProviderGrantsController.completeConsent', CompleteConsentBodySchema],
  ['ProviderGrantsController.setCredentials', SetCredentialsBodySchema],
  ['ProviderGrantsController.verify', VerifyGrantBodySchema],
  ['ProviderDomainsController.replace', ReplaceDomainsBodySchema],
  ['ProviderMailFlowController.apply', ApplyBodySchema],
  ['ProviderAttestationsController.record', AttestationBodySchema],
  ['ProviderValidationsController.create', CreateValidationBodySchema],
  // Step 8.6: the journaling mutations parse after the key checks.
  ['IntakeSourcesController.create', CreateIntakeSourceBodySchema],
  ['IntakeSourcesController.update', UpdateIntakeSourceBodySchema],
  ['IntakeSourcesController.attest', IntakeAttestationBodySchema],
  // Step API-1: the keyed API-mode mutations parse after the key checks; the Graph callbacks
  // parse with the non-strict notification schema (PROVIDER_CALLBACKS).
  ['ProtectionModeController.putOrganization', PutOrganizationModeBodySchema],
  ['ProtectionModeController.putDomain', PutDomainModeBodySchema],
  ['ApiModeController.updateSettings', UpdateSettingsBodySchema],
  // Step API-2: the keyed remediation mutations parse after the key checks.
  ['ApiModeRemediationController.putPolicy', PutRemediationPolicyBodySchema],
  ['ApiModeRemediationController.putDomainPolicy', PutRemediationPolicyBodySchema],
  ['ApiModeRemediationController.remediate', RemediateBodySchema],
  ['ApiModeRemediationController.restore', RestoreBodySchema],
  // Step API-3: the keyed clawback, report and settings mutations parse after the key checks.
  ['ApiModeClawbackController.create', CreateClawbackBodySchema],
  ['ApiModeClawbackController.submit', SubmitClawbackBodySchema],
  ['ApiModeClawbackController.submitHardDelete', DecisionBodySchema],
  ['ApiModeClawbackController.approve', DecisionBodySchema],
  ['ApiModeClawbackController.deny', DecisionBodySchema],
  ['ApiModeClawbackController.cancel', ReasonBodySchema],
  ['ApiModeClawbackController.restore', ReasonBodySchema],
  ['ApiModeReportsController.triage', TriageBodySchema],
  ['ApiModeReportsController.clawback', ReportClawbackBodySchema],
  ['ApiModeReportsController.addMailbox', AddReportMailboxBodySchema],
  ['ApiModeReportsController.setMailbox', SetReportMailboxBodySchema],
  ['ApiModeSettingsController.put', PutOrgSettingsBodySchema],
  // Step API-4: the keyed scope write and the provider ownership check parse after the key checks.
  ['ApiModeOnboardingController.putScope', PutDomainScopeBodySchema],
  ['DomainsController.providerOwnershipCheck', ProviderOwnershipCheckBodySchema],
  ['ProviderNotificationsController.graph', graphNotificationSchema],
  ['ProviderNotificationsController.lifecycle', graphNotificationSchema],
]);

const BODY: number = RouteParamtypes.BODY;
const QUERY: number = RouteParamtypes.QUERY;

type Json = Record<string, unknown>;
interface Operation {
  tags?: string[];
  summary?: string;
  security?: unknown[];
  parameters?: Array<{ name: string; in: string; required?: boolean }>;
  requestBody?: { content?: Record<string, Json> };
  responses: Record<string, { content?: Record<string, Json> } | undefined>;
  [extension: `x-${string}`]: unknown;
}

interface RouteFacts {
  route: DiscoveredRoute;
  key: string;
  takesBody: boolean;
  schemas: Array<{ kind: 'body' | 'query'; schema: z.ZodType }>;
  transactional: { operation: string } | null;
}

const keyOf = (r: Pick<DiscoveredRoute, 'method' | 'path'>) => `${r.method} ${r.path}`;
const openApiPath = (path: string) => path.replace(/:([A-Za-z0-9_]+)/g, '{$1}');

/** Matches `@covers <route>` exactly (not as a prefix of a longer route). */
function hasMarker(text: string, route: string): boolean {
  const escaped = route.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`@covers ${escaped}(?=\\s|$)`, 'm').test(text);
}

const fileCache = new Map<string, string | null>();
function readRepoFile(file: string): string | null {
  if (!fileCache.has(file)) {
    const absolute = resolve(REPO_ROOT, file);
    fileCache.set(file, existsSync(absolute) ? readFileSync(absolute, 'utf8') : null);
  }
  return fileCache.get(file)!;
}

function resolveRef(doc: OpenAPIObject, schema: unknown): Json | undefined {
  let current = schema as Json | undefined;
  for (let i = 0; i < 5 && current && typeof current.$ref === 'string'; i += 1) {
    const name = current.$ref.split('/').pop()!;
    current = doc.components?.schemas?.[name] as Json | undefined;
  }
  return current;
}

/** `nextCursor` among the properties of a 2xx JSON body (directly or in an `allOf` member). */
function isCursorPage(doc: OpenAPIObject, op: Operation): boolean {
  return Object.entries(op.responses).some(([status, response]) => {
    if (!/^2\d\d$/.test(status)) return false;
    const schema = resolveRef(doc, response?.content?.['application/json']?.schema);
    const members = [
      schema,
      ...((schema?.allOf as unknown[]) ?? []).map((s) => resolveRef(doc, s)),
    ];
    return members.some(
      (m) => m?.properties !== undefined && 'nextCursor' in (m.properties as Json),
    );
  });
}

function hasExample(media: Json | undefined): boolean {
  if (!media) return false;
  const schema = media.schema as Json | undefined;
  return (
    media.example !== undefined || media.examples !== undefined || schema?.example !== undefined
  );
}

describe('route inventory (step 6.1, e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  let doc: OpenAPIObject;
  let facts: RouteFacts[];
  const byKey = new Map<string, RouteFacts>();

  const operation = (key: string): Operation | undefined => {
    const [method, path] = key.split(' ') as [string, string];
    return (doc.paths[openApiPath(path)] as Record<string, Operation> | undefined)?.[method];
  };
  const isInternal = (key: string) => INTERNAL_ROUTES.includes(key);

  beforeAll(async () => {
    api = await createStubbedApiApp({}, { discovery: true, principals: false });
    doc = buildOpenApiDocument(api.app);
    const routes = discoverRoutes(api.app);
    facts = [];
    for (const wrapper of api.app.get(DiscoveryService).getControllers()) {
      const controller = wrapper.metatype as (new (...args: never[]) => object) | null;
      if (!controller || !wrapper.instance) continue;
      const prototype = controller.prototype as Record<string, unknown>;
      for (const route of routes.filter((r) => r.name.startsWith(`${controller.name}.`))) {
        const handlerName = route.name.slice(controller.name.length + 1);
        const args = (Reflect.getMetadata(ROUTE_ARGS_METADATA, controller, handlerName) ??
          {}) as Record<string, { pipes?: unknown[] }>;
        const schemas: RouteFacts['schemas'] = [];
        let takesBody = false;
        for (const [argKey, arg] of Object.entries(args)) {
          const type = Number(argKey.split(':')[0]);
          if (type !== BODY && type !== QUERY) continue;
          if (type === BODY) takesBody = true;
          for (const pipe of arg.pipes ?? []) {
            if (pipe instanceof ZodValidationPipe) {
              schemas.push({
                kind: type === BODY ? 'body' : 'query',
                schema: (pipe as unknown as { schema: z.ZodType }).schema,
              });
            }
          }
          const parsedInService = BODY_PARSED_IN_SERVICE.get(route.name);
          if (parsedInService && type === BODY) {
            schemas.push({ kind: 'body', schema: parsedInService });
          }
        }
        const transactional =
          (Reflect.getMetadata(TRANSACTIONAL_IDEMPOTENCY_KEY, prototype[handlerName] as object) as
            { operation: string } | undefined) ?? null;
        const fact: RouteFacts = { route, key: keyOf(route), takesBody, schemas, transactional };
        facts.push(fact);
        byKey.set(fact.key, fact);
      }
    }
  });

  afterAll(async () => {
    await api?.close();
  });

  it('discovers every route once (483 operations under /api/v1 plus the 3 internal endpoints)', () => {
    expect(facts.length).toBe(byKey.size);
    // 249 after step 6.1, plus the 17 routes of step 6.2, plus the 3 reports of step 7.1, plus
    // the 5 saved views routes (WP1) and the headers and two reveal routes (WP2) of step 7.2,
    // plus the validate and sample dry-run routes of step 7.3, plus the 41 archive, legal hold
    // and eDiscovery operations of step 8.1, plus the 26 account takeover and 8 security incident
    // operations of step 8.4, plus the 24 provider-connection operations of step 8.2, plus the 13
    // identity-provider and mailbox state operations of step 8.5, plus the 12 journaling
    // operations of step 8.6, plus the 15 assistant operations of step AI-1, plus the 3
    // confirmation operations of step AI-2, plus the API key read of step AI-3 (D8), plus the
    // report read of step AI-R (§4.1), plus the four single-item reads of step AI-4 (D8), plus
    // the capture-issue read of step AI-5 (D8), plus the 11 hardening operations of step AI-6
    // (§4.1, contracts §35.6), plus the 16 operations of step API-1 (D12: 14 API-mode and
    // protection-mode operations and the 2 public Graph callbacks), plus the 9 remediation
    // operations of step API-2 (R13), plus the 19 clawback, report and settings operations of
    // step API-3 (C14), plus the 5 onboarding operations of step API-4 (A10, B3, B6, B8).
    expect(facts.filter((f) => f.key.includes(' /api/v1/')).length).toBe(488);
    expect(
      facts
        .filter((f) => isInternal(f.key))
        .map((f) => f.key)
        .sort(),
    ).toEqual([...INTERNAL_ROUTES].sort());
  });

  it('serves nothing outside /api/v1 except the internal allow-list (D13)', () => {
    const outside = facts
      .filter((f) => !f.route.path.startsWith('/api/v1/') && !isInternal(f.key))
      .map((f) => f.key);
    expect(outside).toEqual([]);
  });

  it('every route is a documented public route, names a permission, or is allow-listed self-service (D7)', () => {
    const failures: string[] = [];
    for (const { key, route } of facts) {
      const requirement = route.requirement as
        { mode?: string; permissions?: string[] } | undefined;
      if (route.isPublic) {
        if (!PUBLIC_ROUTES.includes(key)) failures.push(`${key}: @Public() but not documented`);
        if (requirement !== undefined) failures.push(`${key}: @Public() with a requirement`);
        continue;
      }
      if (requirement?.mode === 'authenticated') {
        if (!AUTHENTICATED_ONLY_ROUTES.includes(key)) {
          failures.push(`${key}: @AuthenticatedOnly() but not in the self-service allow-list`);
        }
        continue;
      }
      if (
        (requirement?.mode !== 'all' && requirement?.mode !== 'any') ||
        (requirement.permissions ?? []).length === 0
      ) {
        failures.push(`${key}: no permission requirement`);
      }
    }
    expect(failures).toEqual([]);
    // The allow-lists name only routes that exist and carry exactly that kind of authorization.
    for (const key of PUBLIC_ROUTES) expect(byKey.get(key)?.route.isPublic, key).toBe(true);
    for (const key of AUTHENTICATED_ONLY_ROUTES) {
      expect(byKey.get(key)?.route.requirement, key).toEqual({ mode: 'authenticated' });
    }
  });

  it('documents every /api/v1 route as an operation with tag, summary, security, errors, body and 2xx schema (D14)', () => {
    const failures: string[] = [];
    for (const { key, route, takesBody } of facts) {
      if (isInternal(key)) {
        if (operation(key)) failures.push(`${key}: internal endpoint in the public document`);
        continue;
      }
      const op = operation(key);
      if (!op) {
        failures.push(`${key}: no OpenAPI operation`);
        continue;
      }
      if ((op.tags ?? []).length === 0) failures.push(`${key}: no tag`);
      if (!op.summary?.trim()) failures.push(`${key}: no summary`);
      const secured = (op.security ?? []).length > 0;
      if (route.isPublic === secured) {
        failures.push(
          `${key}: security ${secured ? 'on a public' : 'missing on a protected'} route`,
        );
      }
      const hasInput = (op.parameters ?? []).length > 0 || op.requestBody !== undefined;
      const standard = ['429', '500', '503'];
      if (hasInput) standard.push('400');
      if (secured) standard.push('401', '403');
      if (route.path.includes('/:')) standard.push('404');
      for (const status of standard) {
        if (!op.responses[status]) failures.push(`${key}: no ${status} response`);
      }
      if (takesBody) {
        const media = Object.values(op.requestBody?.content ?? {});
        if (!media.some((m) => m.schema !== undefined))
          failures.push(`${key}: no requestBody schema`);
      }
      const ok = Object.entries(op.responses).filter(([s]) => /^2\d\d$/.test(s));
      if (ok.length === 0) failures.push(`${key}: no 2xx response`);
      for (const [status, response] of ok) {
        if (status === '204' || EMPTY_ACCEPTED.includes(key)) continue;
        const media = Object.values(response?.content ?? {});
        if (!media.some((m) => m.schema !== undefined))
          failures.push(`${key}: ${status} without schema`);
      }
    }
    expect(failures).toEqual([]);
    for (const key of EMPTY_ACCEPTED) {
      expect(Object.keys(operation(key)!.responses), key).toContain('202');
    }
  });

  it('gives every route new in 6.1, 6.2, 7.1, 7.2, 7.3, 8.1, 8.4, 8.2, 8.5, 8.6, AI-1, AI-2, AI-R, AI-4, AI-5 and AI-6 explicit response examples (D14)', () => {
    const failures: string[] = [];
    for (const key of [
      ...NEW_IN_6_1,
      ...NEW_IN_6_2,
      ...NEW_IN_7_1,
      ...NEW_IN_7_2,
      ...NEW_IN_7_3,
      ...NEW_IN_8_1,
      ...NEW_IN_8_4,
      ...NEW_IN_8_2,
      ...NEW_IN_8_5,
      ...NEW_IN_8_6,
      ...NEW_IN_AI_1,
      ...NEW_IN_AI_2,
      ...NEW_IN_AI_R,
      ...NEW_IN_AI_4,
      ...NEW_IN_AI_5,
      ...NEW_IN_AI_6,
      ...NEW_IN_API_1,
      ...NEW_IN_API_2,
      ...NEW_IN_API_3,
      ...NEW_IN_API_4,
    ]) {
      const op = operation(key);
      if (!op) {
        failures.push(`${key}: missing`);
        continue;
      }
      for (const [status, response] of Object.entries(op.responses)) {
        if (!/^2\d\d$/.test(status) || status === '204' || BINARY_DOWNLOADS.includes(key)) continue;
        if (!hasExample(response?.content?.['application/json'])) {
          failures.push(`${key}: ${status} without an example`);
        }
      }
      if (
        op.requestBody &&
        !WRITE_ONLY_SECRET_BODIES.includes(key) &&
        !Object.values(op.requestBody.content ?? {}).some(hasExample)
      ) {
        failures.push(`${key}: requestBody without an example`);
      }
    }
    expect(failures).toEqual([]);
    // The write-only secret bodies really have no example anywhere (I27).
    for (const key of WRITE_ONLY_SECRET_BODIES) {
      expect(Object.values(operation(key)!.requestBody?.content ?? {}).some(hasExample), key).toBe(
        false,
      );
    }
    // NEW_IN_6_1 is exactly the 6.1 part of the WP2/WP3 manifests (the rest of messages.ts is
    // the pre-6.1 messages module).
    const preSixOneMessages = COVERAGE_BY_AREA.messages
      .map((c) => c.route)
      .filter((r) => !NEW_IN_6_1.includes(r));
    expect(preSixOneMessages.sort()).toEqual(
      [
        'get /api/v1/messages/:messageId/lifecycle',
        'get /api/v1/messages/:messageId/lifecycle/history',
        'post /api/v1/messages/:messageId/rescan',
        'post /api/v1/messages/:messageId/release',
        'get /api/v1/messages/:messageId/scans',
      ].sort(),
    );
    expect(
      COVERAGE_BY_AREA.insights.every(
        (c) => NEW_IN_6_1.includes(c.route) || NEW_IN_7_1.includes(c.route),
      ),
    ).toBe(true);
    expect(NEW_IN_6_1).toHaveLength(20);
    expect(NEW_IN_7_1.every((r) => COVERAGE_BY_AREA.insights.some((c) => c.route === r))).toBe(
      true,
    );
    // NEW_IN_6_2 is exactly the step 6.2 manifest.
    expect(COVERAGE_BY_AREA.webhooks.map((c) => c.route).sort()).toEqual([...NEW_IN_6_2].sort());
    expect(NEW_IN_6_2).toHaveLength(17);
    // NEW_IN_7_2 is exactly the step 7.2 explorer manifest (WP1, WP2).
    expect(COVERAGE_BY_AREA.explorer.map((c) => c.route).sort()).toEqual([...NEW_IN_7_2].sort());
    // NEW_IN_7_3 is exactly the step 7.3 policy-builder manifest.
    expect(COVERAGE_BY_AREA['policy-builder'].map((c) => c.route).sort()).toEqual(
      [...NEW_IN_7_3].sort(),
    );
    // NEW_IN_8_1 + NEW_IN_AI_5 is exactly the archive manifest (41 operations of step 8.1 plus
    // the capture-issue read of step AI-5).
    expect(COVERAGE_BY_AREA.archive.map((c) => c.route).sort()).toEqual(
      [...NEW_IN_8_1, ...NEW_IN_AI_5].sort(),
    );
    expect(NEW_IN_8_1).toHaveLength(41);
    // NEW_IN_8_4 is exactly the step 8.4 ato and incidents manifests (26 + 8 operations).
    expect(
      [...COVERAGE_BY_AREA.ato, ...COVERAGE_BY_AREA.incidents].map((c) => c.route).sort(),
    ).toEqual([...NEW_IN_8_4].sort());
    expect(COVERAGE_BY_AREA.ato).toHaveLength(26);
    expect(COVERAGE_BY_AREA.incidents).toHaveLength(8);
    // NEW_IN_8_2 is exactly the step 8.2 provider-connections manifest (24 operations).
    expect(COVERAGE_BY_AREA['provider-connections'].map((c) => c.route).sort()).toEqual(
      [...NEW_IN_8_2].sort(),
    );
    expect(NEW_IN_8_2).toHaveLength(24);
    // NEW_IN_8_5 is exactly the step 8.5 ato-providers manifest (13 operations).
    expect(COVERAGE_BY_AREA['ato-providers'].map((c) => c.route).sort()).toEqual(
      [...NEW_IN_8_5].sort(),
    );
    expect(NEW_IN_8_5).toHaveLength(13);
    // NEW_IN_API_1 + PROVIDER_CALLBACKS + NEW_IN_API_2 + NEW_IN_API_3 + NEW_IN_API_4 is exactly
    // the api-mode manifest (16 operations of step API-1, 9 of step API-2, 19 of step API-3, 5
    // of step API-4).
    expect(COVERAGE_BY_AREA['api-mode'].map((c) => c.route).sort()).toEqual(
      [
        ...NEW_IN_API_1,
        ...PROVIDER_CALLBACKS,
        ...NEW_IN_API_2,
        ...NEW_IN_API_3,
        ...NEW_IN_API_4,
      ].sort(),
    );
    expect(NEW_IN_API_1).toHaveLength(14);
    expect(NEW_IN_API_2).toHaveLength(9);
    expect(NEW_IN_API_3).toHaveLength(19);
    expect(NEW_IN_API_4).toHaveLength(5);
    // NEW_IN_8_6 is exactly the step 8.6 journaling manifest (12 operations).
    expect(COVERAGE_BY_AREA.journaling.map((c) => c.route).sort()).toEqual([...NEW_IN_8_6].sort());
    expect(NEW_IN_8_6).toHaveLength(12);
    // NEW_IN_AI_1 + NEW_IN_AI_2 + NEW_IN_AI_R + NEW_IN_AI_6 is exactly the assistant manifest
    // (15 + 3 + 1 + 11).
    expect(COVERAGE_BY_AREA.assistant.map((c) => c.route).sort()).toEqual(
      [...NEW_IN_AI_1, ...NEW_IN_AI_2, ...NEW_IN_AI_R, ...NEW_IN_AI_6].sort(),
    );
    expect(NEW_IN_AI_6).toHaveLength(11);
    expect(NEW_IN_AI_R).toHaveLength(1);
    expect(NEW_IN_AI_1).toHaveLength(15);
    expect(NEW_IN_AI_2).toHaveLength(3);
    // NEW_IN_AI_4 are reads of pre-6.1 modules: in the legacy manifest, next to their lists.
    expect(NEW_IN_AI_4).toHaveLength(4);
    const legacyRoutes = COVERAGE_BY_AREA.legacy.map((c) => c.route);
    expect(NEW_IN_AI_4.filter((r) => !legacyRoutes.includes(r))).toEqual([]);
    expect(NEW_IN_AI_5).toHaveLength(1);
  });

  it('has one coverage entry per served route and none for a route that does not exist (§3.8)', () => {
    const entries = COVERAGE.map((c) => c.route);
    const duplicates = entries.filter((r, i) => entries.indexOf(r) !== i);
    expect(duplicates).toEqual([]);
    const served = new Set(byKey.keys());
    expect(entries.filter((r) => !served.has(r))).toEqual([]);
    expect([...served].filter((r) => !entries.includes(r)).sort()).toEqual([]);
    // Each area holds its own routes: pre-6.1 in legacy.ts (except the messages module).
    for (const route of COVERAGE_BY_AREA.legacy.map((c) => c.route)) {
      expect(NEW_IN_6_1.includes(route), route).toBe(false);
      expect(NEW_IN_6_2.includes(route), route).toBe(false);
      expect(NEW_IN_7_1.includes(route), route).toBe(false);
      expect(NEW_IN_7_2.includes(route), route).toBe(false);
      expect(NEW_IN_7_3.includes(route), route).toBe(false);
      expect(NEW_IN_8_1.includes(route), route).toBe(false);
      expect(NEW_IN_8_4.includes(route), route).toBe(false);
      expect(NEW_IN_8_2.includes(route), route).toBe(false);
      expect(NEW_IN_8_5.includes(route), route).toBe(false);
      expect(NEW_IN_8_6.includes(route), route).toBe(false);
      expect(NEW_IN_AI_1.includes(route), route).toBe(false);
      expect(NEW_IN_AI_2.includes(route), route).toBe(false);
      expect(NEW_IN_AI_R.includes(route), route).toBe(false);
      expect(NEW_IN_AI_5.includes(route), route).toBe(false);
      expect(NEW_IN_AI_6.includes(route), route).toBe(false);
    }
  });

  it('every coverage file exists and carries the @covers marker of its route (§3.8)', () => {
    const failures: string[] = [];
    const check = (entry: RouteCoverage, column: string, file: string) => {
      const text = readRepoFile(file);
      if (text === null) failures.push(`${entry.route}: ${column} file ${file} does not exist`);
      else if (!hasMarker(text, entry.route)) {
        failures.push(`${entry.route}: ${column} file ${file} has no "@covers ${entry.route}"`);
      }
    };
    for (const entry of COVERAGE) {
      check(entry, 'e2e', entry.e2e);
      check(entry, 'integration', entry.integration);
      if (typeof entry.crossTenant === 'string') {
        check(entry, 'crossTenant', entry.crossTenant);
      } else {
        if (!entry.crossTenant.why.trim())
          failures.push(`${entry.route}: crossTenant n/a without why`);
        const key = entry.route;
        const route = byKey.get(key)?.route;
        // `public` only for public routes; `self-only` only for self-service routes.
        if (entry.crossTenant.na === 'public' && route && !route.isPublic) {
          failures.push(`${key}: crossTenant "public" on a protected route`);
        }
      }
    }
    expect(failures).toEqual([]);
  });

  it('every list declares its cursor encoding; the manifest agrees; 6.1 lists are v1 (D3)', () => {
    const failures: string[] = [];
    const coverage = new Map(COVERAGE.map((c) => [c.route, c]));
    for (const { key, route } of facts) {
      if (isInternal(key)) continue;
      const list = isCursorPage(doc, operation(key)!);
      if (list && route.cursor === null) failures.push(`${key}: list without @CursorList`);
      if (!list && route.cursor !== null) failures.push(`${key}: @CursorList on a non-list`);
      if ((coverage.get(key)?.cursor ?? null) !== route.cursor) {
        failures.push(`${key}: manifest cursor ${coverage.get(key)?.cursor} ≠ ${route.cursor}`);
      }
      if (
        (NEW_IN_6_1.includes(key) ||
          NEW_IN_6_2.includes(key) ||
          NEW_IN_7_1.includes(key) ||
          NEW_IN_7_2.includes(key) ||
          NEW_IN_7_3.includes(key) ||
          NEW_IN_8_1.includes(key) ||
          NEW_IN_8_4.includes(key) ||
          NEW_IN_8_2.includes(key) ||
          NEW_IN_8_5.includes(key) ||
          NEW_IN_8_6.includes(key) ||
          NEW_IN_AI_1.includes(key) ||
          NEW_IN_AI_2.includes(key) ||
          NEW_IN_AI_R.includes(key) ||
          NEW_IN_AI_5.includes(key) ||
          NEW_IN_AI_6.includes(key) ||
          NEW_IN_API_1.includes(key) ||
          NEW_IN_API_2.includes(key) ||
          NEW_IN_API_3.includes(key) ||
          NEW_IN_API_4.includes(key)) &&
        route.cursor === 'v0'
      )
        failures.push(`${key}: 6.1/6.2/7.1/7.2/7.3/8.1/8.4/8.2 list on v0`);
      if (route.cursor !== null && operation(key)!['x-eg-cursor'] !== route.cursor) {
        failures.push(`${key}: x-eg-cursor not documented`);
      }
    }
    expect(failures).toEqual([]);
    const counts = { v0: 0, v1: 0 };
    for (const { route } of facts) if (route.cursor) counts[route.cursor] += 1;
    // 33 pre-6.1 lists keep the unsigned v0 cursors; the 9 lists of 6.1, the 2 of 6.2
    // (webhooks, deliveries), the saved views list of 7.2, the 10 lists of 8.1 and the 11 lists
    // of 8.4 (8 ato, 3 incidents) and the 2 of 8.2 (connections, validation runs) and the intake
    // sources list of 8.6 and the 2 of AI-1 (conversations, messages) and the 5 of AI-6 (search,
    // usage per user, admin feedback, audit conversations and executions) and the 2 of API-1
    // (mailboxes, detections) and the remediation history of API-2 and the 3 of API-3
    // (clawbacks, clawback targets, reports) and protection by mode of API-4 are signed v1.
    expect(counts).toEqual({ v0: 33, v1: 50 });
  });

  it('every body and query schema of every route is strict at every object node (D1)', () => {
    const offenders: string[] = [];
    let checked = 0;
    for (const { key, takesBody, schemas } of facts) {
      if (takesBody && !schemas.some((s) => s.kind === 'body')) {
        offenders.push(`${key}: body without a zod schema`);
      }
      for (const { kind, schema } of schemas) {
        checked += 1;
        if (PROVIDER_CALLBACKS.includes(key) && kind === 'body') continue;
        for (const path of isStrictRequestSchema(schema)) offenders.push(`${key} ${kind} ${path}`);
      }
    }
    expect(offenders).toEqual([]);
    expect(checked).toBeGreaterThan(150);
  });

  it('every §3.5 sensitive mutation has idempotency metadata and the sensitive class (D9, D10)', () => {
    const failures: string[] = [];
    for (const key of [
      ...SENSITIVE_TRANSACTIONAL,
      ...SENSITIVE_LEGACY,
      ...EXPENSIVE_TRANSACTIONAL,
    ]) {
      const fact = byKey.get(key);
      const op = operation(key);
      if (!fact || !op) {
        failures.push(`${key}: missing`);
        continue;
      }
      const legacy = SENSITIVE_LEGACY.includes(key);
      if (legacy && fact.route.idempotency?.legacy !== true) {
        failures.push(`${key}: no @Idempotent({ legacy: true })`);
      }
      if (!legacy && fact.transactional === null) failures.push(`${key}: no transactional marker`);
      const expected = EXPENSIVE_TRANSACTIONAL.includes(key) ? 'expensive' : 'sensitive';
      if (fact.route.rateClass !== expected) failures.push(`${key}: not in the ${expected} class`);
      if (op['x-eg-idempotency'] !== (legacy ? 'legacy' : 'required')) {
        failures.push(`${key}: x-eg-idempotency ${String(op['x-eg-idempotency'])}`);
      }
      const header = (op.parameters ?? []).find(
        (p) => p.in === 'header' && p.name.toLowerCase() === 'idempotency-key',
      );
      if (!header?.required) failures.push(`${key}: Idempotency-Key header not documented`);
    }
    expect(failures).toEqual([]);
    // Nothing else is keyed, and every operation name is unique (one key space per tenant).
    const keyed = facts
      .filter((f) => f.route.idempotency !== null || f.transactional !== null)
      .map((f) => f.key)
      .sort();
    expect(keyed).toEqual(
      [
        ...SENSITIVE_TRANSACTIONAL,
        ...SENSITIVE_LEGACY,
        ...EXPENSIVE_TRANSACTIONAL,
        ...KEYED_8_2,
      ].sort(),
    );
    for (const key of KEYED_8_2) {
      const fact = byKey.get(key);
      expect(fact?.transactional, key).not.toBeNull();
      expect(fact?.route.rateClass ?? null, key).toBeNull();
      expect(operation(key)?.['x-eg-idempotency'], key).toBe('required');
    }
    const operations = facts.flatMap((f) =>
      [f.route.idempotency?.operation, f.transactional?.operation].filter(Boolean),
    );
    expect(new Set(operations).size).toBe(operations.length);
    // 42 before step 8.1, plus its 15 keyed archive, legal hold and eDiscovery mutations, plus
    // the 14 keyed ATO and incident mutations of step 8.4, plus the 12 keyed provider-connection
    // mutations of step 8.2, plus the 8 keyed identity-provider and mailbox state mutations of
    // step 8.5, plus the 4 keyed journaling mutations of step 8.6, plus the 5 keyed
    // protection-mode and API-mode mutations of step API-1, plus the 6 keyed remediation
    // mutations of step API-2, plus the 12 keyed clawback, report and settings mutations of step
    // API-3, plus the 2 keyed scope and provider ownership mutations of step API-4.
    expect(operations).toHaveLength(120);
  });

  it('no route is both @Idempotent() and @ReturnsSecret(); secret-bearing and expensive routes carry their class (D8, D9, ADR-0057)', () => {
    expect(
      facts.filter((f) => f.route.returnsSecret && f.route.idempotency !== null).map((f) => f.key),
    ).toEqual([]);
    // ADR-0057: @ReturnsSecret + idempotency only on the allow-list, only transactional and
    // only with the redacted replay; the allow-list routes are exactly that.
    expect(
      facts
        .filter((f) => f.route.returnsSecret && f.transactional)
        .filter(
          (f) => !SECRET_BEARING_REDACTED_REPLAY.includes(f.key) || !f.route.secretRedactedReplay,
        )
        .map((f) => f.key),
    ).toEqual([]);
    for (const key of SECRET_BEARING_REDACTED_REPLAY) {
      const fact = byKey.get(key);
      expect(fact?.route.returnsSecret, key).toBe(true);
      expect(fact?.route.secretRedactedReplay, key).toBe(true);
      expect(fact?.transactional, key).not.toBeNull();
      expect(operation(key)?.['x-eg-secret-replay'], key).toBe('redacted');
    }
    expect(
      facts
        .filter((f) => f.route.secretRedactedReplay)
        .map((f) => f.key)
        .sort(),
    ).toEqual([...SECRET_BEARING_REDACTED_REPLAY].sort());
    expect(
      facts
        .filter((f) => f.route.returnsSecret && !f.route.secretRedactedReplay)
        .map((f) => f.key)
        .sort(),
    ).toEqual([...SECRET_BEARING].sort());
    const byClass = (rateClass: string) =>
      facts
        .filter((f) => f.route.rateClass === rateClass)
        .map((f) => f.key)
        .sort();
    expect(byClass('expensive')).toEqual([...EXPENSIVE].sort());
    expect(byClass('sensitive')).toEqual(
      [
        ...new Set([
          ...SENSITIVE_TRANSACTIONAL,
          ...SENSITIVE_LEGACY,
          ...SECRET_BEARING,
          ...SECRET_BEARING_REDACTED_REPLAY,
          ...SENSITIVE_UNKEYED_8_6,
          ...SENSITIVE_UNKEYED_AI_1,
          ...SENSITIVE_UNKEYED_AI_2,
          ...SENSITIVE_UNKEYED_AI_6,
        ]),
      ].sort(),
    );
    for (const { key, route } of facts) {
      if (route.rateClass && operation(key)?.['x-eg-rate-class'] !== route.rateClass) {
        throw new Error(`${key}: x-eg-rate-class not documented`);
      }
    }
  });
});
